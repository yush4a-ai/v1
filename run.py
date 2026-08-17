"""Единственная команда запуска: чат-бот, модерация, панель и голос.

    .venv\\Scripts\\python run.py

Что поднимается
---------------
В ЭТОМ процессе, одним event loop'ом:
  * чат-бот (twitchio, IRC) — main.py::ChatBot
  * движок модерации на каждый активный канал — cigilbot/pipeline.py
  * веб-панель на 8766 — panel/server.py

Дочерним процессом, только если VOICE_ENABLED=true:
  * распознавание речи — voice_main.py

Почему голос всё-таки отдельным процессом
-----------------------------------------
Не по вкусу и не «потому что так было»: faster-whisper и sounddevice в
одном процессе с twitchio приводили к падению без трассировки (конфликт
нативных потоков с event loop) — см. bot/voice_queue.py. Это записанный
инцидент, а не предположение, поэтому граница сохранена. Но запускать
руками второе окно больше не нужно: процесс поднимается отсюда и гасится
вместе с родителем.

Почему панель — в общем процессе, а голос — нет
-----------------------------------------------
Панель асинхронная и не делает блокирующей работы: uvicorn.Server.serve()
и Bot.start() — обе корутины, они просто живут в одном loop. Голос делает
ровно обратное — тяжёлые нативные вызовы, которые loop не переживает.
Граница проходит там, где к ней есть причина.

Панель отдельно, без бота, по-прежнему запускается — это нужно, чтобы
править её код, не роняя IRC-подключение и не стирая прогретое состояние
движка (скользящее окно, кэш пользователей, кластеры):

    .venv\\Scripts\\python -m panel.server

Бот отдельно, без панели и без голоса — для отладки чат-бота, замена
прежнего отдельного `python main.py`:

    .venv\\Scripts\\python run.py --bot-only
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import subprocess
import sys

import uvicorn

import paths

log = logging.getLogger("run")

PANEL_HOST = "127.0.0.1"
PANEL_PORT = 8766


def _start_voice(*, enabled: bool) -> subprocess.Popen[bytes] | None:
    """Поднимает voice_main.py, если голос включён.

    Дочерний процесс, а не отдельное окно, которое оператор запускает
    руками: единственная команда должна поднимать всё, что нужно для
    стрима. Логи уходят в тот же каталог, что и у остальных процессов."""
    if not enabled:
        return None

    paths.ensure_dirs()
    # Дескрипторы закрываются сразу после Popen: он уже задублировал их
    # дочернему процессу через dup(), держать открытыми в родителе — утечка
    # (тот же приём и по той же причине, что в cigilbot/bot_process_control.py).
    with (
        open(paths.BOT_LOGS / "voice.out.log", "a", encoding="utf-8") as out,
        open(paths.BOT_LOGS / "voice.err.log", "a", encoding="utf-8") as err,
    ):
        proc = subprocess.Popen(
            [sys.executable, str(paths.REPO_ROOT / "voice_main.py")],
            cwd=str(paths.REPO_ROOT),
            stdout=out,
            stderr=err,
            env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        )
    log.info("Голосовой ввод запущен (pid=%s)", proc.pid)
    return proc


def _stop_voice(proc: subprocess.Popen[bytes] | None) -> None:
    if proc is None or proc.poll() is not None:
        return
    log.info("Останавливаю голосовой ввод (pid=%s)", proc.pid)
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


def _log_if_failed(task: asyncio.Task[None]) -> None:
    """Кричит сразу, как только половина системы отвалилась.

    Без этого падение бота при живой панели (или наоборот) осталось бы
    незамеченным до самого выхода из процесса — а внешне всё выглядело бы
    работающим."""
    if task.cancelled():
        return
    exc = task.exception()
    if exc is not None:
        log.error("Задача %r остановилась с ошибкой — остальное продолжает работать",
                  task.get_name(), exc_info=exc)
    else:
        log.error("Задача %r неожиданно завершилась — остальное продолжает работать",
                  task.get_name())


async def _serve_panel() -> None:
    """Панель как корутина в общем loop'е, а не как отдельный процесс.

    uvicorn.run() здесь не годится — он создаёт свой event loop; нужен
    именно Server.serve(), который работает в уже существующем."""
    from panel.server import app

    # Панель внутри процесса бота: кнопки «запустить/остановить бота» на
    # экране Registry должны честно отвечать 409, а не поднимать второй
    # main.py со вторым движком модерации на те же БД (см. registry_api.py).
    app.state.in_bot_process = True

    config = uvicorn.Config(app, host=PANEL_HOST, port=PANEL_PORT, log_level="info")
    await uvicorn.Server(config).serve()


async def _run_all(main: object, *, bot_only: bool) -> None:
    channels = await main.load_initial_channels()  # type: ignore[attr-defined]
    if not channels:
        raise SystemExit(
            "Нет ни одного активного канала (Channel Registry пуст и TWITCH_CHANNEL "
            "в .env не задан) — добавьте канал через панель перед запуском"
        )
    log.info("Список каналов для подключения: %s", ", ".join(channels))

    bot = main.ChatBot(channels)  # type: ignore[attr-defined]

    # Задачи НЕ снимают друг друга при падении, и это осознанно.
    #
    # Умер бот (протух токен, Twitch недоступен) — панель обязана остаться:
    # она ровно то место, где токен и настройки чинят. Снести её вместе с
    # ботом значит отобрать инструмент починки в тот момент, когда он нужен.
    #
    # Умерла панель (занят порт) — бот обязан остаться: чат и модерация и
    # есть продукт, а панель к нему лишь пульт.
    #
    # Цена — процесс может жить наполовину. Поэтому падение каждой задачи
    # логируется немедленно через колбэк, а не всплывает в конце: молча
    # работающая половина выглядит как работающее целое, и это хуже всего.
    tasks = [asyncio.create_task(bot.start(), name="чат-бот")]
    # --bot-only (замена прежнего отдельного `python main.py`): панель не
    # поднимается вовсе, а не поднимается и сразу глушится — иначе порт 8766
    # оказался бы ненадолго занят самим этим процессом, мешая параллельно
    # запущенной `python -m panel.server` для отладки её кода.
    if not bot_only:
        log.info("Панель: http://localhost:%d/", PANEL_PORT)
        tasks.append(asyncio.create_task(_serve_panel(), name="панель"))
    for task in tasks:
        task.add_done_callback(_log_if_failed)

    try:
        await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await bot.close()
        # bot.close() гасит только IRC-соединение (twitchio) — движки
        # модерации/автоклипа держат свои задачи, БД-соединения и
        # httpx-клиенты отдельно и без явной остановки переживают процесс
        # до сборки мусора: панель после Ctrl+C продолжает показывать
        # канал как активный (process_status в registry.db не обновлён),
        # а httpx-клиенты остаются висеть открытыми (bug-аудит 2026-08-15,
        # HIGH #3). moderation_hub.stop()/autoclip_hub.stop() уже
        # идемпотентны к "start() не вызывался" (AUTOCLIP_ENABLED=false и
        # т.п.) — оба хаба сами проверяют, что останавливать нечего.
        await main.moderation_hub.stop()  # type: ignore[attr-defined]
        await main.autoclip_hub.stop()  # type: ignore[attr-defined]


def main_entry() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--bot-only", action="store_true",
        help="только чат-бот и модерация, без панели и без голоса — замена `python main.py`",
    )
    args = parser.parse_args()

    # main импортируется ПЕРВЫМ и настраивает логирование сам (файл
    # var/bot/logs/bot.log + консоль). Свой logging.basicConfig здесь
    # молча отобрал бы файловый обработчик: повторный вызов basicConfig
    # ничего не делает, если корневой логгер уже настроен, — и запись в
    # файл просто перестала бы происходить, без единой ошибки.
    import main

    voice = _start_voice(enabled=main.cfg.voice_enabled and not args.bot_only)
    try:
        asyncio.run(_run_all(main, bot_only=args.bot_only))
    except KeyboardInterrupt:
        log.info("Остановка по Ctrl+C")
    finally:
        _stop_voice(voice)


if __name__ == "__main__":
    main_entry()
