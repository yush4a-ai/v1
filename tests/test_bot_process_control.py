"""Тесты cigilbot/integrations/bot_process_control.py.

До этой правки (test-coverage-аудит 2026-08-15, MEDIUM #13) модуль не имел
ни одного прямого теста — существующие тесты (tests/panel/test_bot_control.py)
бьют только по HTTP-роуту panel/registry_api.py с моком самого модуля, не
проверяя ни _pid_lock() на конкуренцию, ни поведение при протухшем PID-файле.
CLAUDE.md явно связывает дублирующийся main.py с дублирующимися банами —
именно _pid_lock() и есть механизм, который должен это предотвращать.

Все внешние эффекты (subprocess.run/Popen, tasklist/taskkill) замоканы —
ни один тест не запускает реальный процесс.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

import pytest

from cigilbot.integrations import bot_process_control as bpc


@pytest.fixture(autouse=True)
def _isolated_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bpc, "PID_FILE", tmp_path / "chatbot.pid")
    monkeypatch.setattr(bpc, "LOCK_FILE", tmp_path / "chatbot.lock")
    monkeypatch.setattr(bpc, "LOG_OUT", tmp_path / "chatbot.out.log")
    monkeypatch.setattr(bpc, "LOG_ERR", tmp_path / "chatbot.err.log")
    monkeypatch.setattr(bpc, "BOT_PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(bpc, "BOT_VENV_PYTHON", tmp_path / "fake_python.exe")
    (tmp_path / "fake_python.exe").write_text("", encoding="utf-8")
    monkeypatch.setattr(bpc.paths, "ensure_dirs", lambda: None)


class _FakeProc:
    def __init__(self, pid: int) -> None:
        self.pid = pid


class TestPidLock:
    def test_serializes_two_sequential_holders(self, tmp_path: Path) -> None:
        """Не сама конкуренция (сложно детерминированно проверить с реальным
        потоком в юнит-тесте), а гарантия: лок-файл создаётся на входе и
        снимается на выходе, второй вход после выхода первого не блокируется
        и не находит чужой файл — база для реальной атомарности."""
        with bpc._pid_lock():
            assert bpc.LOCK_FILE.exists()
        assert not bpc.LOCK_FILE.exists()

        with bpc._pid_lock():
            assert bpc.LOCK_FILE.exists()
        assert not bpc.LOCK_FILE.exists()

    def test_second_concurrent_holder_times_out(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Пока лок держит первый вызывающий, второй не может получить его
        и в итоге поднимает TimeoutError — именно это не даёт двум
        параллельным start_bot() породить два живых main.py."""
        monkeypatch.setattr(bpc, "_LOCK_TIMEOUT_SECONDS", 0.2)
        bpc.LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
        bpc.LOCK_FILE.write_text("", encoding="utf-8")  # эмулирует чужой активный лок

        with pytest.raises(TimeoutError):
            with bpc._pid_lock():
                pass  # не должны сюда попасть

    def test_stale_lock_is_reclaimed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Лок-файл старше _LOCK_STALE_SECONDS считается брошенным
        (процесс, державший его, упал) и снимается автоматически, а не
        блокирует управление ботом навсегда."""
        monkeypatch.setattr(bpc, "_LOCK_STALE_SECONDS", 0.1)
        monkeypatch.setattr(bpc, "_LOCK_TIMEOUT_SECONDS", 5.0)
        bpc.LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
        bpc.LOCK_FILE.write_text("", encoding="utf-8")
        old_mtime = time.time() - 10
        import os

        os.utime(bpc.LOCK_FILE, (old_mtime, old_mtime))

        with bpc._pid_lock():
            pass  # не подвисает, забирает "протухший" лок


class TestStartBot:
    def test_starts_and_writes_pid_file(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: _FakeProc(4242))

        pid = bpc.start_bot()

        assert pid == 4242
        assert bpc.PID_FILE.read_text(encoding="ascii").strip() == "4242"

    def test_idempotent_when_already_running(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Повторный start_bot() на уже запущенный процесс не порождает
        второй main.py — возвращает существующий pid, Popen не вызывается."""
        popen_calls = []
        monkeypatch.setattr(
            subprocess, "Popen", lambda *a, **kw: popen_calls.append(1) or _FakeProc(4242)
        )
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _TasklistAlive(4242))

        first_pid = bpc.start_bot()
        second_pid = bpc.start_bot()

        assert first_pid == second_pid == 4242
        assert len(popen_calls) == 1  # Popen вызван только один раз

    def test_stale_pid_file_does_not_block_restart(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """PID-файл остался от процесса, который уже мёртв (например,
        panel/бот упал без graceful shutdown) — is_running()/get_pid()
        честно говорят "не жив" (пусто в tasklist), и start_bot() запускает
        новый процесс, не считая PID-файл живым доказательством."""
        bpc.PID_FILE.write_text("9999", encoding="ascii")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _TasklistEmpty())
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: _FakeProc(5555))

        assert bpc.is_running() is False
        assert bpc.get_pid() is None

        pid = bpc.start_bot()
        assert pid == 5555

    def test_missing_venv_raises_runtime_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(bpc, "BOT_VENV_PYTHON", bpc.BOT_PROJECT_ROOT / "does-not-exist.exe")
        with pytest.raises(RuntimeError, match="Не найден общий venv"):
            bpc.start_bot()


class TestStopBot:
    def test_kills_running_process_and_clears_pid_file(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        bpc.PID_FILE.write_text("4242", encoding="ascii")
        run_calls = []
        monkeypatch.setattr(
            subprocess,
            "run",
            lambda *a, **kw: run_calls.append(a) or _TasklistAlive(4242),
        )

        bpc.stop_bot()

        assert not bpc.PID_FILE.exists()
        # taskkill реально вызван (второй subprocess.run после tasklist-проверки)
        assert any("taskkill" in str(call) for call in run_calls)

    def test_noop_when_not_running(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _TasklistEmpty())
        bpc.stop_bot()  # не должен упасть при отсутствии pid-файла/процесса
        assert not bpc.PID_FILE.exists()


class _TasklistAlive:
    def __init__(self, pid: int) -> None:
        self.stdout = f"python.exe  {pid}"


class _TasklistEmpty:
    stdout = ""
