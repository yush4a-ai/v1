"""Общий Limiter (slowapi) для роутеров панели.

Один объект, не по одному на модуль — slowapi.Limiter сам хранит счётчики
запросов (in-memory storage по умолчанию), и @limiter.limit(...) в разных
роутерах обязан делить один и тот же объект, иначе лимиты в auth.py и
bots_api.py считались бы независимо друг от друга и не отражали бы
реальную нагрузку от одного клиента на панель в целом.

Модуль отдельный от panel/server.py (где раньше был единственный резонный
кандидат на app.state.limiter), потому что server.py импортирует роутеры
из auth.py/bots_api.py — импорт в обратную сторону создал бы цикл.
server.py подключает этот же limiter в app.state.limiter и добавляет
SlowAPIMiddleware/exception handler; роутеры декорируют свои эндпоинты
через limiter.limit(...) из этого модуля.
"""

from __future__ import annotations

import warnings

from slowapi import Limiter
from slowapi.util import get_remote_address

# config_filename="" (не None): без этого Limiter.__init__ видит корневой
# .env (os.path.isfile(".env")) и молча открывает его через
# starlette.config.Config(".env") — тот читает файл в системной кодировке
# консоли (cp1251 на русской Windows), а .env этого репозитория содержит
# кириллические комментарии в UTF-8, что роняет импорт этого модуля с
# UnicodeDecodeError ещё до старта приложения. Лимитеру не нужны значения
# ИЗ .env вообще (default_limits/storage_uri заданы явно в коде), поэтому
# он ничего не теряет, не читая файл. Warning про "Config file '' not
# found" от самого starlette в этом случае ожидаем и неинформативен —
# подавляем точечно, а не глобально.
with warnings.catch_warnings():
    warnings.filterwarnings("ignore", message="Config file '' not found")
    limiter = Limiter(key_func=get_remote_address, config_filename="")
