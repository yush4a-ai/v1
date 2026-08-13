"""Версионированные миграции схемы модерации.

Каждая миграция — это (номер_версии, SQL). Применяются по порядку начиная с
версии, на которой сейчас находится БД (PRAGMA user_version), и только
вперёд — откатов нет, как и в большинстве миграционных систем: чтобы
"отменить" миграцию, пишут новую, обратную.

Схема растёт по мере того, как в проекте появляется код, который её
использует: mod_actions/mod_action_queue — на этапе 7 (executor), когда
появится, что в них писать, mod_panel_users — на этапе 8 (панель), и т.д.
Создавать все таблицы сразу с расчётом на будущее не нужно — версионирование
миграций уже даёт расширяемость, для которой это годилось бы.

Таблицы называются с префиксом mod_, чтобы не столкнуться с viewers/
recent_messages из bot/database.py — тот слой обслуживает LLM-бота
(bot/brain.py) и его трогать нельзя, но SQLite один файл прекрасно
держит два независимых набора таблиц.
"""

from __future__ import annotations

import aiosqlite

_MIGRATION_001_CORE_AUDIT = """
CREATE TABLE IF NOT EXISTS mod_users (
    user_id TEXT PRIMARY KEY,
    login TEXT NOT NULL,
    display_name TEXT,
    account_created_at REAL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    message_count INTEGER NOT NULL DEFAULT 0,
    trust_level INTEGER NOT NULL DEFAULT 0,
    prior_timeouts INTEGER NOT NULL DEFAULT 0,
    prior_warnings INTEGER NOT NULL DEFAULT 0,
    marked_safe INTEGER NOT NULL DEFAULT 0,
    marked_safe_at REAL,
    marked_safe_by TEXT,
    note TEXT
);
CREATE INDEX IF NOT EXISTS idx_mod_users_login ON mod_users(login);

CREATE TABLE IF NOT EXISTS mod_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    login TEXT NOT NULL,
    text TEXT NOT NULL,
    normalized TEXT NOT NULL,
    skeleton TEXT NOT NULL,
    created_at REAL NOT NULL,
    is_first_message INTEGER NOT NULL DEFAULT 0,
    is_subscriber INTEGER NOT NULL DEFAULT 0,
    is_moderator INTEGER NOT NULL DEFAULT 0,
    is_vip INTEGER NOT NULL DEFAULT 0,
    domains TEXT
);
CREATE INDEX IF NOT EXISTS idx_mod_messages_created_at ON mod_messages(created_at);
CREATE INDEX IF NOT EXISTS idx_mod_messages_user_id ON mod_messages(user_id, created_at);

CREATE TABLE IF NOT EXISTS mod_clusters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL NOT NULL,
    closed_at REAL,
    size INTEGER NOT NULL,
    risk_score INTEGER NOT NULL,
    confidence REAL NOT NULL,
    similarity_score REAL NOT NULL,
    arrival_window_sec REAL NOT NULL,
    first_message_ratio REAL NOT NULL,
    new_account_ratio REAL NOT NULL,
    shared_domains TEXT,
    status TEXT NOT NULL DEFAULT 'active'
);
CREATE INDEX IF NOT EXISTS idx_mod_clusters_status ON mod_clusters(status);
CREATE INDEX IF NOT EXISTS idx_mod_clusters_created_at ON mod_clusters(created_at);

CREATE TABLE IF NOT EXISTS mod_cluster_members (
    cluster_id INTEGER NOT NULL REFERENCES mod_clusters(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL,
    login TEXT NOT NULL,
    joined_at REAL NOT NULL,
    PRIMARY KEY (cluster_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_mod_cluster_members_user_id ON mod_cluster_members(user_id);

CREATE TABLE IF NOT EXISTS mod_verdicts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL NOT NULL,
    user_id TEXT NOT NULL,
    login TEXT NOT NULL,
    message_id INTEGER REFERENCES mod_messages(id),
    risk_score INTEGER NOT NULL,
    confidence REAL NOT NULL,
    families_triggered INTEGER NOT NULL,
    recommended_action TEXT NOT NULL,
    reason TEXT NOT NULL,
    cluster_id INTEGER REFERENCES mod_clusters(id),
    is_provisional INTEGER NOT NULL DEFAULT 0,
    blocked_by TEXT,
    mode TEXT NOT NULL,
    action_taken TEXT,
    engine_version TEXT,
    config_version TEXT
);
CREATE INDEX IF NOT EXISTS idx_mod_verdicts_created_at ON mod_verdicts(created_at);
CREATE INDEX IF NOT EXISTS idx_mod_verdicts_user_id ON mod_verdicts(user_id);
CREATE INDEX IF NOT EXISTS idx_mod_verdicts_action ON mod_verdicts(recommended_action);

CREATE TABLE IF NOT EXISTS mod_signals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    verdict_id INTEGER NOT NULL REFERENCES mod_verdicts(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    family TEXT NOT NULL,
    weight REAL NOT NULL,
    value REAL NOT NULL,
    evidence TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mod_signals_verdict_id ON mod_signals(verdict_id);
CREATE INDEX IF NOT EXISTS idx_mod_signals_name ON mod_signals(name);
"""

# Очередь команд панель/автоправило -> бот (этап 7): бот поллит
# mod_action_queue и исполняет через executor.py. mod_actions — итоговый
# аудит "кто нажал что и по какому правилу" (раздел 10 ТЗ), одна строка на
# задание, а не на каждого пользователя внутри него — детали по каждому
# участнику лежат в details_json.
_MIGRATION_002_ACTIONS = """
CREATE TABLE IF NOT EXISTS mod_action_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL NOT NULL,
    requested_by TEXT NOT NULL,
    requested_role TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    progress_done INTEGER NOT NULL DEFAULT 0,
    progress_total INTEGER NOT NULL DEFAULT 0,
    started_at REAL,
    finished_at REAL,
    result_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_mod_action_queue_status ON mod_action_queue(status);

CREATE TABLE IF NOT EXISTS mod_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL NOT NULL,
    actor TEXT NOT NULL,
    actor_role TEXT NOT NULL,
    action TEXT NOT NULL,
    scope TEXT NOT NULL,
    cluster_id INTEGER REFERENCES mod_clusters(id),
    pattern_id INTEGER,
    reason TEXT,
    confirmation TEXT NOT NULL,
    succeeded INTEGER NOT NULL DEFAULT 0,
    failed INTEGER NOT NULL DEFAULT 0,
    details_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_mod_actions_created_at ON mod_actions(created_at);
CREATE INDEX IF NOT EXISTS idx_mod_actions_actor ON mod_actions(actor);
"""

# Роли доступа к панели (этап 8). Роль в основном определяется автоматически
# через Twitch OAuth при входе (panel/auth.py — владелец канала -> OWNER,
# модератор канала -> MODERATOR), эта таблица хранит только ручной оверрайд
# на ADMIN/OWNER, который из статуса на Twitch не вывести. token_hash не
# используется (аутентификация через cookie-сессию, не токен в этой таблице).
_MIGRATION_003_PANEL_USERS = """
CREATE TABLE IF NOT EXISTS mod_panel_users (
    login TEXT PRIMARY KEY,
    role TEXT NOT NULL,
    token_hash TEXT,
    created_at REAL NOT NULL,
    last_seen REAL
);
"""

# Доверенные пользователи (этап 9a, ручной MARK SAFE — раздел 10 ТЗ).
# Отдельно от mod_users.marked_safe/trust_level: та таблица хранит ТЕКУЩЕЕ
# состояние пользователя для движка, эта — историю решений "кто, когда и
# почему пометил как safe", нужную для аудита и для отмены решения.
_MIGRATION_004_TRUSTED = """
CREATE TABLE IF NOT EXISTS mod_trusted (
    user_id TEXT PRIMARY KEY,
    added_by TEXT NOT NULL,
    added_at REAL NOT NULL,
    reason TEXT
);
"""

# Bot Pattern Library (этап 9b) — именованные шаблоны атак, сопоставляемые
# с уже посчитанным Verdict/ClusterInfo (cigilbot/patterns.py), а не
# новые детекторы. stats_json — счётчики срабатываний/false positive по
# паттерну, накапливаются панелью (этап 9d), здесь только место для них.
_MIGRATION_005_PATTERNS = """
CREATE TABLE IF NOT EXISTS mod_patterns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    required_signal_names TEXT NOT NULL DEFAULT '[]',
    min_families INTEGER NOT NULL DEFAULT 0,
    min_risk_score INTEGER NOT NULL DEFAULT 0,
    min_confidence REAL NOT NULL DEFAULT 0.0,
    min_cluster_size INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    auto_enabled INTEGER NOT NULL DEFAULT 0,
    weight REAL NOT NULL DEFAULT 1.0,
    created_by TEXT NOT NULL,
    created_at REAL NOT NULL,
    stats_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_mod_patterns_enabled ON mod_patterns(enabled);
"""

# pattern_id на mod_clusters/mod_verdicts — заполняется engine.py после
# policy.decide(), когда patterns.match_patterns() нашёл подходящий
# именованный шаблон (cigilbot/patterns.py). mod_actions.pattern_id
# уже существовал с этапа 7 (аудит действий), эти два — недостающая
# половина: без них "почему сработало ИМЕННО это название" было бы видно
# только в момент исполнения действия, а не на самой карточке кластера.
_MIGRATION_006_PATTERN_LINKS = """
ALTER TABLE mod_clusters ADD COLUMN pattern_id INTEGER REFERENCES mod_patterns(id);
ALTER TABLE mod_verdicts ADD COLUMN pattern_id INTEGER REFERENCES mod_patterns(id);
"""

# Attack Mode (этап 9c, раздел 11 ТЗ риск #16) — ручной panic-режим,
# поднимающий Sensitivity.ATTACK на канале с автоматическим таймером
# выключения. Одна БД = один бот = один канал, поэтому таблица без PK по
# channel — просто singleton-строка (id=1), которую store.py удаляет/
# перезаписывает целиком, а не индексирует по каналам. Хранится в БД (не в
# памяти/конфиге), чтобы: 1) пережить рестарт бота, 2) быть видимой в
# аудите "кто включил панику и когда".
_MIGRATION_007_ATTACK_MODE = """
CREATE TABLE IF NOT EXISTS mod_attack_mode (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    activated_by TEXT NOT NULL,
    activated_at REAL NOT NULL,
    expires_at REAL NOT NULL
);
"""

# Feedback loop (этап 9d) — модератор нажимает "это был false positive"
# на конкретном СИГНАЛЕ вердикта/кластера (не на вердикте целиком: один
# вердикт часто содержит несколько сигналов, и ошибиться может конкретно
# один из них, например unexpected_language, а не exact_duplicate рядом).
# signal_name — то, по чему считается статистика в confidence.py
# (fp_penalty конкретного правила), verdict_id/cluster_id — куда именно
# кликнул модератор, оба опциональны и взаимоисключающи по смыслу (кластер
# для кластерных сигналов вроде synchronized_arrival, вердикт для остальных).
_MIGRATION_008_FEEDBACK = """
CREATE TABLE IF NOT EXISTS mod_feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL NOT NULL,
    signal_name TEXT NOT NULL,
    verdict_id INTEGER REFERENCES mod_verdicts(id),
    cluster_id INTEGER REFERENCES mod_clusters(id),
    user_id TEXT,
    pattern_id INTEGER REFERENCES mod_patterns(id),
    moderator TEXT NOT NULL,
    decision TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mod_feedback_signal_name ON mod_feedback(signal_name);
CREATE INDEX IF NOT EXISTS idx_mod_feedback_created_at ON mod_feedback(created_at);

CREATE TABLE IF NOT EXISTS mod_stats_daily (
    date TEXT PRIMARY KEY,
    total_messages INTEGER NOT NULL DEFAULT 0,
    suspicious INTEGER NOT NULL DEFAULT 0,
    would_timeout INTEGER NOT NULL DEFAULT 0,
    would_ban INTEGER NOT NULL DEFAULT 0,
    actual_timeouts INTEGER NOT NULL DEFAULT 0,
    actual_bans INTEGER NOT NULL DEFAULT 0,
    clusters INTEGER NOT NULL DEFAULT 0,
    false_positives INTEGER NOT NULL DEFAULT 0
);
"""

# Giveaway Mode (FALSE-BAN-001 аудита) — ручной переключатель "сейчас на
# канале розыгрыш", тот же паттерн singleton-таблицы, что mod_attack_mode
# (миграция 007): нет технического сигнала, который надёжно отличил бы
# "100 зрителей написали !giveaway" от координированной атаки — у обоих
# синхронное появление одинакового короткого сообщения. В отличие от Attack
# Mode это НЕ повышает чувствительность, а СНИЖАЕТ её (ChannelContext.is_giveaway
# -> confidence.py::context_factor=0.5) — включает модератор/стример вручную
# на время розыгрыша, выключается сама по таймеру, чтобы не остаться
# забытой включённой навсегда.
_MIGRATION_009_GIVEAWAY_MODE = """
CREATE TABLE IF NOT EXISTS mod_giveaway_mode (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    activated_by TEXT NOT NULL,
    activated_at REAL NOT NULL,
    expires_at REAL NOT NULL
);
"""

# Discord-webhook (направление 01 master-plan.html) — тот же singleton-
# паттерн, что mod_attack_mode/mod_giveaway_mode: одна БД = один канал,
# поэтому одна строка, а не таблица с channel_id. url хранится как есть
# (не токенизированный секрет вроде TWITCH_MOD_*) — Discord сам считает
# webhook URL секретом и ротирует его при компрометации, здесь достаточно
# того же уровня защиты, что у остального содержимого БД.
_MIGRATION_010_DISCORD_WEBHOOK = """
CREATE TABLE IF NOT EXISTS mod_discord_webhook (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    url TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    updated_by TEXT NOT NULL,
    updated_at REAL NOT NULL
);
"""

# Ежедневный digest (направление 01 master-plan.html) — та же строка
# mod_discord_webhook, не отдельная таблица: last_digest_sent_at существует
# ровно для того, чтобы пережить рестарт бота и не отправить второй digest
# в тот же день (ChannelPipeline поднимается заново после каждого падения/
# деплоя — без этого поля таймер стартовал бы с нуля каждый раз). NULL по
# умолчанию — "ещё ни разу не отправляли", отличимо от 0.0.
_MIGRATION_011_DIGEST = """
ALTER TABLE mod_discord_webhook ADD COLUMN last_digest_sent_at REAL;
"""

# Эскалация при повторных атаках (направление 01 master-plan.html) — та же
# строка mod_discord_webhook. last_escalation_sent_at нужен как cooldown:
# без него КАЖДЫЙ новый кластер сверх порога (4-й, 5-й, 6-й...) заново слал
# бы "эскалация!", хотя план говорит "алертится отдельно", то есть один раз
# на волну, не на каждый лишний кластер внутри неё.
_MIGRATION_012_ESCALATION = """
ALTER TABLE mod_discord_webhook ADD COLUMN last_escalation_sent_at REAL;
"""

# Порог confidence для алерта на новый кластер (направление 01
# master-plan.html) — настраиваемый per-channel через панель, не жёстко
# зашитая константа: разным каналам подходит разная граница "достаточно
# уверены, чтобы отвлекать модератора" (маленький канал может хотеть более
# ранние алерты, крупный — только самые очевидные случаи). DEFAULT 0.9 —
# то же значение, что было константой ALERT_CONFIDENCE_THRESHOLD, чтобы
# поведение существующих установок не изменилось молча после миграции.
_MIGRATION_013_ALERT_THRESHOLD = """
ALTER TABLE mod_discord_webhook ADD COLUMN alert_confidence_threshold REAL NOT NULL DEFAULT 0.9;
"""

# Content Rules (словарный детектор — Rule Engine) — правила лежат в БД, а
# не в moderation.yml, потому что список фраз меняется чаще порогов и
# правится модератором из панели, без деплоя. category — текстовое имя
# ContentCategory (types.py), не FK: категорий мало и они меняются вместе с
# кодом политики, отдельная таблица-справочник была бы лишней.
_MIGRATION_014_CONTENT_RULES = """
CREATE TABLE IF NOT EXISTS mod_content_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL,
    phrase TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mod_content_rules_category ON mod_content_rules(category);

CREATE TABLE IF NOT EXISTS mod_content_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    enabled INTEGER NOT NULL DEFAULT 0,
    updated_by TEXT NOT NULL,
    updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS mod_content_violations (
    user_id TEXT NOT NULL,
    category TEXT NOT NULL,
    violation_count INTEGER NOT NULL DEFAULT 0,
    last_violation_at REAL NOT NULL,
    PRIMARY KEY (user_id, category)
);

-- Аудит срабатываний словарного детектора — отдельно от mod_verdicts:
-- content-решение не имеет risk_score/confidence/signals, поля другой формы
-- (category, matched_phrase, prior_violations). enforced=0 означает "решение
-- вычислено, но не выполнено" — режим наблюдателя (content_moderation_enabled
-- выключен) или blocked_by сработал; отличимо от "выполнено и это был OBSERVE".
CREATE TABLE IF NOT EXISTS mod_content_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL NOT NULL,
    user_id TEXT NOT NULL,
    login TEXT NOT NULL,
    message_id INTEGER REFERENCES mod_messages(id),
    category TEXT NOT NULL,
    matched_phrase TEXT NOT NULL,
    action TEXT NOT NULL,
    prior_violations INTEGER NOT NULL,
    blocked_by TEXT NOT NULL DEFAULT '',
    enforced INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_mod_content_events_created_at ON mod_content_events(created_at);
CREATE INDEX IF NOT EXISTS idx_mod_content_events_user_id ON mod_content_events(user_id, created_at);
"""

# Ручное модерирование из ленты Content (пользователь 2026-08-13: "можешь
# сделать в это меню ручное модерирование, удалить, тайм-аут, бан"). Кнопка
# "Удалить сообщение" зовёт executor.py::delete_chat_messages, а тому нужен
# НАСТОЯЩИЙ Twitch message_id — mod_messages.id до этой миграции был только
# внутренним AUTOINCREMENT, никогда не совпадающим с тем, что принимает
# Helix DELETE /moderation/chat. ChatEvent.message_id (types.py) содержал
# нужное значение с самого начала, просто ни один store-метод его не
# сохранял — до сих пор это никому не было нужно, потому что удаление
# отдельных сообщений через панель не существовало как функция.
_MIGRATION_015_TWITCH_MESSAGE_ID = """
ALTER TABLE mod_messages ADD COLUMN twitch_message_id TEXT;
"""

# Пометка "уже разобрано" на строке ленты Content (пользователь 2026-08-13:
# "можем как-то помечать сообщения (которое было забанено/удалено/таймаут)
# в модераторской панели?") — без этого поля обновление страницы стирало
# след ручного действия: панель заново читала mod_content_events, у которых
# ничего не менялось от нажатия кнопки "Удалить"/"Таймаут"/"Бан" (эти кнопки
# только кладут задание в mod_action_queue, саму запись события не трогают).
# NULL означает "по этой строке ручных действий ещё не было" — отличимо от
# записи, где действие явно решили не предпринимать.
_MIGRATION_016_MANUAL_ACTION_MARK = """
ALTER TABLE mod_content_events ADD COLUMN manual_action TEXT;
ALTER TABLE mod_content_events ADD COLUMN manual_action_by TEXT;
ALTER TABLE mod_content_events ADD COLUMN manual_action_at REAL;
"""

MIGRATIONS: tuple[tuple[int, str], ...] = (
    (1, _MIGRATION_001_CORE_AUDIT),
    (2, _MIGRATION_002_ACTIONS),
    (3, _MIGRATION_003_PANEL_USERS),
    (4, _MIGRATION_004_TRUSTED),
    (5, _MIGRATION_005_PATTERNS),
    (6, _MIGRATION_006_PATTERN_LINKS),
    (7, _MIGRATION_007_ATTACK_MODE),
    (8, _MIGRATION_008_FEEDBACK),
    (9, _MIGRATION_009_GIVEAWAY_MODE),
    (10, _MIGRATION_010_DISCORD_WEBHOOK),
    (11, _MIGRATION_011_DIGEST),
    (12, _MIGRATION_012_ESCALATION),
    (13, _MIGRATION_013_ALERT_THRESHOLD),
    (14, _MIGRATION_014_CONTENT_RULES),
    (15, _MIGRATION_015_TWITCH_MESSAGE_ID),
    (16, _MIGRATION_016_MANUAL_ACTION_MARK),
)


async def current_version(conn: aiosqlite.Connection) -> int:
    cursor = await conn.execute("PRAGMA user_version")
    row = await cursor.fetchone()
    return int(row[0]) if row else 0


async def migrate(conn: aiosqlite.Connection) -> int:
    """Применить все миграции новее текущей версии БД.

    Идемпотентно: повторный вызов на уже мигрированной БД ничего не меняет
    (PRAGMA user_version отсекает уже применённые шаги), а CREATE TABLE IF
    NOT EXISTS в самих миграциях — вторая линия защиты на случай, если
    версия была применена частично.
    """
    current = await current_version(conn)

    for version, sql in MIGRATIONS:
        if version <= current:
            continue
        await conn.executescript(sql)
        # user_version не параметризуется через ? в SQLite; безопасно, т.к.
        # version — целое число из MIGRATIONS, а не внешний ввод.
        await conn.execute(f"PRAGMA user_version = {version}")
        current = version

    await conn.commit()
    return current
