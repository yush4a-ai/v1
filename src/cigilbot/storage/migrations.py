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

# Переключатель автоклипа канала из панели (bot/autoclip.py), без рестарта
# бота — тот же singleton-паттерн, что mod_content_settings (миграция 014).
# enabled здесь ПОВЕРХ, а не ВМЕСТО autoclip.enabled в
# config/channels/<канал>.yml: YAML остаётся дефолтом при первом включении
# канала, эта таблица — быстрый живой рубильник поверх него, который
# AutoclipHub перечитывает в своём reconcile-цикле. NULL/нет строки —
# "явного решения через панель не было", тогда используется значение из
# YAML, а не жёстко закодированный дефолт здесь.
_MIGRATION_017_AUTOCLIP_SETTINGS = """
CREATE TABLE IF NOT EXISTS mod_autoclip_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    enabled INTEGER NOT NULL,
    updated_by TEXT NOT NULL,
    updated_at REAL NOT NULL
);
"""

# Живые пороги трёх триггеров (bot/autoclip.py) поверх той же таблицы, что
# миграция 017 завела для enabled — расширяет её, а не заводит отдельную,
# потому что смысл один и тот же ("настройка автоклипа канала из панели",
# singleton-строка id=1). NULL в любом новом поле — тот же принцип, что и у
# enabled: "панель не трогала этот параметр", используется YAML.
#
# enabled тоже становится NULL-допустимым (пересоздание таблицы — SQLite не
# умеет снимать NOT NULL через plain ALTER TABLE): строка теперь может
# существовать только из-за set_autoclip_thresholds (пороги настроены
# раньше, чем канал явно включили переключателем), и такая запись не
# должна интерпретироваться как "панель решила выключить канал". Различать
# два случая колонкой-флагом (enabled_explicit) было бы дублированием
# смысла, который NULL уже выражает сам по себе.
#
# keyword_phrases/voice_phrases — JSON-массив строк (json.dumps/json.loads,
# тот же приём, что required_signal_names в mod_patterns) — список
# переменной длины плохо ложится в отдельные колонки постоянного числа.
_MIGRATION_018_AUTOCLIP_THRESHOLDS = """
CREATE TABLE mod_autoclip_settings_new (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    enabled INTEGER,
    updated_by TEXT NOT NULL,
    updated_at REAL NOT NULL,
    burst_unique_authors_threshold INTEGER,
    burst_window_seconds REAL,
    keyword_phrases TEXT,
    voice_phrases TEXT,
    cooldown_seconds REAL
);
INSERT INTO mod_autoclip_settings_new (id, enabled, updated_by, updated_at)
    SELECT id, enabled, updated_by, updated_at FROM mod_autoclip_settings;
DROP TABLE mod_autoclip_settings;
ALTER TABLE mod_autoclip_settings_new RENAME TO mod_autoclip_settings;
"""

# Авто-подстройка порога всплеска под текущее число зрителей канала
# (bot/autoclip.py, HelixClient.get_streams) — та же таблица, что пороги
# (миграция 018): singleton-строка "настройки автоклипа канала из панели".
# Все новые поля NULL-допустимы без NOT NULL, поэтому, в отличие от
# миграции 018, простой ADD COLUMN достаточен — пересоздавать таблицу не
# нужно. last_viewer_count — кэш последнего успешного опроса Twitch
# (AutoclipHub._poll_viewer_counts пишет сюда), чтобы панель могла
# показать реальное текущее вычисленное значение порога, а не только сам
# факт "авто-режим включён", даже между опросами.
_MIGRATION_019_AUTOCLIP_AUTO_SCALE = """
ALTER TABLE mod_autoclip_settings ADD COLUMN burst_auto_scale_enabled INTEGER;
ALTER TABLE mod_autoclip_settings ADD COLUMN burst_auto_scale_percent REAL;
ALTER TABLE mod_autoclip_settings ADD COLUMN burst_auto_scale_min INTEGER;
ALTER TABLE mod_autoclip_settings ADD COLUMN burst_auto_scale_max INTEGER;
ALTER TABLE mod_autoclip_settings ADD COLUMN last_viewer_count INTEGER;
ALTER TABLE mod_autoclip_settings ADD COLUMN last_viewer_count_at REAL;
"""

# Токен для клиппинга (TWITCH_CLIP_*, scope clips:edit) — per-channel, не в
# .env. Причина: Twitch Helix POST /helix/clips принимает только токен,
# принадлежащий реальному broadcaster'у/модератору/редактору ИМЕННО ЭТОГО
# канала — общий на весь бот .env-токен (как было раньше) работает только
# для того одного канала, на который он выпущен, и молча проваливает клипы
# на остальных (см. инцидент: paverpapa не получал клипов, потому что
# TWITCH_CLIP_* в .env был выпущен от dobriy_yura). Тот же singleton-приём,
# что и mod_autoclip_settings/mod_content_settings — id=1, broadcaster_id не
# хранится в строке, эту роль играет сам файл mod.<broadcaster_id>.db.
# Отдельная таблица, не расширение mod_autoclip_settings: секреты — не то
# же самое, что пороги, разная таблица снижает риск случайно захватить
# токен вместе с остальными настройками при отладке/дампе.
_MIGRATION_020_CLIP_TOKEN = """
CREATE TABLE IF NOT EXISTS mod_clip_token (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    access_token TEXT NOT NULL,
    refresh_token TEXT NOT NULL,
    user_login TEXT NOT NULL,
    user_id TEXT NOT NULL,
    updated_at REAL NOT NULL
);
"""

# Twitch Helix POST /clips не принимает ни длительность, ни сдвиг назад —
# сам решает окно клипа относительно момента вызова API. capture_delay_
# seconds придерживает вызов create_clip() после срабатывания триггера,
# чтобы момент реакции стримера оказался ближе к концу окна, а не к началу
# (см. bot/autoclip.py::ChannelAutoclip._create_clip).
_MIGRATION_021_AUTOCLIP_CAPTURE_DELAY = """
ALTER TABLE mod_autoclip_settings ADD COLUMN capture_delay_seconds REAL;
"""

# mod_actions.cluster_id теряет REFERENCES mod_clusters(id) — этот столбец
# аудиторская метка ("это действие было по такому-то кластеру"), а не живая
# ссылка, обязанная указывать на существующую строку. request.cluster_id
# приходит из payload, поставленного панелью в очередь заранее; исполнение
# в executor.py и запись аудита случаются позже, к этому моменту кластер
# мог уже быть заархивирован/удалён — тот же принцип, что чат-лог не
# обязан ломаться, если человек, о котором он говорит, потом удалил
# аккаунт. Найдено включением PRAGMA foreign_keys=ON (миграция ретеншена,
# bug-аудит 2026-08-15, HIGH #16, purge_old_records) — раньше FK в этой БД
# полностью игнорировались SQLite, ошибка не проявлялась никогда: ни
# record_action_audit с произвольным cluster_id в тестах, ни (потенциально)
# в проде на архивированных кластерах.
#
# Пересоздание таблицы, не ALTER TABLE — SQLite не умеет снимать
# REFERENCES с колонки через plain ALTER TABLE (тот же паттерн, что
# миграция 018 для NOT NULL).
_MIGRATION_022_ACTIONS_CLUSTER_ID_SOFT_REF = """
CREATE TABLE mod_actions_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL NOT NULL,
    actor TEXT NOT NULL,
    actor_role TEXT NOT NULL,
    action TEXT NOT NULL,
    scope TEXT NOT NULL,
    cluster_id INTEGER,
    pattern_id INTEGER,
    reason TEXT,
    confirmation TEXT NOT NULL,
    succeeded INTEGER NOT NULL DEFAULT 0,
    failed INTEGER NOT NULL DEFAULT 0,
    details_json TEXT
);
INSERT INTO mod_actions_new
    SELECT id, created_at, actor, actor_role, action, scope, cluster_id, pattern_id,
           reason, confirmation, succeeded, failed, details_json
    FROM mod_actions;
DROP TABLE mod_actions;
ALTER TABLE mod_actions_new RENAME TO mod_actions;
CREATE INDEX IF NOT EXISTS idx_mod_actions_created_at ON mod_actions(created_at);
CREATE INDEX IF NOT EXISTS idx_mod_actions_actor ON mod_actions(actor);
"""

# Lease-токен на mod_action_queue (bug-аудит 2026-08-15/2026-08-18) —
# reclaim_stuck_actions определял "зависшее" задание только по возрасту
# started_at, не проверяя, жив ли исполнитель. Если два процесса бота
# одновременно работают с одним mod.<id>.db (старый завис, но не убит,
# новый уже стартовал), новый исполнитель мог реклеймить и взять задание,
# которое старый ещё физически доисполняет — задвоенный аудит и, для
# TIMEOUT, задвоенное продление длительности/инкремент prior_timeouts.
#
# lease_token — случайная строка, выданная mark_action_started() тому
# конкретному вызову, который взял задание. update_action_progress()
# (дёргается на каждую цель — см. executor.py::_run_per_target) и
# complete_action() пишут только при совпадении токена: если задание уже
# успели реклеймить (и тем самым обнулить токен) и передать другому
# исполнителю, поздние UPDATE от "зомби"-исполнителя находят 0 строк и
# тихо не применяются, вместо того чтобы затереть прогресс/результат
# актуального исполнителя.
_MIGRATION_023_ACTION_QUEUE_LEASE_TOKEN = """
ALTER TABLE mod_action_queue ADD COLUMN lease_token TEXT;
"""

# Персистентность результата автоклипа (bug-аудит 2026-08-18) — раньше
# _create_clip (bot/autoclip.py) писал clip_id/edit_url только в log.info,
# ни одной строки в БД. Если Twitch создал клип, а процесс падал до записи
# лога — клип физически существовал, но бот навсегда не знал о нём.
#
# Запись создаётся ДО вызова Helix (status='pending'), не после — это и
# есть персистентность: если процесс падает между INSERT и ответом Twitch,
# при следующем старте канала мы ТОЧНО знаем, что было незавершённое
# событие, а не молчим о нём.
#
# Пять статусов, не идемпотентность, а устойчивость к неопределённости
# (Twitch Clips API не даёт idempotency-key, повторный POST после
# потерянного ответа создал бы второй клип — retry на этот эндпоинт
# отключён явно, см. HelixClient.create_clip(retry=False)):
#   pending             — событие поставлено, ответа от Twitch ещё нет
#   created             — Twitch подтвердил (202), clip_id/edit_url
#                         записаны с первой попытки
#   failed              — Twitch точно отклонил (4xx кроме 429, или 429 —
#                         оба означают "запрос не дошёл до создания клипа
#                         на стороне Twitch", см. HelixClient.create_clip)
#   lost_after_success  — Twitch подтвердил, clip_id/edit_url известны
#                         ЖИВОМУ процессу, но первая попытка записать их
#                         не удалась (SQLite locked и т.п.) — данные не
#                         теряются, просто эта запись потребовала второй
#                         попытки со стороны бота, не Twitch
#   unknown             — либо HelixClient сам вернул outcome="unknown"
#                         (5xx/TransportError — сервер мог упасть и до, и
#                         после фактического создания клипа, не различимо
#                         в текущей реализации _request), либо запись
#                         осталась 'pending' через рестарт процесса (никто
#                         не может задним числом узнать, дошёл ли POST)
#
# Ни один статус не запускает автоматический повторный POST к Twitch —
# единственный источник нового клипа это новый независимый
# ClipTriggerEvent от реального нового триггера в чате/голосе.
_MIGRATION_024_CLIPS = """
CREATE TABLE IF NOT EXISTS mod_clips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL NOT NULL,
    trigger_reason TEXT NOT NULL,
    trigger_text TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    clip_id TEXT,
    edit_url TEXT,
    error TEXT,
    finished_at REAL
);
CREATE INDEX IF NOT EXISTS idx_mod_clips_status ON mod_clips(status);
CREATE INDEX IF NOT EXISTS idx_mod_clips_created_at ON mod_clips(created_at);
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
    (17, _MIGRATION_017_AUTOCLIP_SETTINGS),
    (18, _MIGRATION_018_AUTOCLIP_THRESHOLDS),
    (19, _MIGRATION_019_AUTOCLIP_AUTO_SCALE),
    (20, _MIGRATION_020_CLIP_TOKEN),
    (21, _MIGRATION_021_AUTOCLIP_CAPTURE_DELAY),
    (22, _MIGRATION_022_ACTIONS_CLUSTER_ID_SOFT_REF),
    (23, _MIGRATION_023_ACTION_QUEUE_LEASE_TOKEN),
    (24, _MIGRATION_024_CLIPS),
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
