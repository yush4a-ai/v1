import os
from dataclasses import dataclass

from dotenv import load_dotenv

import paths

# BOT_ENV_FILE позволяет держать несколько ботов на разные каналы: у каждого
# свой .env.<profile>, а вместе с ним своя БД, очередь и логи (см. INSTANCE
# ниже). Панель именно так и разводит профили, запуская main.py с этой
# переменной.
#
# Без неё читается общий .env В КОРНЕ МОНОРЕПО, а не рядом с main.py: после
# слияния панелей общий конфиг живёт в одном файле на весь репозиторий.
# Раньше здесь было относительное ".env", то есть файл искался относительно
# текущей папки процесса — работало только потому, что бота всегда запускали
# из каталога рядом с main.py.
ENV_FILE = os.environ.get("BOT_ENV_FILE") or str(paths.REPO_ROOT / ".env")
load_dotenv(ENV_FILE)


@dataclass
class Config:
    bot_token: str
    bot_nick: str
    channel: str
    # None — чисто модераторский профиль без разговорного AI (см. CIGILBOT):
    # main.py тогда не создаёт Brain вовсе, а не создаёт его с пустым ключом.
    deepseek_api_key: str | None
    streamer_name: str
    streamer_context: str
    voice_enabled: bool
    triggers: list[str]
    voice_triggers: list[str]
    voice_require_trigger: bool
    voice_source: str
    voice_stream_channel: str
    voice_silence_threshold: int
    voice_free_reply_cooldown: int
    personality: str
    instance: str
    moderation_enabled: bool
    autoclip_enabled: bool

    @property
    def db_path(self) -> str:
        return str(paths.BOT_VAR / self._name("bot", "db"))

    @property
    def usage_path(self) -> str:
        return str(paths.BOT_VAR / self._name("usage", "json"))

    @property
    def queue_path(self) -> str:
        return str(paths.BOT_VAR / self._name("voice_input", "txt"))

    def log_path(self, name: str) -> str:
        return str(paths.BOT_LOGS / self._name(name, "log"))

    def _name(self, name: str, ext: str) -> str:
        """Имя файла инстанса: INSTANCE разводит несколько ботов по разным
        файлам в одной папке (bot.<instance>.db). Панель повторяет этот же
        алгоритм в panel/bots_api.py::_instance_path, чтобы читать файлы
        того инстанса, который сейчас запущен."""
        return f"{name}.{self.instance}.{ext}" if self.instance else f"{name}.{ext}"


def load_config() -> Config:
    bot_token = os.environ["TWITCH_BOT_TOKEN"]
    if not bot_token.startswith("oauth:"):
        bot_token = f"oauth:{bot_token}"

    raw_triggers = os.environ.get("BOT_TRIGGER", "бот").lower()
    triggers = [t for t in raw_triggers.split() if t]

    # Для голоса триггеры отдельные: распознавание речи коверкает имя
    # ("Шинра" слышится как "Шершень", "Синра"), поэтому список шире.
    raw_voice_triggers = os.environ.get("VOICE_TRIGGER", "").lower()
    voice_triggers = [t for t in raw_voice_triggers.split() if t] or triggers

    channel = os.environ["TWITCH_CHANNEL"].lstrip("#").lower()

    return Config(
        bot_token=bot_token,
        bot_nick=os.environ["TWITCH_BOT_NICK"],
        channel=channel,
        deepseek_api_key=os.environ.get("DEEPSEEK_API_KEY", "").strip() or None,
        streamer_name=os.environ.get("STREAMER_NAME", "стример"),
        # Свободный текст: пол/имя/город/тематика стрима — коротко описывает,
        # кто такой стример этого канала, чтобы бот не путал его пол и не
        # придумывал случайные детали. Не часть характера бота, отдельная
        # вводная про площадку, поэтому хранится отдельно от BOT_PERSONALITY.
        streamer_context=os.environ.get("STREAMER_CONTEXT", "").strip(),
        voice_enabled=os.environ.get("VOICE_ENABLED", "false").lower() == "true",
        triggers=triggers,
        voice_triggers=voice_triggers,
        voice_require_trigger=os.environ.get("VOICE_REQUIRE_TRIGGER", "false").lower()
        == "true",
        # mic — микрофон этого компьютера, twitch — аудиодорожка стрима
        voice_source=os.environ.get("VOICE_SOURCE", "mic").lower(),
        voice_stream_channel=os.environ.get("VOICE_STREAM_CHANNEL", channel)
        .lstrip("#")
        .lower(),
        voice_silence_threshold=int(os.environ.get("VOICE_SILENCE_THRESHOLD", "500")),
        voice_free_reply_cooldown=int(os.environ.get("VOICE_FREE_REPLY_COOLDOWN", "20")),
        personality=os.environ.get(
            "BOT_PERSONALITY",
            "Ты — дружелюбный чат-бот стримера. Отвечай коротко и с юмором.",
        ),
        instance=os.environ.get("INSTANCE", "").strip(),
        # На этапе 5 движок модерации работает только в SHADOW-режиме —
        # наблюдает и пишет вердикты в БД, но ничего не делает в чате.
        # Выбор SIMULATION/SHADOW/LIVE и авто-действия появятся на этапе 7-9.
        moderation_enabled=os.environ.get("MODERATION_ENABLED", "true").lower() == "true",
        # Выключено по умолчанию — в отличие от moderation_enabled: клипы
        # видны зрителям и создаются от лица настроенного Twitch-аккаунта,
        # включать стоит осознанно, после подбора порогов в
        # config/channels/<канал>.yml (см. bot/autoclip_config.py).
        autoclip_enabled=os.environ.get("AUTOCLIP_ENABLED", "false").lower() == "true",
    )
