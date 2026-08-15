"""Конфигурация автоклиппинга: пороги всплеска чата, ключевые фразы,
кулдаун — отдельно от cigilbot.domain.config, потому что автоклип не часть
движка модерации и не должен тянуть за собой её строгую типизацию (bot/ не
проверяется mypy strict, cigilbot/ — проверяется). Тот же приём точечной
загрузки YAML с отказом на неизвестных ключах, что и в
cigilbot/domain/config.py (_check_keys/_load_yaml_dict), продублирован
здесь, а не импортирован — тот же принцип, что и с
cigilbot/integrations/clip_token.py::_write_env_values.

Читает ТОТ ЖЕ файл, что и cigilbot.domain.config.load_channel_profile
(config/channels/<channel>.yml), но отдельную top-level секцию autoclip: —
не заводит второй файл на канал.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

import paths

DEFAULT_CHANNELS_DIR: Path = paths.CONFIG_DIR / "channels"


class AutoclipConfigError(ValueError):
    """Плохой YAML в секции autoclip: — отдельный класс, чтобы вызывающий
    код мог явно отличить его от прочих ValueError."""


def _check_keys(raw: dict[str, Any], allowed: set[str], context: str) -> None:
    unknown = set(raw) - allowed
    if unknown:
        raise AutoclipConfigError(f"Неизвестные ключи в {context}: {sorted(unknown)}")


def _load_yaml_dict(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise AutoclipConfigError(f"Не удалось прочитать конфиг {path}: {exc}") from exc
    data = yaml.safe_load(text) or {}
    if not isinstance(data, dict):
        raise AutoclipConfigError(f"{path}: верхний уровень YAML должен быть словарём")
    return data


@dataclass(frozen=True, slots=True)
class BurstTriggerConfig:
    enabled: bool = True
    window_seconds: float = 20.0
    unique_authors_threshold: int = 12
    # Авто-подстройка порога под текущее число зрителей на канале (Twitch
    # Helix GET /streams, см. AutoclipHub._poll_viewer_counts) — вместо
    # фиксированного unique_authors_threshold. auto_scale_percent — доля
    # зрителей, auto_scale_min/max — границы, чтобы формула не требовала
    # нереально много авторов на гигантских каналах и не срабатывала почти
    # на каждое сообщение на крошечных. unique_authors_threshold остаётся
    # полем на случай auto_scale_enabled=False (обычный фиксированный режим)
    # и как fallback, пока стрим оффлайн или Twitch недоступен.
    auto_scale_enabled: bool = False
    auto_scale_percent: float = 0.04
    auto_scale_min: int = 4
    auto_scale_max: int = 200


@dataclass(frozen=True, slots=True)
class KeywordTriggerConfig:
    enabled: bool = True
    phrases: tuple[str, ...] = ("клип это", "клип", "clip it", "clip that")


@dataclass(frozen=True, slots=True)
class VoiceTriggerConfig:
    enabled: bool = True
    phrases: tuple[str, ...] = ("клип это", "заклипай", "clip it", "clip that")


@dataclass(frozen=True, slots=True)
class AutoclipChannelConfig:
    # По умолчанию выключено — канал должен явно включить автоклип в своём
    # config/channels/<channel>.yml, иначе включённый AUTOCLIP_ENABLED=true
    # на уровне процесса начал бы клипать на всех каналах без разбора.
    enabled: bool = False
    # Общий кулдаун для burst и keyword (не два отдельных значения) —
    # иначе была бы возможность рассинхронизации между ними без пользы:
    # смысл один и тот же, "не клипать слишком часто по этому каналу".
    cooldown_seconds: float = 300.0
    # Twitch Helix POST /clips не принимает ни длительность, ни сдвиг назад
    # — сам решает, сколько секунд до/после момента вызова попадёт в клип.
    # Единственный доступный рычаг — самим отложить вызов create_clip()
    # после срабатывания триггера, тогда момент реакции стримера ("клип
    # это!") окажется ближе к концу окна, а не к началу, и в кадр попадёт
    # то, что было ДО реакции, а не только сама реакция.
    capture_delay_seconds: float = 0.0
    burst: BurstTriggerConfig = field(default_factory=BurstTriggerConfig)
    keyword: KeywordTriggerConfig = field(default_factory=KeywordTriggerConfig)
    voice: VoiceTriggerConfig = field(default_factory=VoiceTriggerConfig)


def _parse_burst(raw: dict[str, Any]) -> BurstTriggerConfig:
    _check_keys(
        raw,
        {
            "enabled", "window_seconds", "unique_authors_threshold",
            "auto_scale_enabled", "auto_scale_percent", "auto_scale_min", "auto_scale_max",
        },
        "autoclip.burst",
    )
    return BurstTriggerConfig(**raw)


def _parse_keyword(raw: dict[str, Any]) -> KeywordTriggerConfig:
    _check_keys(raw, {"enabled", "phrases"}, "autoclip.keyword")
    if "phrases" in raw:
        raw = {**raw, "phrases": tuple(raw["phrases"])}
    return KeywordTriggerConfig(**raw)


def _parse_voice(raw: dict[str, Any]) -> VoiceTriggerConfig:
    _check_keys(raw, {"enabled", "phrases"}, "autoclip.voice")
    if "phrases" in raw:
        raw = {**raw, "phrases": tuple(raw["phrases"])}
    return VoiceTriggerConfig(**raw)


def load_autoclip_channel_config(
    channel: str, channels_dir: Path = DEFAULT_CHANNELS_DIR
) -> AutoclipChannelConfig:
    """Секции или файла нет -> AutoclipChannelConfig(enabled=False) —
    автоклип выключен по умолчанию, канал должен включить его явно."""
    path = channels_dir / f"{channel}.yml"
    if not path.exists():
        return AutoclipChannelConfig()

    raw = _load_yaml_dict(path)
    if "autoclip" not in raw:
        return AutoclipChannelConfig()

    section = raw["autoclip"]
    _check_keys(
        section,
        {"enabled", "cooldown_seconds", "capture_delay_seconds", "burst", "keyword", "voice"},
        f"{path}:autoclip",
    )

    return AutoclipChannelConfig(
        enabled=bool(section.get("enabled", False)),
        cooldown_seconds=float(section.get("cooldown_seconds", 300.0)),
        capture_delay_seconds=float(section.get("capture_delay_seconds", 0.0)),
        burst=_parse_burst(section.get("burst", {})),
        keyword=_parse_keyword(section.get("keyword", {})),
        voice=_parse_voice(section.get("voice", {})),
    )
