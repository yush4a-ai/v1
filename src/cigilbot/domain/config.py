"""Загрузка конфигурации движка модерации из YAML.

Все веса, пороги и настройки детекторов живут в config/moderation.yml, а не
разбросаны по коду — так требует ТЗ (раздел 17 «Конфигурация») и так нужно
для расширяемости: подкрутить чувствительность после недели в SHADOW-режиме
должно быть правкой файла, а не патчем Python.

Загрузчик не проглатывает опечатки молча: неизвестный ключ в секции — это
ConfigError при старте, а не тихо проигнорированная настройка, из-за которой
система на канале вела бы себя не так, как думает оператор.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

import paths
from cigilbot.domain.types import Sensitivity, SignalFamily

# paths.CONFIG_DIR, не свой пересчёт Path(__file__).resolve().parents[N] —
# та формула завязана на глубину вложенности этого файла внутри пакета и
# однажды уже разъезжалась, когда её копии жили в bot/, cigilbot/, panel/
# по отдельности (см. paths.py). Один источник правды, не третий пересчёт.
DEFAULT_CONFIG_PATH = paths.CONFIG_DIR / "moderation.yml"
DEFAULT_CHANNELS_DIR = paths.CONFIG_DIR / "channels"


class ConfigError(ValueError):
    """Ошибка конфигурации модерации — отдельный класс, чтобы вызывающий
    код мог явно отличить «плохой YAML» от прочих ValueError."""


def _check_keys(raw: dict[str, Any], allowed: set[str], context: str) -> None:
    unknown = set(raw) - allowed
    if unknown:
        raise ConfigError(f"Неизвестные ключи в {context}: {sorted(unknown)}")


def _load_yaml_dict(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Не удалось прочитать конфиг {path}: {exc}") from exc
    data = yaml.safe_load(text) or {}
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: верхний уровень YAML должен быть словарём")
    return data


# ---------------------------------------------------------------------------
# Пороги и веса
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class SignalWeight:
    name: str
    family: SignalFamily
    weight: float


@dataclass(frozen=True, slots=True)
class RiskThresholds:
    observe: int = 30
    timeout: int = 60
    ban: int = 80

    def __post_init__(self) -> None:
        if not (0 <= self.observe < self.timeout < self.ban <= 100):
            raise ConfigError(
                "risk_thresholds должны строго возрастать в диапазоне [0,100]: "
                f"observe={self.observe}, timeout={self.timeout}, ban={self.ban}"
            )


@dataclass(frozen=True, slots=True)
class ConfidenceConfig:
    minimum_for_timeout: float = 0.75
    minimum_for_ban: float = 0.90
    family_factor: dict[int, float] = field(
        default_factory=lambda: {1: 0.45, 2: 0.70, 3: 0.88, 4: 0.95, 5: 0.98}
    )
    sample_factor_low: float = 0.6
    sample_factor_high: float = 1.0
    context_factor: dict[str, float] = field(
        default_factory=lambda: {"raid": 0.5, "giveaway": 0.5, "hype": 0.8, "normal": 1.0}
    )

    def __post_init__(self) -> None:
        if not 0.0 <= self.minimum_for_timeout <= self.minimum_for_ban <= 1.0:
            raise ConfigError(
                "confidence.minimum_for_timeout должен быть <= minimum_for_ban, "
                "оба в [0,1]"
            )
        if not self.family_factor:
            raise ConfigError("confidence.family_factor не может быть пустым")

    def family_factor_for(self, families_triggered: int) -> float:
        """Множитель уверенности по числу независимых семейств сигналов.

        Значения из конфига заданы для конкретных количеств семейств;
        для количества выше максимального заданного берём максимум таблицы —
        больше семейств не может означать МЕНЬШУЮ уверенность.
        """
        if families_triggered <= 0:
            return 0.0
        capped = min(families_triggered, max(self.family_factor))
        return self.family_factor[capped]


# ---------------------------------------------------------------------------
# Настройки отдельных детекторов
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class BurstConfig:
    enabled: bool = True
    user_messages_threshold: int = 10
    user_window_seconds: float = 5.0
    channel_messages_threshold: int = 30
    channel_window_seconds: float = 10.0


@dataclass(frozen=True, slots=True)
class DuplicateConfig:
    enabled: bool = True
    window_seconds: float = 25.0
    near_duplicate_threshold: float = 0.75
    skeleton_min_length: int = 12
    # Короче — сообщение не считается дубликатом ни с кем, даже при полном
    # текстовом совпадении. Без этого "ку", "гг", "+1" от разных обычных
    # зрителей чата стабильно давали ложный exact_duplicate (найдено на
    # replay реального чата, см. detectors/duplicate.py).
    min_content_length: int = 6


@dataclass(frozen=True, slots=True)
class LinksConfig:
    enabled: bool = True
    shared_link_window_seconds: float = 30.0
    shared_link_min_users: int = 3
    known_scam_domains: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class UnicodeConfig:
    enabled: bool = True


@dataclass(frozen=True, slots=True)
class LanguageConfig:
    enabled: bool = True
    expected_languages: tuple[str, ...] = ("ru", "en")
    min_confidence: float = 0.65


@dataclass(frozen=True, slots=True)
class AccountConfig:
    enabled: bool = True
    new_account_days: float = 7.0
    no_history_message_count: int = 1


@dataclass(frozen=True, slots=True)
class UsernameConfig:
    enabled: bool = True


@dataclass(frozen=True, slots=True)
class CrossChannelConfig:
    """Cross-Channel Bot Fingerprint (направление 03 master-plan.html)."""

    enabled: bool = True


@dataclass(frozen=True, slots=True)
class EmoteConfig:
    enabled: bool = True
    repeat_threshold: int = 8


@dataclass(frozen=True, slots=True)
class KeywordOverlapConfig:
    """Совпадение по значимым словам, без учёта порядка/структуры — ловит
    перефразированный self-promo спам, который duplicate.py (посимвольные
    триграммы) пропускает. См. detectors/keyword_overlap.py."""

    enabled: bool = True
    window_seconds: float = 90.0
    # Jaccard по множествам значимых слов — доля общих слов от объединения.
    # Калибровано прогоном на реальной перефразированной self-promo
    # кампании (12 вариаций одной фразы, короткие сообщения твич-чата):
    # медианный Jaccard между вариациями оказался 0.40-0.50, при пороге
    # 0.6 (изначальная догадка) детектор находил совпадение только в 3
    # парах из 11 — большинство реальной кампании проходило мимо. Ниже
    # near_duplicate_threshold (0.75) намеренно: совпадение по словам не
    # обязано быть таким же строгим — компенсируется min_matches (нужно
    # несколько независимых подтверждений, не одна пара сообщений).
    overlap_threshold: float = 0.35
    # 1, не 3 — короткие сообщения твич-чата ("го стрим глянь") после
    # фильтра стоп-слов часто дают всего 2-3 значимых слова; порог 3
    # отсеивал большинство реальной атаки целиком, до сравнения с кем-либо.
    min_significant_words: int = 1
    # Сколько ДРУГИХ сообщений должны пересечься по словам, чтобы считать
    # это координацией, а не двумя зрителями, случайно попавшими в одну
    # тему — главный тормоз против ложных срабатываний при мягком пороге
    # overlap_threshold выше.
    min_matches: int = 3


@dataclass(frozen=True, slots=True)
class DetectorsConfig:
    burst: BurstConfig = field(default_factory=BurstConfig)
    duplicate: DuplicateConfig = field(default_factory=DuplicateConfig)
    links: LinksConfig = field(default_factory=LinksConfig)
    unicode: UnicodeConfig = field(default_factory=UnicodeConfig)
    language: LanguageConfig = field(default_factory=LanguageConfig)
    account: AccountConfig = field(default_factory=AccountConfig)
    username: UsernameConfig = field(default_factory=UsernameConfig)
    emote: EmoteConfig = field(default_factory=EmoteConfig)
    cross_channel: CrossChannelConfig = field(default_factory=CrossChannelConfig)
    keyword_overlap: KeywordOverlapConfig = field(default_factory=KeywordOverlapConfig)


@dataclass(frozen=True, slots=True)
class ClusterConfig:
    """Настройки группировки пользователей, действующих согласованно.

    similarity_threshold и min_content_length_for_edge — отдельные от
    detectors.duplicate пороги: кластеризация ищет РЁБРА между разными
    пользователями по всему окну, а не сигнал для одного сообщения, и
    ошибочно построенный кластер обходится дороже одного ложного сигнала —
    поэтому пороги здесь можно (и по умолчанию нужно) держать строже.
    """

    enabled: bool = True
    window_seconds: float = 60.0
    min_users: int = 4
    arrival_window_seconds: float = 20.0
    similarity_threshold: float = 0.75
    # Короче этого — сообщение не участвует в построении content-рёбер
    # кластера (ни по minhash, ни по skeleton). Ключевая защита от хайпа:
    # без неё "+", "гг", "лол" от сотни разных зрителей стали бы кластером.
    min_content_length_for_edge: int = 6
    # Доля первых сообщений на канале среди участников, начиная с которой
    # выдаётся сигнал mass_first_messages.
    mass_first_message_ratio_threshold: float = 0.5
    # Ручной стоп-лист нормализованных фраз/skeleton'ов, которые никогда не
    # формируют content-ребро, даже если длиннее min_content_length_for_edge
    # (устойчивые обороты чата конкретного канала). Автоматическое построение
    # из истории — см. docs/moderation-plan.md, раздел 12 (этап 6, replay).
    excluded_phrases: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class TrustConfig:
    """Автоматическое доверие по истории (этап 9a, пункт D раздела 10 ТЗ).

    Оба порога должны выполниться одновременно, а не любой из двух —
    иначе аккаунт, "проживший" месяц без сообщений, а затем внезапно
    начавший спамить, получил бы доверие просто по возрасту, а активный
    бот, отправивший сто сообщений за минуту, получил бы его просто по
    количеству. Найдено на replay реального чата (этап 6): постоянные
    зрители типа tema7_5/digitalthevoid копипаста-перекликаются похоже на
    координированную атаку, но органично, с историей на канале.
    """

    enabled: bool = True
    min_messages_for_regular: int = 20
    min_days_for_regular: float = 3.0
    # Насколько сильно REGULAR снижает risk_score относительно того же
    # набора сигналов у неизвестного пользователя (1.0 = без изменений).
    regular_risk_multiplier: float = 0.7


# ---------------------------------------------------------------------------
# Профиль канала — отдельный файл, чтобы у каждого канала были свои языки
# без правки общего moderation.yml
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class ChannelProfile:
    channel: str
    primary_language: str = "ru"
    expected_languages: tuple[str, ...] = ("ru", "en")
    # НЕ причина действия сама по себе — просто слабый сигнал внутри
    # detectors/language.py. См. docs/moderation-plan.md, раздел 9.
    suspicious_languages: tuple[str, ...] = ()


def load_channel_profile(
    channel: str, channels_dir: Path = DEFAULT_CHANNELS_DIR
) -> ChannelProfile:
    path = channels_dir / f"{channel}.yml"
    if not path.exists():
        return ChannelProfile(channel=channel)

    raw = _load_yaml_dict(path)
    # "autoclip" — секция того же файла, читаемая отдельно
    # bot.autoclip_config.load_autoclip_channel_config (см. её докстринг);
    # здесь она разрешена, но не парсится — иначе типо в имени ключа
    # автоклипа никогда бы не поймал ConfigError, а любая правка автоклипа
    # ломала бы load_channel_profile через _check_keys неизвестных ключей.
    _check_keys(raw, {"channel_profile", "autoclip"}, str(path))
    profile_raw = raw.get("channel_profile", {})
    _check_keys(
        profile_raw,
        {"primary_language", "expected_languages", "suspicious_languages"},
        f"{path}:channel_profile",
    )
    return ChannelProfile(
        channel=channel,
        primary_language=profile_raw.get("primary_language", "ru"),
        expected_languages=tuple(profile_raw.get("expected_languages", ["ru", "en"])),
        suspicious_languages=tuple(profile_raw.get("suspicious_languages", [])),
    )


# ---------------------------------------------------------------------------
# Полный конфиг
# ---------------------------------------------------------------------------

_DEFAULT_SIGNAL_WEIGHTS: dict[str, tuple[SignalFamily, float]] = {
    "user_message_burst": (SignalFamily.TIMING, 15),
    "channel_message_burst": (SignalFamily.TIMING, 10),
    "exact_duplicate": (SignalFamily.CONTENT, 25),
    "near_duplicate": (SignalFamily.CONTENT, 20),
    "skeleton_match": (SignalFamily.CONTENT, 15),
    "link_present": (SignalFamily.CONTENT, 10),
    "shared_link_multi_user": (SignalFamily.NETWORK, 30),
    "url_shortener": (SignalFamily.CONTENT, 10),
    "known_scam_domain": (SignalFamily.CONTENT, 35),
    "invisible_chars": (SignalFamily.ENCODING, 25),
    "homoglyph_mix": (SignalFamily.ENCODING, 20),
    "script_mix_in_word": (SignalFamily.ENCODING, 10),
    "unexpected_language": (SignalFamily.ENCODING, 3),
    "new_account": (SignalFamily.IDENTITY, 10),
    "first_message": (SignalFamily.IDENTITY, 5),
    "no_history": (SignalFamily.IDENTITY, 5),
    "generated_username_pattern": (SignalFamily.IDENTITY, 8),
    "emote_spam": (SignalFamily.CONTENT, 10),
    "zalgo_text_spam": (SignalFamily.CONTENT, 8),
    "synchronized_arrival": (SignalFamily.TIMING, 25),
    "cluster_membership": (SignalFamily.NETWORK, 25),
    "mass_first_messages": (SignalFamily.NETWORK, 20),
    "keyword_overlap": (SignalFamily.CONTENT, 20),
    "known_bad_actor": (SignalFamily.HISTORY, 30),
}


@dataclass(frozen=True, slots=True)
class ModerationConfig:
    version: int
    sensitivity: Sensitivity
    risk: RiskThresholds
    confidence: ConfidenceConfig
    mode_multipliers: dict[Sensitivity, float]
    signal_weights: dict[str, SignalWeight]
    detectors: DetectorsConfig
    cluster: ClusterConfig
    trust: TrustConfig

    def weight(self, signal_name: str) -> SignalWeight:
        try:
            return self.signal_weights[signal_name]
        except KeyError:
            raise ConfigError(f"Нет веса для сигнала {signal_name!r} в конфиге") from None

    def mode_multiplier(self, sensitivity: Sensitivity | None = None) -> float:
        key = sensitivity or self.sensitivity
        try:
            return self.mode_multipliers[key]
        except KeyError:
            raise ConfigError(f"Нет множителя режима для {key!r} в конфиге") from None


_TOP_LEVEL_KEYS = {
    "version", "mode", "risk_thresholds", "confidence", "mode_multipliers",
    "signals", "detectors", "cluster", "trust",
}


def _parse_risk(raw: dict[str, Any]) -> RiskThresholds:
    _check_keys(raw, {"observe", "timeout", "ban"}, "risk_thresholds")
    return RiskThresholds(**raw)


def _parse_trust(raw: dict[str, Any]) -> TrustConfig:
    _check_keys(
        raw,
        {"enabled", "min_messages_for_regular", "min_days_for_regular", "regular_risk_multiplier"},
        "trust",
    )
    return TrustConfig(**raw)


def _parse_cluster(raw: dict[str, Any]) -> ClusterConfig:
    _check_keys(
        raw,
        {
            "enabled", "window_seconds", "min_users", "arrival_window_seconds",
            "similarity_threshold", "min_content_length_for_edge",
            "mass_first_message_ratio_threshold", "excluded_phrases",
        },
        "cluster",
    )
    kwargs = dict(raw)
    if "excluded_phrases" in kwargs:
        kwargs["excluded_phrases"] = tuple(kwargs["excluded_phrases"])
    return ClusterConfig(**kwargs)


def _parse_confidence(raw: dict[str, Any]) -> ConfidenceConfig:
    _check_keys(
        raw,
        {
            "minimum_for_timeout", "minimum_for_ban", "family_factor",
            "sample_factor_low", "sample_factor_high", "context_factor",
        },
        "confidence",
    )
    kwargs: dict[str, Any] = dict(raw)
    if "family_factor" in kwargs:
        kwargs["family_factor"] = {int(k): float(v) for k, v in kwargs["family_factor"].items()}
    return ConfidenceConfig(**kwargs)


# SEC-004 аудита: unexpected_language — единственный сигнал, для которого
# весь остальной код (language.py, docs/moderation-plan.md) декларирует
# жёсткий инвариант "строго ниже любого другого сигнала" — язык по короткой
# фразе чата ненадёжен (30-50% ошибок langdetect), и весь дизайн защиты от
# false positive на этом сигнале держится на том, что он один физически не
# может дотянуть даже до порога OBSERVE. Раньше это было верно только
# случайно — по умолчанию (config/moderation.yml) он и правда самый слабый,
# но ADMIN мог через Settings-экран панели поднять signals.unexpected_language.weight
# выше остальных, тихо сломав этот инвариант без единого предупреждения.
_WEAKEST_BY_DESIGN_SIGNAL = "unexpected_language"


def _parse_signals(raw: dict[str, Any]) -> dict[str, SignalWeight]:
    weights: dict[str, SignalWeight] = {}
    for name, spec in raw.items():
        _check_keys(spec, {"family", "weight"}, f"signals.{name}")
        try:
            family = SignalFamily(spec["family"])
        except ValueError as exc:
            raise ConfigError(
                f"signals.{name}.family={spec['family']!r} — неизвестное семейство"
            ) from exc
        weights[name] = SignalWeight(name=name, family=family, weight=float(spec["weight"]))

    if _WEAKEST_BY_DESIGN_SIGNAL in weights:
        language_weight = weights[_WEAKEST_BY_DESIGN_SIGNAL].weight
        heavier = [
            f"{n} ({w.weight})"
            for n, w in weights.items()
            if n != _WEAKEST_BY_DESIGN_SIGNAL and w.weight <= language_weight
        ]
        if heavier:
            raise ConfigError(
                f"signals.{_WEAKEST_BY_DESIGN_SIGNAL}.weight={language_weight} должен быть "
                f"строго МЕНЬШЕ веса любого другого сигнала (определение языка по короткой "
                f"фразе чата ненадёжно — см. docs/moderation-plan.md); сейчас не меньше: "
                f"{', '.join(sorted(heavier))}"
            )

    return weights


def _section(raw: dict[str, Any], name: str, allowed: set[str]) -> dict[str, Any]:
    spec = raw.get(name, {})
    _check_keys(spec, allowed, f"detectors.{name}")
    return dict(spec)


def _parse_detectors(raw: dict[str, Any]) -> DetectorsConfig:
    _check_keys(
        raw,
        {
            "burst", "duplicate", "links", "unicode", "language", "account", "username",
            "emote", "keyword_overlap", "cross_channel",
        },
        "detectors",
    )

    burst = _section(
        raw, "burst",
        {
            "enabled", "user_messages_threshold", "user_window_seconds",
            "channel_messages_threshold", "channel_window_seconds",
        },
    )
    duplicate = _section(
        raw, "duplicate",
        {
            "enabled", "window_seconds", "near_duplicate_threshold", "skeleton_min_length",
            "min_content_length",
        },
    )
    links = _section(
        raw, "links",
        {"enabled", "shared_link_window_seconds", "shared_link_min_users", "known_scam_domains"},
    )
    if "known_scam_domains" in links:
        links["known_scam_domains"] = tuple(links["known_scam_domains"])

    unicode_cfg = _section(raw, "unicode", {"enabled"})

    language = _section(raw, "language", {"enabled", "expected_languages", "min_confidence"})
    if "expected_languages" in language:
        language["expected_languages"] = tuple(language["expected_languages"])

    account = _section(
        raw, "account", {"enabled", "new_account_days", "no_history_message_count"}
    )
    username = _section(raw, "username", {"enabled"})
    emote = _section(raw, "emote", {"enabled", "repeat_threshold"})
    keyword_overlap = _section(
        raw, "keyword_overlap",
        {"enabled", "window_seconds", "overlap_threshold", "min_significant_words", "min_matches"},
    )
    cross_channel = _section(raw, "cross_channel", {"enabled"})

    return DetectorsConfig(
        burst=BurstConfig(**burst),
        duplicate=DuplicateConfig(**duplicate),
        links=LinksConfig(**links),
        unicode=UnicodeConfig(**unicode_cfg),
        language=LanguageConfig(**language),
        account=AccountConfig(**account),
        username=UsernameConfig(**username),
        emote=EmoteConfig(**emote),
        keyword_overlap=KeywordOverlapConfig(**keyword_overlap),
        cross_channel=CrossChannelConfig(**cross_channel),
    )


def default_config() -> ModerationConfig:
    """Конфиг из встроенных дефолтов, без похода на диск.

    Используется тестами (не зависеть от файловой системы и CWD) и как
    аварийный fallback, если config/moderation.yml не найден.
    """
    return ModerationConfig(
        version=1,
        sensitivity=Sensitivity.BALANCED,
        risk=RiskThresholds(),
        confidence=ConfidenceConfig(),
        mode_multipliers={
            Sensitivity.SAFE: 0.8,
            Sensitivity.BALANCED: 1.0,
            Sensitivity.AGGRESSIVE: 1.25,
            Sensitivity.ATTACK: 1.5,
        },
        signal_weights={
            name: SignalWeight(name=name, family=family, weight=weight)
            for name, (family, weight) in _DEFAULT_SIGNAL_WEIGHTS.items()
        },
        detectors=DetectorsConfig(),
        cluster=ClusterConfig(),
        trust=TrustConfig(),
    )


def load_config(path: Path = DEFAULT_CONFIG_PATH) -> ModerationConfig:
    if not path.exists():
        raise ConfigError(f"Конфиг модерации не найден: {path}")

    raw = _load_yaml_dict(path)
    _check_keys(raw, _TOP_LEVEL_KEYS, str(path))

    defaults = default_config()
    try:
        sensitivity = Sensitivity(raw["mode"]) if "mode" in raw else defaults.sensitivity
    except ValueError as exc:
        raise ConfigError(f"mode={raw['mode']!r} — неизвестный режим чувствительности") from exc

    try:
        mode_multipliers = (
            {Sensitivity(k): float(v) for k, v in raw["mode_multipliers"].items()}
            if "mode_multipliers" in raw
            else defaults.mode_multipliers
        )
    except ValueError as exc:
        raise ConfigError(f"mode_multipliers: неизвестный режим — {exc}") from exc

    return ModerationConfig(
        version=int(raw.get("version", defaults.version)),
        sensitivity=sensitivity,
        risk=_parse_risk(raw["risk_thresholds"]) if "risk_thresholds" in raw else defaults.risk,
        confidence=(
            _parse_confidence(raw["confidence"]) if "confidence" in raw else defaults.confidence
        ),
        mode_multipliers=mode_multipliers,
        signal_weights=(
            _parse_signals(raw["signals"]) if "signals" in raw else defaults.signal_weights
        ),
        detectors=_parse_detectors(raw["detectors"]) if "detectors" in raw else defaults.detectors,
        cluster=_parse_cluster(raw["cluster"]) if "cluster" in raw else defaults.cluster,
        trust=_parse_trust(raw["trust"]) if "trust" in raw else defaults.trust,
    )
