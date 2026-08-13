"""Базовые типы движка модерации.

Здесь описан контракт между всеми частями системы. Правило, которое держит
архитектуру: в этом модуле нет ни одного импорта, умеющего ввод-вывод —
ни aiosqlite, ни httpx, ни twitchio. Детектор физически не может забанить
пользователя, потому что у него нет и не может быть Twitch-клиента.

Разделение detection/action из ТЗ обеспечено именно так, а не договорённостью.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum


class SignalFamily(str, Enum):
    """Семейство сигнала — ключевое понятие для расчёта confidence.

    Два сигнала одного семейства НЕ считаются независимыми подтверждениями:
    "точный дубликат" и "почти дубликат" — это один и тот же факт, увиденный
    двумя детекторами, а не два разных наблюдения. Без такой группировки
    достаточно написать пять детекторов на одно и то же явление, чтобы
    получить фальшивую уверенность 0.99 на пустом месте.
    """

    CONTENT = "content"    # что написано: дубликаты, ссылки, эмоут-спам
    TIMING = "timing"      # когда написано: скорость, синхронность
    IDENTITY = "identity"  # кто пишет: возраст аккаунта, первое сообщение, ник
    ENCODING = "encoding"  # как записано: гомоглифы, невидимые символы, язык
    NETWORK = "network"    # связи с другими: кластер, общая ссылка
    HISTORY = "history"    # что было раньше: прошлые предупреждения и таймауты


class Action(str, Enum):
    """Что система предлагает сделать. Порядок = возрастание строгости."""

    NOTHING = "NOTHING"
    OBSERVE = "OBSERVE"
    TIMEOUT = "TIMEOUT"
    BAN = "BAN"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Mode(str, Enum):
    """Режим модерации. SIMULATION и SHADOW не выполняют действий."""

    SIMULATION = "SIMULATION"  # ничего не делает, только показывает намерение
    SHADOW = "SHADOW"          # работает в реальном чате, но действий не выполняет
    LIVE = "LIVE"              # действия выполняются


class Sensitivity(str, Enum):
    """Профиль чувствительности: множители порогов и весов."""

    SAFE = "SAFE"
    BALANCED = "BALANCED"
    AGGRESSIVE = "AGGRESSIVE"
    ATTACK = "ATTACK"  # panic mode, включается вручную и сам выключается по таймеру


class ContentCategory(str, Enum):
    """Категория нарушения, пойманного словарным Rule Engine (cigilbot/content/).

    Отдельно от SignalFamily: словарное совпадение — бинарный факт (нашли
    фразу или нет), а не вероятностный признак вроде burst/duplicate, и не
    участвует в risk_score/confidence. У каждой категории своя политика
    эскалации — cigilbot/content/policy.py.
    """

    RACISM = "racism"            # оскорбления по признаку — самая строгая
    THREATS = "threats"          # угрозы насилия
    ADVERTISING = "advertising"  # реклама и спам-фразы вне детекции ботов


class TrustLevel(int, Enum):
    """Насколько пользователь известен каналу."""

    UNKNOWN = 0    # новый или почти новый
    REGULAR = 1    # обычный зритель с историей
    TRUSTED = 2    # помечен модератором как safe
    PRIVILEGED = 3  # мод/VIP/стример — под автодействия не попадает никогда


@dataclass(frozen=True, slots=True)
class Signal:
    """Одно наблюдение детектора.

    value ∈ [0, 1] — насколько признак выражен. Плавность вместо ступенек
    if/else: 6 сообщений за 5 секунд это не то же самое, что 20.

    evidence — конкретный наблюдаемый факт для объяснения модератору
    ("14 сообщений за 10 сек"). Сигнал без evidence движок не принимает:
    необъяснимых решений в системе быть не должно.
    """

    name: str
    family: SignalFamily
    weight: float
    value: float
    evidence: str

    def __post_init__(self) -> None:
        if not 0.0 <= self.value <= 1.0:
            raise ValueError(f"Signal.value должен быть в [0,1], получено {self.value!r}")
        if not self.evidence:
            raise ValueError(f"Сигнал {self.name} без evidence — решение будет необъяснимым")

    @property
    def score(self) -> float:
        """Вклад сигнала в risk score."""
        return self.weight * self.value


@dataclass(frozen=True, slots=True)
class ContentMatch:
    """Одно совпадение словарного Rule Engine с сообщением.

    matched_phrase — правило, с которым совпало; normalized_text — сообщение
    после обхода замен (транслит, разделители), тем видом, в котором
    совпадение действительно нашлось — модератору иначе не объяснить, почему
    сработало на тексте, который выглядит иначе, чем правило.
    """

    category: ContentCategory
    matched_phrase: str
    normalized_text: str


@dataclass(frozen=True, slots=True)
class ChatEvent:
    """Сообщение чата со всем, что известно на момент получения.

    Часть полей приходит из IRC-тегов мгновенно и бесплатно (user_id,
    is_first_message, badges), часть требует запроса к Helix и появляется
    позже (account_created_at). Поэтому account_created_at = None означает
    "ещё не знаем", а не "аккаунт новый" — путать эти вещи нельзя, иначе
    каждый зритель на старте будет выглядеть подозрительным.
    """

    user_id: str
    login: str
    text: str
    timestamp: float
    channel: str = ""
    display_name: str = ""
    message_id: str = ""

    # Из IRC-тегов — доступно сразу
    is_first_message: bool = False   # тег first-msg=1
    is_returning_chatter: bool = False
    is_subscriber: bool = False
    is_moderator: bool = False
    is_vip: bool = False
    is_broadcaster: bool = False
    badges: tuple[str, ...] = ()

    # Требует Helix — может быть неизвестно на момент оценки
    account_created_at: float | None = None

    @property
    def is_privileged(self) -> bool:
        """Мод, VIP или сам стример. Такие под автодействия не попадают."""
        return self.is_moderator or self.is_vip or self.is_broadcaster


@dataclass(slots=True)
class UserState:
    """Накопленное состояние пользователя в пределах сессии.

    Живёт в памяти движка. В БД уходит отдельно, через store.
    """

    user_id: str
    login: str
    first_seen: float
    last_seen: float
    message_count: int = 0
    trust_level: TrustLevel = TrustLevel.UNKNOWN
    account_created_at: float | None = None
    # История: сколько раз система уже принимала по нему решения
    prior_timeouts: int = 0
    prior_warnings: int = 0
    marked_safe: bool = False
    # Последние risk score — чтобы видеть динамику, а не только текущий момент
    recent_risks: list[float] = field(default_factory=list)

    @property
    def account_age_days(self) -> float | None:
        if self.account_created_at is None:
            return None
        return (time.time() - self.account_created_at) / 86400.0

    @property
    def is_protected(self) -> bool:
        """Пользователь, которого нельзя трогать автоматически."""
        return self.marked_safe or self.trust_level >= TrustLevel.TRUSTED

    def qualifies_for_regular(
        self, *, min_messages: int, min_days: float, now: float | None = None
    ) -> bool:
        """Достаточно ли истории на канале для автоматического REGULAR
        (этап 9a). ОБА порога обязательны — см. докстринг TrustConfig в
        config.py: только количество сообщений впустило бы активного
        бота-спамера, только возраст впустил бы старый аккаунт-болванку,
        молчавший месяц перед атакой."""
        if self.message_count < min_messages:
            return False
        age_days = ((now if now is not None else time.time()) - self.first_seen) / 86400.0
        return age_days >= min_days


@dataclass(frozen=True, slots=True)
class ClusterInfo:
    """Группа пользователей, действующих согласованно.

    risk_score/confidence считаются так же, как для отдельного вердикта
    (scoring.py/confidence.py), но на signals уровня кластера — они не
    заменяют собой Verdict каждого участника, а становятся одним из
    источников NETWORK-сигналов, которые engine.py подмешивает в вердикт
    конкретного пользователя.
    """

    cluster_id: int
    user_ids: tuple[str, ...]
    logins: tuple[str, ...]
    similarity_score: float
    arrival_window_sec: float
    first_message_ratio: float
    new_account_ratio: float
    shared_domains: tuple[str, ...]
    signals: tuple[Signal, ...]
    risk_score: int
    confidence: float
    created_at: float
    # Заполняется engine.py ПОСЛЕ кластеризации (этап 9b) — clustering.py
    # ничего не знает про Pattern Library, поэтому поле опционально и
    # по умолчанию None здесь, а не обязательный параметр конструктора.
    pattern_id: int | None = None

    @property
    def size(self) -> int:
        return len(self.user_ids)

    def to_dict(self) -> dict[str, object]:
        """Формат для API панели — пример из ТЗ (раздел 6)."""
        return {
            "cluster_id": self.cluster_id,
            "users": self.size,
            "user_ids": list(self.user_ids),
            "logins": list(self.logins),
            "risk_score": self.risk_score,
            "confidence": round(self.confidence, 3),
            "similarity_score": round(self.similarity_score, 3),
            "arrival_window_sec": round(self.arrival_window_sec, 1),
            "first_message_ratio": round(self.first_message_ratio, 3),
            "new_account_ratio": round(self.new_account_ratio, 3),
            "shared_domains": list(self.shared_domains),
            "signals": [s.name for s in self.signals],
            "created_at": self.created_at,
            "pattern_id": self.pattern_id,
        }


@dataclass(frozen=True, slots=True)
class ChannelContext:
    """Что происходит на канале прямо сейчас.

    Нужен, чтобы не принимать хайп за атаку. Во время рейда или розыгрыша
    всплеск активности — норма, и пороги обязаны это учитывать.
    """

    is_raid: bool = False
    is_giveaway: bool = False
    is_hype: bool = False
    raid_started_at: float | None = None
    messages_per_minute: float = 0.0
    unique_chatters_last_minute: int = 0

    @property
    def is_special(self) -> bool:
        return self.is_raid or self.is_giveaway or self.is_hype

    @property
    def label(self) -> str:
        if self.is_raid:
            return "рейд"
        if self.is_giveaway:
            return "розыгрыш"
        if self.is_hype:
            return "хайп-момент"
        return "обычный чат"


@dataclass(frozen=True, slots=True)
class Verdict:
    """Результат оценки. Ничего не исполняет — только описывает.

    is_provisional=True означает, что вердикт вынесен без данных о возрасте
    аккаунта (Helix ещё не ответил) и будет пересчитан. Массовые действия
    по предварительным вердиктам запрещены.
    """

    user_id: str
    login: str
    risk_score: int
    confidence: float
    signals: tuple[Signal, ...]
    recommended_action: Action
    reason: str
    timestamp: float
    families_triggered: int = 0
    cluster_id: int | None = None
    is_provisional: bool = False
    blocked_by: str = ""  # какая защита от false positive снизила действие
    mode: Mode = Mode.SHADOW
    engine_version: str = ""
    config_version: str = ""
    # Название сработавшего именованного шаблона атаки (этап 9b Pattern
    # Library) — не пересчитывает risk/confidence, только классифицирует
    # уже готовый вердикт для UI панели.
    pattern_id: int | None = None

    @property
    def risk_level(self) -> RiskLevel:
        if self.risk_score >= 80:
            return RiskLevel.CRITICAL
        if self.risk_score >= 60:
            return RiskLevel.HIGH
        if self.risk_score >= 30:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    @property
    def signal_names(self) -> tuple[str, ...]:
        return tuple(s.name for s in self.signals)

    def explain(self) -> str:
        """Человекочитаемое объяснение — то, что видит модератор.

        Никаких «ИИ считает, что это бот»: только перечисление наблюдаемых
        фактов, каждый со своим вкладом в оценку.
        """
        lines = [
            f"ДЕЙСТВИЕ: {self.recommended_action.value}",
            "",
            f"Пользователь: {self.login}",
            f"Риск: {self.risk_score}/100",
            f"Уверенность: {self.confidence:.2f}",
            "",
            "Сигналы:",
        ]
        for s in sorted(self.signals, key=lambda x: x.score, reverse=True):
            lines.append(f"  + {s.evidence} ({s.name}, +{s.score:.0f})")
        if not self.signals:
            lines.append("  (нет)")
        lines += ["", f"Причина: {self.reason}"]
        if self.blocked_by:
            lines.append(f"Ограничено защитой: {self.blocked_by}")
        if self.is_provisional:
            lines.append("Вердикт предварительный: возраст аккаунта ещё не получен")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, object]:
        """Формат для API панели и аудита."""
        return {
            "user_id": self.user_id,
            "login": self.login,
            "risk_score": self.risk_score,
            "confidence": round(self.confidence, 3),
            "risk_level": self.risk_level.value,
            "detected_signals": list(self.signal_names),
            "recommended_action": self.recommended_action.value,
            "reason": self.reason,
            "families_triggered": self.families_triggered,
            "cluster_id": self.cluster_id,
            "is_provisional": self.is_provisional,
            "blocked_by": self.blocked_by,
            "mode": self.mode.value,
            "timestamp": self.timestamp,
            "engine_version": self.engine_version,
            "config_version": self.config_version,
            "pattern_id": self.pattern_id,
            "evidence": [
                {"name": s.name, "family": s.family.value, "score": round(s.score, 1),
                 "evidence": s.evidence}
                for s in self.signals
            ],
        }
