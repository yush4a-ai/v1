"""Bot Pattern Library (этап 9b).

Не новый детектор — надстройка ПОСЛЕ scoring/confidence/policy, которая
даёт модератору название причины вместо голого списка сигналов. Правило
сопоставления — намеренно простой набор порогов (набор обязательных
сигналов, минимум семейств, минимум risk/confidence/size), а не
произвольный DSL: сложные условные выражения в JSON сложно и валидировать,
и тестировать, и объяснить модератору, который их редактирует через
панель. Если найденных полей когда-нибудь не хватит для реального
сценария — это будет конкретный, проверяемый повод расширить Pattern, а
не гипотетическая гибкость впрок.

Паттерн срабатывает на Verdict ИЛИ ClusterInfo — у обоих есть signals/
risk_score/confidence, но только у ClusterInfo есть size (число участников),
поэтому Pattern.min_cluster_size игнорируется при сопоставлении с Verdict.
"""

from __future__ import annotations

from dataclasses import dataclass

from cigilbot.domain.types import ClusterInfo, Verdict


@dataclass(frozen=True, slots=True)
class Pattern:
    """Именованный шаблон атаки — условия сопоставляются с уже посчитанным
    Verdict/ClusterInfo, само определение сигналов/весов остаётся в
    config.py, паттерн их не пересчитывает, только классифицирует."""

    id: int
    name: str
    description: str
    # Хотя бы один сигнал из списка должен присутствовать (если список
    # пуст — условие пропускается, паттерн не завязан на конкретные сигналы).
    required_signal_names: tuple[str, ...]
    min_families: int
    min_risk_score: int
    min_confidence: float
    # Игнорируется для Verdict (у пользователя нет "размера") — имеет
    # смысл только при сопоставлении с ClusterInfo.
    min_cluster_size: int
    enabled: bool
    auto_enabled: bool
    weight: float
    created_by: str
    created_at: float

    def matches(self, target: Verdict | ClusterInfo) -> bool:
        if not self.enabled:
            return False
        if target.risk_score < self.min_risk_score:
            return False
        if target.confidence < self.min_confidence:
            return False

        if self.required_signal_names:
            names = {s.name for s in target.signals}
            if not names & set(self.required_signal_names):
                return False

        families = len({s.family for s in target.signals})
        if families < self.min_families:
            return False

        return not (
            self.min_cluster_size > 0
            and isinstance(target, ClusterInfo)
            and target.size < self.min_cluster_size
        )


def match_patterns(target: Verdict | ClusterInfo, patterns: list[Pattern]) -> Pattern | None:
    """Первый подходящий включённый паттерн, отсортированный по weight
    (сильнее сформулированные условия должны иметь приоритет над общими) —
    не "все совпадения", т.к. panel показывает ОДНО название причины на
    карточке, а не список. Порядок — забота вызывающего кода/конфига через
    weight, а не порядок вставки в БД."""
    candidates = sorted(
        (p for p in patterns if p.matches(target)), key=lambda p: p.weight, reverse=True
    )
    return candidates[0] if candidates else None
