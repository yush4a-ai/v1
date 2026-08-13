"""Policy Engine: risk_score + confidence + контекст -> recommended_action.

Ключевые инварианты безопасности (раздел 23 ТЗ) зашиты здесь константой, а
не читаются из конфига — их нельзя ослабить правкой YAML, включая режимы
AGGRESSIVE/ATTACK:

1. BAN невозможен при < 2 независимых семейств сигналов.
2. Ни TIMEOUT, ни BAN не назначаются без confidence не ниже
   соответствующего порога из конфига.
3. Привилегированные пользователи (модератор/VIP/стример канала) и те, кого
   модератор пометил доверенными/safe — не получают автоматическое действие
   выше OBSERVE никогда.
4. BAN невозможен для предварительного вердикта (is_provisional=True —
   возраст аккаунта ещё не получен от Helix, см. types.py::Verdict).
   FALSE-BAN-002 аудита: Verdict.is_provisional документировал этот
   инвариант ("массовые действия по предварительным вердиктам запрещены")
   с самого начала, но код его не проверял — сигналы, зависящие от
   возраста аккаунта, просто не срабатывали без данных, из-за чего
   инвариант держался случайно, а не по правилу. Здесь он закрыт явно.

Понижение действия всегда фиксируется в blocked_by — это то, что Verdict
показывает как "какая защита сработала" (см. types.py, раздел 11 ТЗ
"Explainable Moderation").
"""

from __future__ import annotations

from cigilbot.domain.config import ModerationConfig
from cigilbot.domain.types import Action, ChatEvent, Signal, UserState

# Не читается из конфига намеренно — см. докстринг модуля.
MIN_FAMILIES_FOR_BAN = 2


def _raw_action_for_risk(risk_score: int, config: ModerationConfig) -> Action:
    if risk_score >= config.risk.ban:
        return Action.BAN
    if risk_score >= config.risk.timeout:
        return Action.TIMEOUT
    if risk_score >= config.risk.observe:
        return Action.OBSERVE
    return Action.NOTHING


def decide(
    *,
    risk_score: int,
    confidence: float,
    families_triggered: int,
    config: ModerationConfig,
    user: UserState,
    event: ChatEvent,
    is_provisional: bool = False,
) -> tuple[Action, str]:
    """Определить действие и то, была ли применена защита от false positive.

    Возвращает (recommended_action, blocked_by). blocked_by — пустая
    строка, если действие не было понижено ни одной защитой.

    is_provisional=True — возраст аккаунта ещё не получен от Helix
    (Verdict.is_provisional). BAN на предварительном вердикте понижается до
    TIMEOUT: как только придёт account_created_at, engine.py пересчитает
    вердикт заново на следующем сообщении с уже полными данными — TIMEOUT
    достаточно "мягок", чтобы не быть проблемой, если пересчёт немного
    запоздает, в отличие от необратимого BAN на неполной информации.
    """
    action = _raw_action_for_risk(risk_score, config)
    if action == Action.NOTHING:
        return action, ""

    # Мод/VIP/стример — никогда не под автодействие, максимум наблюдение.
    if event.is_privileged:
        return Action.OBSERVE, "privileged_user"

    # Помечен модератором как safe, или уже достаточно доверен каналу.
    if user.is_protected:
        return Action.OBSERVE, "trusted_or_marked_safe"

    blocked_by = ""

    if action == Action.BAN and is_provisional:
        action = Action.TIMEOUT
        blocked_by = "provisional_verdict"

    if action == Action.BAN and families_triggered < MIN_FAMILIES_FOR_BAN:
        action = Action.TIMEOUT
        blocked_by = blocked_by or "minimum_families_for_ban"

    if action == Action.BAN and confidence < config.confidence.minimum_for_ban:
        action = Action.TIMEOUT
        blocked_by = blocked_by or "insufficient_confidence_for_ban"

    if action == Action.TIMEOUT and confidence < config.confidence.minimum_for_timeout:
        action = Action.OBSERVE
        blocked_by = blocked_by or "insufficient_confidence_for_timeout"

    return action, blocked_by


def build_reason(action: Action, signals: tuple[Signal, ...], blocked_by: str) -> str:
    """Короткое объяснение вердикта на человеческом языке.

    Подробности по каждому сигналу — в Verdict.explain(), это поле только
    для одной строки "почему в целом".
    """
    # Причины, завязанные на статус пользователя, не зависят от того, есть
    # ли сигналы вообще — проверяем их первыми, иначе пустой signals ложно
    # даёт "ничего не найдено" вместо настоящей причины понижения действия.
    if blocked_by == "privileged_user":
        return "Пользователь — модератор/VIP/стример канала, автодействие не применяется"
    if blocked_by == "trusted_or_marked_safe":
        return "Пользователь отмечен как доверенный, автодействие не применяется"

    if action == Action.NOTHING or not signals:
        return "Подозрительных признаков не обнаружено"

    top = max(signals, key=lambda s: s.score)
    families = sorted({s.family.value for s in signals})

    if blocked_by == "provisional_verdict":
        return (
            f"BAN понижен до TIMEOUT: возраст аккаунта ещё не получен от Helix; "
            f"главный сигнал: {top.name}"
        )
    if blocked_by:
        return (
            f"Действие понижено защитой от ложных срабатываний ({blocked_by}); "
            f"главный сигнал: {top.name}"
        )
    if len(families) >= 2:
        return f"Независимые признаки координированного поведения: {', '.join(families)}"
    return f"Обнаружен сигнал: {top.name}"
