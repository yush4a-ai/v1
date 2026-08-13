"""Content Policy: ContentMatch -> рекомендованное действие с эскалацией.

Отдельный путь от cigilbot/policy.py (risk_score + confidence), а не ветка
внутри него — по двум причинам:

1. Словарное совпадение — бинарный факт (фраза найдена или нет), а не
   вероятностный признак вроде burst/duplicate. MIN_FAMILIES_FOR_BAN из
   policy.py требует 2+ независимых СЕМЕЙСТВА сигналов для BAN — это
   правило про накопление вероятностных улик про бота, а не про то, что
   один явный факт (пользователь написал угрозу) должен требовать
   подкрепления другим сигналом, чтобы на него отреагировать.
2. У разных категорий (racism/threats/advertising) разные лестницы
   эскалации, определяемые здесь через _ESCALATION, а не общими
   risk_thresholds — «реклама» и «угроза» не должны наказываться по одной
   шкале.

РЕЖИМ НАБЛЮДАТЕЛЯ (см. чат с пользователем от 2026-08-12): этот детектор
новый и непроверенный на реальном чате, в отличие от спам-движка. Пока
content_moderation_enabled=False (дефолт per-channel настройки, миграция
014), decide_content() всегда возвращает Action.OBSERVE независимо от
лестницы эскалации — совпадение по-прежнему считается и пишется в аудит
(mod_content_events), чтобы было видно, что бы сработало, до включения
реальных действий.

requires_manual_review на ContentDecision — задел на будущее, когда
content_moderation_enabled будет включён: RACISM/THREATS размечены как
требующие ручного подтверждения в панели (Review Queue), ADVERTISING — нет,
может ставиться в mod_action_queue напрямую. Сейчас это поле ни на что не
влияет — engine.py вообще не кладёт content-решения в mod_action_queue,
только пишет аудит; поле существует, чтобы эту развилку не пришлось
придумывать заново, когда автоматизация будет включаться.
"""

from __future__ import annotations

from dataclasses import dataclass

from cigilbot.domain.types import Action, ChatEvent, ContentCategory, ContentMatch, UserState

# Лестница эскалации по количеству ПРЕДЫДУЩИХ нарушений этой же категории
# (mod_content_violations.violation_count ДО текущего сообщения). Число в
# ключе — сколько нарушений уже было; действие — что делать при следующем.
# RACISM самый строгий (пользователь: "самый строгий") — сразу таймаут,
# бан со второго нарушения. THREATS так же строго, отдельной категорией —
# угроза насилия не мягче оскорбления по признаку. ADVERTISING мягче:
# спам-реклама раздражает, но не то же самое по тяжести, три нарушения до
# бана вместо одного.
_ESCALATION: dict[ContentCategory, dict[int, Action]] = {
    ContentCategory.RACISM: {0: Action.TIMEOUT, 1: Action.BAN},
    ContentCategory.THREATS: {0: Action.TIMEOUT, 1: Action.BAN},
    ContentCategory.ADVERTISING: {0: Action.TIMEOUT, 1: Action.TIMEOUT, 2: Action.BAN},
}

# Требует ли категория ручного подтверждения модератором, когда автодействия
# будут включены (см. докстринг модуля про requires_manual_review).
_REQUIRES_MANUAL_REVIEW: dict[ContentCategory, bool] = {
    ContentCategory.RACISM: True,
    ContentCategory.THREATS: True,
    ContentCategory.ADVERTISING: False,
}

# Длительность таймаута в секундах, растёт с числом нарушений — совпадает
# по духу с "прогрессивные таймауты" из мастер-плана (направление 03), но
# здесь только для content-нарушений, не общий механизм.
_TIMEOUT_DURATIONS: dict[int, int] = {0: 600, 1: 1800, 2: 3600}
_MAX_TIMEOUT_DURATION = 3600


@dataclass(frozen=True, slots=True)
class ContentDecision:
    action: Action
    category: ContentCategory
    matched_phrase: str
    prior_violations: int
    timeout_duration_seconds: int | None
    blocked_by: str
    requires_manual_review: bool


def _escalated_action(category: ContentCategory, prior_violations: int) -> Action:
    ladder = _ESCALATION[category]
    step = min(prior_violations, max(ladder))
    return ladder[step]


def decide_content(
    match: ContentMatch,
    *,
    user: UserState,
    event: ChatEvent,
    prior_violations: int,
    content_moderation_enabled: bool,
) -> ContentDecision:
    """Определить действие по словарному совпадению.

    Та же защита привилегированных/доверенных пользователей, что в
    cigilbot/policy.py — правило одно и то же независимо от того, какой
    путь его проверяет. См. докстринг модуля про режим наблюдателя.
    """
    action = _escalated_action(match.category, prior_violations)
    review = _REQUIRES_MANUAL_REVIEW[match.category]

    if event.is_privileged:
        return ContentDecision(
            action=Action.OBSERVE, category=match.category, matched_phrase=match.matched_phrase,
            prior_violations=prior_violations, timeout_duration_seconds=None,
            blocked_by="privileged_user", requires_manual_review=review,
        )
    if user.is_protected:
        return ContentDecision(
            action=Action.OBSERVE, category=match.category, matched_phrase=match.matched_phrase,
            prior_violations=prior_violations, timeout_duration_seconds=None,
            blocked_by="trusted_or_marked_safe", requires_manual_review=review,
        )
    if not content_moderation_enabled:
        return ContentDecision(
            action=Action.OBSERVE, category=match.category, matched_phrase=match.matched_phrase,
            prior_violations=prior_violations, timeout_duration_seconds=None,
            blocked_by="content_moderation_disabled", requires_manual_review=review,
        )

    duration = None
    if action == Action.TIMEOUT:
        step = min(prior_violations, max(_TIMEOUT_DURATIONS))
        duration = _TIMEOUT_DURATIONS.get(step, _MAX_TIMEOUT_DURATION)

    return ContentDecision(
        action=action, category=match.category, matched_phrase=match.matched_phrase,
        prior_violations=prior_violations, timeout_duration_seconds=duration, blocked_by="",
        requires_manual_review=review,
    )
