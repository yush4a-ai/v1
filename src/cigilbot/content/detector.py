"""Поиск словарных совпадений в сообщении.

Не Detector из cigilbot/detectors/base.py — тот протокол производит Signal
для risk_score/confidence, а словарное совпадение в них не участвует (см.
cigilbot/content/policy.py). check_content() — чистая функция, без I/O,
как и остальной пакет cigilbot.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from cigilbot.content.wordlist import normalize_for_content_match
from cigilbot.domain.types import ContentCategory, ContentMatch

# Однословные правила матчатся по корню с любым буквенным окончанием
# ("пидор" ловит "пидоры"/"пидору"/"пидорас"), многословные — точным
# совпадением подстроки, как раньше (пользователь 2026-08-13: "может ещё
# вариации того что уже есть?"). Разница обязательна: у фразы из нескольких
# слов нет одного "корня", по которому можно матчить любую словоформу.
#
# MIN_ROOT_LENGTH — защита от того, что короткий корень ловит случайные
# слова с тем же началом ("гей" в "гейшер" — обычное слово игрового чата,
# см. чат с пользователем). Правила короче порога остаются точным
# совпадением, а не корневым — иначе они были бы самыми опасными по ложным
# срабатываниям, будучи самыми короткими.
MIN_ROOT_LENGTH = 4


@dataclass(frozen=True, slots=True)
class ContentRule:
    """Одно правило словаря — строка из mod_content_rules."""

    id: int
    category: ContentCategory
    phrase: str
    enabled: bool


def _is_single_word(normalized_phrase: str) -> bool:
    return " " not in normalized_phrase


def _find_word_match(fragment: str, normalized_text: str, *, allow_suffix: bool) -> bool:
    """Есть ли в тексте слово, содержащее fragment на границе слова.

    allow_suffix=True (корневой матчинг, длина от MIN_ROOT_LENGTH) — после
    fragment разрешены ЛЮБЫЕ буквы до конца слова: "пидор" находит
    "пидоры"/"пидору"/"пидорас" (пользователь 2026-08-13: "может ещё
    вариации того что уже есть?"). allow_suffix=False (короткие однословные
    правила вроде "жид"/"хач", см. MIN_ROOT_LENGTH) — fragment должен быть
    словом целиком, без буквенного продолжения: "жид" находит "жид", не
    находит "жидкость". Оба случая используют одинаковый lookbehind —
    fragment не может начинаться посреди другого слова ("непидор" не
    считается, начало fragment обязано совпасть с началом слова).

    Леетспик-цифра после fragment не бывает продолжением того же слова:
    normalize_for_content_match уже превратил её в букву на этапе
    нормализации, так что после fragment остаются только настоящие буквы,
    не цифры/спецсимволы — граница строится по [^\\W\\d_], не по \\b."""
    suffix = r"[^\W\d_]*" if allow_suffix else ""
    pattern = re.compile(
        r"(?<![^\W\d_])" + re.escape(fragment) + suffix + r"(?![^\W\d_])", re.UNICODE
    )
    return pattern.search(normalized_text) is not None


def check_content(text: str, rules: tuple[ContentRule, ...]) -> ContentMatch | None:
    """Найти первое совпадение текста с включённым правилом словаря.

    Однословные правила матчатся на границе слова (см. _find_word_match) —
    от MIN_ROOT_LENGTH символов как корень с любым окончанием, короче —
    как слово целиком, без буквенного продолжения ("жид" не ловит
    "жидкость"). Многословные фразы остаются точным совпадением подстроки,
    как раньше — у фразы из нескольких слов нет одного "корня", по
    которому можно матчить любую словоформу, и границы слова у неё нет
    смысла проверять. Правила уже отсортированы по строгости категории
    вызывающим кодом (store.list_content_rules) — первое найденное
    совпадение и есть самое строгое релевантное.
    """
    normalized = normalize_for_content_match(text)
    if not normalized:
        return None

    for rule in rules:
        if not rule.enabled:
            continue
        normalized_phrase = normalize_for_content_match(rule.phrase)
        if not normalized_phrase:
            continue

        if _is_single_word(normalized_phrase):
            matched = _find_word_match(
                normalized_phrase, normalized,
                allow_suffix=len(normalized_phrase) >= MIN_ROOT_LENGTH,
            )
        else:
            matched = normalized_phrase in normalized

        if matched:
            return ContentMatch(
                category=rule.category,
                matched_phrase=rule.phrase,
                normalized_text=normalized,
            )

    return None
