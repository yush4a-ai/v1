"""Нормализация текста под словарное сравнение.

Отдельно от cigilbot/normalize.py::normalize_for_matching — та нормализация
искала ПОХОЖИЕ сообщения (MinHash, скелет) и сводит гомоглифы к латинице
(направление для дедупликации спама не важно, лишь бы одинаково). Здесь
нужно точное совпадение со словарной фразой, хранимой по-русски, поэтому
гомоглифы сводятся в обратную сторону — к кириллице. Плюс обход, которого
нет в normalize.py: посимвольные разделители ("н-е-г-р") и цифры-вместо-букв
("н3гр"), которыми чат ломает точное совпадение фразы.
"""

from __future__ import annotations

import re
import unicodedata

from cigilbot.domain.normalize import CONFUSABLE_PAIRS, strip_invisible

# Обратное к CONFUSABLE_PAIRS: латиница -> кириллица, для сравнения со
# словарной фразой, которая хранится по-русски (см. docstring модуля).
_LATIN_TO_CYRILLIC = {latin: cyr for cyr, latin in CONFUSABLE_PAIRS.items()}

# Цифры и типографские символы, которые чат подставляет вместо букв.
# Применяются только когда символ стоит РЯДОМ с буквой в том же слове
# (см. _WORD_WITH_LEET_RE) — самостоятельное число ("+100", "topic 1")
# остаётся числом, не превращается в буквы.
_LEETSPEAK_MAP = {
    "0": "о", "3": "е", "4": "ч", "6": "б", "1": "и", "@": "а", "$": "с",
}
_LEET_CHARS = "".join(_LEETSPEAK_MAP)

# Разделители, которыми обходят точное совпадение фразы. Два разных
# правила ниже: дефис/точка/подчёркивание/звёздочка/тильда внутри слова
# редки в обычной русской речи ("по-тихому" — исключение, не норма), поэтому
# для них снимается ограничение на длину частей — "пи-д-р" схлопывается
# так же, как "п-и-д-р". Пробел, наоборот, разделяет слова постоянно —
# снятие ограничения для него схлопнуло бы любое многословное предложение в
# одну строку без пробелов, поэтому пробел остаётся под старым правилом
# (см. _collapse_short_separators): только одиночные буквы, 3+ подряд.
_LOOSE_SEPARATORS = frozenset("-_.*~")
_TIGHT_SEPARATORS = frozenset(" ")
_SEPARATORS = _LOOSE_SEPARATORS | _TIGHT_SEPARATORS

# "Словоподобный" токен: содержит хотя бы одну обычную букву и, возможно,
# leet-символы вперемешку с ней — "н3гр", "нeгр", но не голое "100" или "1".
_WORD_WITH_LEET_RE = re.compile(
    r"(?:[^\W\d_]|[" + re.escape(_LEET_CHARS) + r"])*[^\W\d_](?:[^\W\d_]|["
    + re.escape(_LEET_CHARS) + r"])*",
    re.UNICODE,
)


def _collapse_loose_separators(text: str) -> str:
    """Убрать дефис/точку/подчёркивание/звёздочку/тильду между частями
    слова любой длины — "пи-д-р", "пи.д.р" и "п-и-д-р" все схлопываются в
    "пидр". Без ограничения на длину частей (в отличие от пробела, см.
    _collapse_short_separators): такие символы внутри слова редки в обычной
    русской речи, поэтому цена ложного схлопывания ниже, чем у пробела,
    который разделяет слова постоянно.
    """
    chunk = r"(?:[^\W\d_]|[" + re.escape(_LEET_CHARS) + r"])+"
    separator_class = "[" + re.escape("".join(_LOOSE_SEPARATORS)) + "]"
    pattern = re.compile(rf"(?:{chunk}{separator_class}){{1,}}{chunk}", re.UNICODE)

    def _strip(match: re.Match[str]) -> str:
        return "".join(ch for ch in match.group(0) if ch not in _LOOSE_SEPARATORS)

    return pattern.sub(_strip, text)


def _collapse_short_separators(text: str) -> str:
    """Убрать разделители (включая пробел), вставленные между КАЖДОЙ буквой
    слова, и только между одиночными буквами.

    "н-е-г-р" -> "негр": каждый промежуток между буквами — разделитель, и
    таких букв подряд минимум три, иначе обычное "по-русски" ложно
    схлопнулось бы в "порусски" от одной случайной пары. С пробелом это
    единственное правило (см. docstring _SEPARATORS про то, почему пробел
    не получает ослабленное правило _collapse_loose_separators). Буквы
    включают leet-цифры ("п-р-1-в-е-т" тоже должен схлопнуться) — граница
    совпадения проверяется тем же расширенным классом, иначе "1" обрывает
    цепочку раньше, чем она успевает схлопнуться.
    """
    letter = r"(?:[^\W\d_]|[" + re.escape(_LEET_CHARS) + r"])"
    separator_class = "[" + re.escape("".join(_SEPARATORS)) + "]"
    pattern = (
        f"(?<!{letter})(?:{letter}{separator_class}){{2,}}{letter}(?!{letter})"
    )
    token_re = re.compile(pattern, re.UNICODE)

    def _strip(match: re.Match[str]) -> str:
        return "".join(ch for ch in match.group(0) if ch not in _SEPARATORS)

    return token_re.sub(_strip, text)


def _normalize_word(word: str) -> str:
    """Гомоглифы -> кириллица, leetspeak-символы -> буквы, для одного
    словоподобного токена (содержащего хотя бы одну настоящую букву)."""
    out = []
    for ch in word:
        ch = _LATIN_TO_CYRILLIC.get(ch, ch)
        ch = _LEETSPEAK_MAP.get(ch, ch)
        out.append(ch)
    return "".join(out)


def normalize_for_content_match(text: str) -> str:
    """Привести текст к виду, сравнимому со словарной фразой.

    Пайплайн: снять невидимые символы -> убрать дефис/точку/подчёркивание
    между частями слова любой длины -> убрать пробел между ОДИНОЧНЫМИ
    буквами (см. docstring _collapse_short_separators про разницу с
    предыдущим шагом) -> unicode-нормализация и нижний регистр -> для
    каждого словоподобного токена (буквы вперемешку с leetspeak-цифрами, но
    не голые числа) свести гомоглифы к кириллице и заменить leetspeak-
    символы на буквы -> схлопнуть пробелы.
    """
    text = strip_invisible(text)
    text = _collapse_loose_separators(text)
    text = _collapse_short_separators(text)
    text = unicodedata.normalize("NFKC", text).casefold()
    text = _WORD_WITH_LEET_RE.sub(lambda m: _normalize_word(m.group(0)), text)

    return re.sub(r"\s+", " ", text).strip()
