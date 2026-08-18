"""Нормализация сообщений и извлечение технических признаков.

Модуль отвечает на вопрос «одно и то же написали эти двое или нет» и на
вопрос «как именно записан текст». Всё детерминировано и без ввода-вывода:
одинаковый вход даёт одинаковый выход в любом запуске — иначе невозможны
ни тесты, ни повторный прогон истории чата.

Отдельно про хеширование: встроенный hash() для строк рандомизирован
(PYTHONHASHSEED), поэтому MinHash считается на blake2b. Иначе кластеры
после перезапуска бота получались бы другими.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Невидимые и служебные символы
# ---------------------------------------------------------------------------

# Символы, которых в осмысленном сообщении быть не должно. Ими прячут
# отличия между копиями одного и того же спама, чтобы обойти фильтр дублей.
# U+FE0F (emoji variation selector) намеренно НЕ включён: он есть в каждом
# втором эмодзи и означал бы, что подозрителен любой живой чат.
INVISIBLE_CHARS = frozenset(
    "​‌‍⁠﻿"  # zero-width space/non-joiner/joiner/word-joiner/BOM
    "‪‫‬‭‮"  # изменение направления письма
    "⁦⁧⁨⁩"        # изоляты направления
    "᠎­"                    # монгольский разделитель, мягкий перенос
)

# Диапазон tag-символов U+E0000..U+E007F — невидимые копии ASCII.
_TAG_CHARS_START = 0xE0000
_TAG_CHARS_END = 0xE007F

# Пары букв, которые выглядят одинаково в кириллице и латинице. Смешение
# именно этих букв внутри слова — почти наверняка попытка обхода фильтра,
# а не случайная раскладка.
CONFUSABLE_PAIRS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "к": "k", "м": "m", "н": "h", "т": "t", "в": "b", "і": "i", "ѕ": "s",
    "ј": "j", "һ": "h", "ԁ": "d", "ԛ": "q", "ԝ": "w",
}

_URL_RE = re.compile(
    r"(?:(?:https?://)|(?:www\.)|(?<![\w@.]))"
    r"([a-zA-Zа-яА-Я0-9](?:[a-zA-Zа-яА-Я0-9-]{0,61}[a-zA-Zа-яА-Я0-9])?"
    r"(?:\.[a-zA-Zа-яА-Я0-9](?:[a-zA-Zа-яА-Я0-9-]{0,61}[a-zA-Zа-яА-Я0-9])?)+)"
    r"(/[^\s]*)?",
    re.IGNORECASE,
)

# Домены верхнего уровня, которые реально встречаются. Без этого списка
# «спасибо.всем» или «т.е» превращались бы в ссылки.
_KNOWN_TLDS = frozenset(
    "com net org io gg tv me ru рф ua by kz co uk de pl cz sk fr it es nl se no fi "
    "info biz online site shop store xyz top club live link click app dev cloud "
    "gift ly to cc vc am fm us ws pro art fun space website tech su".split()
)

# Сокращатели ссылок: сам факт их использования в чате — слабый сигнал,
# потому что настоящий адрес за ними не виден.
URL_SHORTENERS = frozenset(
    "bit.ly tinyurl.com goo.gl t.co ow.ly is.gd buff.ly clck.ru vk.cc cutt.ly "
    "rb.gy shorturl.at rebrand.ly bit.do t.ly u.to clc.to qps.ru".split()
)

_WORD_RE = re.compile(r"[^\W\d_]+", re.UNICODE)
_REPEAT_RE = re.compile(r"(.)\1{2,}", re.UNICODE)
_SPACE_RE = re.compile(r"\s+", re.UNICODE)
_PUNCT_TRANSLATE = {ord(c): " " for c in "!?.,;:()[]{}\"'«»„“”—–-_*~`|/\\"}

# Частицы, местоимения, предлоги, союзы — не несут содержательного смысла
# сами по себе, исключены, чтобы не давать ложных совпадений между любыми
# двумя сообщениями чата. Список короткий и русско-английский намеренно:
# это не полноценный стоп-лист NLP-библиотеки, а минимальный фильтр для
# самых частых служебных слов твич-чата. Живёт здесь, а не в
# detectors/keyword_overlap.py, потому что significant_words теперь
# считается один раз в fingerprint() и нужен ещё clustering.py — оба
# domain-модуля, а detectors/ им становиться зависимостью не должен.
_STOPWORDS = frozenset(
    """
    и а но или да нет не ни же ли бы то это тот та те эти
    я ты он она оно мы вы они мне тебе ему ей нам вам им меня тебя его её нас вас их
    у в на с со из от до по за над под при без для про через
    что как когда где куда откуда почему зачем
    the a an is are was were be to of in on at for and or but not
    """.split()
)


# ---------------------------------------------------------------------------
# Скрипты Unicode
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class ScriptProfile:
    """Из каких алфавитов состоит сообщение.

    Для русского канала латиница — норма (ники, «gg», «pog», транслит),
    поэтому сама по себе она ничего не значит и веса не имеет. Значение
    имеет смешение алфавитов ВНУТРИ слова.
    """

    cyrillic: float
    latin: float
    other: float
    emoji_count: int
    total_letters: int
    mixed_words: tuple[str, ...]
    confusable_words: tuple[str, ...]

    @property
    def has_mixed_words(self) -> bool:
        return bool(self.mixed_words)

    @property
    def has_confusables(self) -> bool:
        """Смешение похожих букв — сильный технический признак подмены."""
        return bool(self.confusable_words)


def _char_script(ch: str) -> str:
    """К какому алфавиту относится буква. Только для букв."""
    code = ord(ch)
    if 0x0400 <= code <= 0x04FF or 0x0500 <= code <= 0x052F:
        return "cyrillic"
    if (0x0041 <= code <= 0x005A) or (0x0061 <= code <= 0x007A) or (0x00C0 <= code <= 0x024F):
        return "latin"
    return "other"


def _is_emoji(ch: str) -> bool:
    code = ord(ch)
    return (
        0x1F300 <= code <= 0x1FAFF
        or 0x2600 <= code <= 0x27BF
        or 0x1F000 <= code <= 0x1F2FF
        or code in (0x2764, 0x2665, 0x2660, 0x2663)
    )


def script_profile(text: str) -> ScriptProfile:
    """Разложить сообщение по алфавитам и найти смешанные слова."""
    counts = {"cyrillic": 0, "latin": 0, "other": 0}
    emoji = 0

    for ch in text:
        if _is_emoji(ch):
            emoji += 1
        elif ch.isalpha():
            counts[_char_script(ch)] += 1

    total = sum(counts.values())
    mixed: list[str] = []
    confusable: list[str] = []

    for word in _WORD_RE.findall(text):
        if len(word) < 2:
            continue
        letters = [c for c in word if c.isalpha()]
        scripts = {_char_script(c) for c in letters}
        if len(scripts) <= 1:
            continue
        mixed.append(word)

        # Подмена — это когда БОЛЬШИНСТВО букв слова из одного алфавита, а
        # меньшинство — гомоглифы, взятые из другого специально, чтобы
        # обойти точное сравнение строк. Наличие "w" где-то в слове само по
        # себе ничего не значит: "w" — цель подмены для редкой кириллической
        # "ԝ", и просто нашёлся бы в любом слове с латинской w ("Wowчик").
        # При равном соотношении алфавитов большинство не определить — не
        # флагуем, чтобы не плодить ложные срабатывания на пограничных словах.
        lowered_letters = [c.lower() for c in letters]
        cyr_count = sum(1 for c in lowered_letters if _char_script(c) == "cyrillic")
        lat_count = sum(1 for c in lowered_letters if _char_script(c) == "latin")
        if cyr_count == 0 or lat_count == 0 or cyr_count == lat_count:
            continue

        majority = "cyrillic" if cyr_count > lat_count else "latin"
        minority_letters = (c for c in lowered_letters if _char_script(c) != majority)
        is_homoglyph = any(
            (c in CONFUSABLE_PAIRS.values()) if majority == "cyrillic" else (c in CONFUSABLE_PAIRS)
            for c in minority_letters
        )
        if is_homoglyph:
            confusable.append(word)

    return ScriptProfile(
        cyrillic=counts["cyrillic"] / total if total else 0.0,
        latin=counts["latin"] / total if total else 0.0,
        other=counts["other"] / total if total else 0.0,
        emoji_count=emoji,
        total_letters=total,
        mixed_words=tuple(mixed),
        confusable_words=tuple(confusable),
    )


def find_invisible_chars(text: str) -> list[str]:
    """Невидимые символы в тексте. Возвращает их коды для объяснения."""
    found = []
    for ch in text:
        code = ord(ch)
        if ch in INVISIBLE_CHARS or _TAG_CHARS_START <= code <= _TAG_CHARS_END:
            found.append(f"U+{code:04X}")
    return found


def count_combining_marks(text: str) -> int:
    """Комбинирующие знаки. Их избыток — «залго»-текст, забивающий чат."""
    return sum(1 for ch in text if unicodedata.combining(ch))


# ---------------------------------------------------------------------------
# Нормализация текста
# ---------------------------------------------------------------------------

def strip_invisible(text: str) -> str:
    return "".join(
        ch for ch in text
        if ch not in INVISIBLE_CHARS and not (_TAG_CHARS_START <= ord(ch) <= _TAG_CHARS_END)
    )


def normalize_text(text: str) -> str:
    """Привести сообщение к виду, в котором его можно сравнивать с другими.

    Требование из ТЗ: три варианта одного спама должны стать одной строкой.

        BUY CHEAP FOLLOWERS!!!  →  buy cheap followers
        Buy cheap followers!!!  →  buy cheap followers
        BUY   CHEAP   FOLLOWERS →  buy cheap followers

    Повторы символов схлопываются до двух, а не до одного: «аа» и «а» —
    разные вещи, а «аааааа» и «ааааааааа» — одна и та же.
    """
    text = strip_invisible(text)
    text = unicodedata.normalize("NFKC", text)
    text = text.casefold()
    text = text.translate(_PUNCT_TRANSLATE)
    text = _REPEAT_RE.sub(r"\1\1", text)
    return _SPACE_RE.sub(" ", text).strip()


def unify_confusables(text: str) -> str:
    """Свести визуально одинаковые буквы к одной форме.

    Нужно, чтобы «пpивет» с латинской p и обычный «привет» считались одним
    сообщением при поиске дублей. На риск это само по себе не влияет —
    факт подмены фиксирует отдельный сигнал.
    """
    return "".join(CONFUSABLE_PAIRS.get(ch, ch) for ch in text)


def normalize_for_matching(text: str) -> str:
    """Максимально агрессивная нормализация — только для поиска дублей."""
    return unify_confusables(normalize_text(text))


def _significant_words_from_normalized(normalized: str) -> frozenset[str]:
    return frozenset(w for w in normalized.split() if len(w) >= 2 and w not in _STOPWORDS)


def significant_words(text: str) -> frozenset[str]:
    """Слова сообщения за вычетом стоп-слов — для сравнения по пересечению.

    >= 2, не >= 3 — короче отсекало бы твич-сленг вроде "го" (зов
    присоединиться), который как раз оказался главным связующим словом
    в реальной self-promo кампании при калибровке (проверено прогоном:
    12 фраз-перефразировок, "го" встречалось в 10 из 12, при пороге >=3
    детектор пропускал сообщение целиком чаще, чем находил совпадение).
    """
    return _significant_words_from_normalized(normalize_text(text))


def _skeleton_from_normalized(normalized: str) -> str:
    out = []
    for ch in normalized:
        if ch.isspace():
            out.append(" ")
        elif ch.isdigit():
            out.append("9")
        elif _is_emoji(ch):
            out.append("e")
        elif ch.isalpha():
            out.append("a")
        else:
            out.append(ch)
    return "".join(out)


def skeleton(text: str) -> str:
    """Структурный шаблон сообщения.

    Ловит спам, в котором меняется только «начинка»: «Приз 12345» и
    «Приз 67890» дают одинаковый скелет aaaa 99999, хотя как строки различны.
    """
    return _skeleton_from_normalized(normalize_text(text))


# ---------------------------------------------------------------------------
# Ссылки
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class LinkInfo:
    domain: str      # нормализованный домен, без www и протокола
    full: str        # домен + путь, для точного сравнения
    is_shortener: bool


def extract_links(text: str) -> list[LinkInfo]:
    """Найти ссылки, в том числе записанные без протокола.

    Боты редко пишут полный https:// — чаще «bit.ly/xxx» или «site.com/promo»,
    поэтому опираться на наличие схемы нельзя. Защита от ложных срабатываний
    на «и.т.д» — проверка домена верхнего уровня по списку.
    """
    links: list[LinkInfo] = []
    seen: set[str] = set()

    for match in _URL_RE.finditer(strip_invisible(text)):
        host = match.group(1).lower().removeprefix("www.")
        tld = host.rsplit(".", 1)[-1] if "." in host else ""
        if tld not in _KNOWN_TLDS:
            continue

        path = (match.group(2) or "").rstrip("/")
        # Отсекаем query и метки кампаний: боты рассылают одну ссылку с
        # разными utm-хвостами, чтобы она выглядела как разные ссылки.
        path = path.split("?", 1)[0].split("#", 1)[0]

        full = f"{host}{path}"
        if full in seen:
            continue
        seen.add(full)
        links.append(LinkInfo(domain=host, full=full, is_shortener=host in URL_SHORTENERS))

    return links


# ---------------------------------------------------------------------------
# MinHash — оценка похожести двух сообщений
# ---------------------------------------------------------------------------

MINHASH_PERMUTATIONS = 32
_SHINGLE_SIZE = 3
_MAX_HASH_CHARS = 240  # длиннее — не имеет смысла, лимит сообщения Twitch 500
_MERSENNE = (1 << 61) - 1

# Коэффициенты хеш-функций. Зафиксированы константой, а не random: иначе
# отпечатки менялись бы между запусками и история была бы несравнима.
_COEFFS: tuple[tuple[int, int], ...] = tuple(
    (
        int.from_bytes(hashlib.blake2b(f"a{i}".encode(), digest_size=8).digest(), "big")
        % (_MERSENNE - 1) + 1,
        int.from_bytes(hashlib.blake2b(f"b{i}".encode(), digest_size=8).digest(), "big")
        % _MERSENNE,
    )
    for i in range(MINHASH_PERMUTATIONS)
)


def _shingles(text: str) -> set[str]:
    """Символьные триграммы. По символам, а не по словам — так похожесть
    сохраняется при опечатках и вставленных символах, которыми боты
    маскируют одинаковые сообщения."""
    text = text[:_MAX_HASH_CHARS]
    if len(text) < _SHINGLE_SIZE:
        return {text} if text else set()
    return {text[i:i + _SHINGLE_SIZE] for i in range(len(text) - _SHINGLE_SIZE + 1)}


def _minhash_from_matching(matching: str) -> tuple[int, ...]:
    shingles = _shingles(matching)
    if not shingles:
        return tuple([0] * MINHASH_PERMUTATIONS)

    bases = [
        int.from_bytes(hashlib.blake2b(s.encode("utf-8"), digest_size=8).digest(), "big")
        for s in shingles
    ]
    return tuple(
        min((a * base + b) % _MERSENNE for base in bases) for a, b in _COEFFS
    )


def minhash(text: str) -> tuple[int, ...]:
    """Отпечаток сообщения фиксированной длины.

    Доля совпавших позиций у двух отпечатков — оценка коэффициента Жаккара
    исходных текстов. Считается один раз на сообщение, сравнение потом
    стоит 32 сравнения целых чисел вместо посимвольного разбора.
    """
    return _minhash_from_matching(normalize_for_matching(text))


def similarity(a: tuple[int, ...], b: tuple[int, ...]) -> float:
    """Оценка похожести двух сообщений по их отпечаткам, [0, 1].

    minhash("") возвращает вектор из нулей — это placeholder «нет данных»,
    а не осмысленный отпечаток. Без явной проверки два сообщения из одних
    только знаков препинания ("...", "!!!") давали бы похожесть 1.0 и
    ложно склеивались бы в один кластер при массовом хайпе.
    """
    if not a or not b or len(a) != len(b):
        return 0.0
    if all(x == 0 for x in a) or all(x == 0 for x in b):
        return 0.0
    return sum(1 for x, y in zip(a, b, strict=True) if x == y) / len(a)


@dataclass(frozen=True, slots=True)
class MessageFingerprint:
    """Всё, что нужно знать о сообщении для сравнения с другими.

    Считается один раз при получении сообщения и дальше переиспользуется
    всеми детекторами — повторно разбирать текст никто не должен.
    """

    original: str
    normalized: str
    matching: str
    skeleton: str
    minhash: tuple[int, ...]
    links: tuple[LinkInfo, ...]
    scripts: ScriptProfile
    invisible_chars: tuple[str, ...]
    combining_marks: int
    significant_words: frozenset[str]

    @property
    def domains(self) -> tuple[str, ...]:
        return tuple(sorted({link.domain for link in self.links}))

    @property
    def has_links(self) -> bool:
        return bool(self.links)

    @property
    def is_empty(self) -> bool:
        return not self.normalized

    def similarity_to(self, other: MessageFingerprint) -> float:
        return similarity(self.minhash, other.minhash)


def fingerprint(text: str) -> MessageFingerprint:
    """Разобрать сообщение один раз и сохранить всё нужное.

    normalize_text(text) считается здесь РОВНО ОДИН раз (bug-аудит
    2026-08-15, HIGH #18) — раньше skeleton()/minhash()/significant_words()
    вызывались с сырым text и каждая заново прогоняла свою копию
    normalize_text изнутри, то есть на одно сообщение normalize_text
    отрабатывал четыре раза подряд. matching уже был единственным полем,
    переиспользующим normalized (unify_confusables ниже) — остальные три
    теперь делают то же самое через приватные _..._from_normalized/
    _minhash_from_matching, публичные skeleton()/minhash()/
    significant_words() при этом не изменились: они по-прежнему принимают
    сырой текст для вызывающих без готового MessageFingerprint (store.py
    ищет паттерны по сохранённому тексту, autoclip.py сверяет фразы)."""
    normalized = normalize_text(text)
    matching = unify_confusables(normalized)
    return MessageFingerprint(
        original=text,
        normalized=normalized,
        matching=matching,
        skeleton=_skeleton_from_normalized(normalized),
        minhash=_minhash_from_matching(matching),
        links=tuple(extract_links(text)),
        scripts=script_profile(text),
        invisible_chars=tuple(find_invisible_chars(text)),
        combining_marks=count_combining_marks(text),
        significant_words=_significant_words_from_normalized(normalized),
    )
