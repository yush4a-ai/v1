"""Определение языка — самый слабый сигнал в системе (вес 5 из конфига).

ВАЖНО: язык сам по себе никогда не основание для действия. Один этот
сигнал не дотягивает даже до уровня OBSERVE (порог 30 при максимум 5
баллах). Он способен что-то изменить только внутри кластера, где рядом
сработали ещё 5-6 независимых сигналов из других семейств.

Почему не langdetect: он ошибается на коротких сообщениях чата (2-5 слов)
в 30-50% случаев и систематически путает славянские языки между собой
(ru/uk, pl/cs/sk). lingua на коротких текстах надёжнее, а обязательный
порог уверенности (min_confidence) отсекает случаи, где алгоритм сам не
уверен — сленг вроде "gg wp" не должен становиться "польским сообщением"
только потому, что формально ближе всего лёг на польскую модель.

Детектор ограничен небольшим набором языков (expected + suspicious из
профиля канала), а не всеми ~75 языками lingua: чем меньше кандидатов,
тем точнее классификация на коротких текстах, и незачем тратить память на
модели языков, которых на канале никогда не бывает.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from lingua import Language, LanguageDetector, LanguageDetectorBuilder

from cigilbot.detectors.base import DetectionContext
from cigilbot.domain.types import Signal, SignalFamily

name = "language"

# lingua лениво подгружает модель языка при первом использовании — не всё
# сразу, поэтому не критично держать здесь чуть больше языков, чем нужно
# одному каналу, если детектор используется несколькими профилями сразу.
_ISO_TO_LANGUAGE: dict[str, Language] = {
    lang.iso_code_639_1.name.lower(): lang for lang in Language.all()
}


@lru_cache(maxsize=8)
def _detector_for(languages: tuple[str, ...]) -> LanguageDetector:
    """Кэш детекторов по набору языков — построение модели не бесплатно,
    а набор языков (expected+suspicious профиля канала) почти не меняется
    между вызовами."""
    known = [_ISO_TO_LANGUAGE[code] for code in languages if code in _ISO_TO_LANGUAGE]
    if len(known) < 2:
        # lingua требует минимум 2 языка для сравнения; меньше — не с чем
        # сравнивать, детектор в detect() просто вернёт пустой список сигналов
        known = [Language.RUSSIAN, Language.ENGLISH]
    return LanguageDetectorBuilder.from_languages(*known).build()


@dataclass(frozen=True, slots=True)
class LanguageResult:
    iso_code: str
    confidence: float


def detect_language(text: str, candidate_languages: tuple[str, ...]) -> LanguageResult | None:
    detector = _detector_for(candidate_languages)
    values = detector.compute_language_confidence_values(text)
    if not values:
        return None
    top = values[0]
    return LanguageResult(iso_code=top.language.iso_code_639_1.name.lower(), confidence=top.value)


def detect(ctx: DetectionContext) -> list[Signal]:
    cfg = ctx.config.detectors.language
    if not cfg.enabled or ctx.fingerprint.is_empty:
        return []

    profile = ctx.channel_profile
    candidates = tuple(dict.fromkeys(profile.expected_languages + profile.suspicious_languages))
    if len(candidates) < 2:
        return []

    result = detect_language(ctx.fingerprint.normalized, candidates)
    if result is None or result.confidence < cfg.min_confidence:
        return []

    if result.iso_code in profile.expected_languages:
        return []

    return [
        Signal(
            name="unexpected_language",
            family=SignalFamily.ENCODING,
            weight=ctx.config.weight("unexpected_language").weight,
            value=result.confidence,
            evidence=(
                f"язык сообщения — {result.iso_code} "
                f"(уверенность {result.confidence:.0%}), не входит в ожидаемые "
                f"для канала ({', '.join(profile.expected_languages)})"
            ),
        )
    ]
