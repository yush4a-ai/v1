"""Тесты cigilbot/content/detector.py: поиск словарных совпадений."""

from __future__ import annotations

from cigilbot.content.detector import ContentRule, check_content
from cigilbot.domain.types import ContentCategory


def make_rule(**overrides: object) -> ContentRule:
    defaults: dict[str, object] = {
        "id": 1, "category": ContentCategory.RACISM, "phrase": "запрещённое слово",
        "enabled": True,
    }
    defaults.update(overrides)
    return ContentRule(**defaults)  # type: ignore[arg-type]


class TestCheckContent:
    def test_no_rules_no_match(self) -> None:
        assert check_content("любой текст", ()) is None

    def test_exact_match(self) -> None:
        rule = make_rule(phrase="плохое слово")
        match = check_content("тут есть плохое слово в чате", (rule,))
        assert match is not None
        assert match.category == ContentCategory.RACISM
        assert match.matched_phrase == "плохое слово"

    def test_no_match_when_phrase_absent(self) -> None:
        rule = make_rule(phrase="плохое слово")
        assert check_content("обычное безобидное сообщение", (rule,)) is None

    def test_disabled_rule_not_matched(self) -> None:
        rule = make_rule(phrase="плохое слово", enabled=False)
        assert check_content("тут есть плохое слово", (rule,)) is None

    def test_obfuscated_match(self) -> None:
        rule = make_rule(phrase="негр")
        match = check_content("ты н-е-г-р", (rule,))
        assert match is not None
        assert match.matched_phrase == "негр"

    def test_first_matching_rule_wins(self) -> None:
        # Правила приходят уже отсортированными по строгости (store.py) —
        # detector.py доверяет порядку, не пересортировывает сам.
        strict = make_rule(id=1, category=ContentCategory.RACISM, phrase="слово")
        loose = make_rule(id=2, category=ContentCategory.ADVERTISING, phrase="слово")
        match = check_content("тут слово есть", (strict, loose))
        assert match is not None
        assert match.category == ContentCategory.RACISM

    def test_empty_text(self) -> None:
        rule = make_rule(phrase="слово")
        assert check_content("", (rule,)) is None

    def test_empty_phrase_never_matches(self) -> None:
        rule = make_rule(phrase="   ")
        assert check_content("любой текст", (rule,)) is None


class TestRootMatching:
    """Однословные правила от MIN_ROOT_LENGTH символов ловят словоформы
    (пользователь 2026-08-13: "может ещё вариации того что уже есть?")."""

    def test_catches_plural_form(self) -> None:
        rule = make_rule(phrase="пидор")
        match = check_content("пидоры все дураки", (rule,))
        assert match is not None

    def test_catches_dative_form(self) -> None:
        rule = make_rule(phrase="пидор")
        assert check_content("он пидору сказал", (rule,)) is not None

    def test_catches_derived_word(self) -> None:
        rule = make_rule(phrase="негр")
        assert check_content("это негритос", (rule,)) is not None

    def test_does_not_require_word_start_of_message(self) -> None:
        rule = make_rule(phrase="даун")
        assert check_content("он даунич полный", (rule,)) is not None

    def test_matches_root_inside_longer_word(self) -> None:
        # Защита от начала слова у корня отсутствует намеренно (только
        # конец) — "пидорожник" содержит корень "пидор" в начале своего
        # слова, значит матчится, даже если это не то слово, что имелось
        # в виду автором фразы. Компромисс, принятый явно вместе с
        # пользователем: цена узкой защиты (пропустить реальные словоформы)
        # выше цены редкого совпадения с посторонним словом.
        rule = make_rule(phrase="пидор")
        assert check_content("пидорожник растение", (rule,)) is not None

    def test_short_root_does_not_expand_by_design(self) -> None:
        # "гей" короче MIN_ROOT_LENGTH — остаётся словом целиком, не
        # корнем: "гейзер"/"гейминг" не должны попадать под фильтр на
        # обычном игровом чате.
        rule = make_rule(phrase="гей")
        assert check_content("обычное слово гейзер", (rule,)) is None
        assert check_content("гейминг стрим сегодня", (rule,)) is None

    def test_short_word_matches_word_boundary(self) -> None:
        rule = make_rule(phrase="жид")
        assert check_content("он жид", (rule,)) is not None

    def test_short_word_does_not_match_inside_longer_word(self) -> None:
        rule = make_rule(phrase="жид")
        assert check_content("жидкость льется", (rule,)) is None

    def test_short_word_does_not_match_other_word_start(self) -> None:
        rule = make_rule(phrase="хач")
        assert check_content("хачапури вкусное", (rule,)) is None

    def test_multi_word_phrase_keeps_substring_matching(self) -> None:
        # Многословные фразы не получают ни корневой матчинг, ни границу
        # слова — у фразы из нескольких слов нет одного "корня".
        rule = make_rule(phrase="убью тебя")
        assert check_content("я убью тебя сегодня", (rule,)) is not None
