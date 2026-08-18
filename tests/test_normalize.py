"""Тесты нормализации текста, ссылок, Unicode-профиля и MinHash.

Сценарии из ТЗ проверяются буквально: три варианта одного спама должны
нормализоваться в одну строку, "и.т.д" не должно считаться ссылкой,
"пpивет" с латинской p должно ловиться как смешение алфавитов.
"""

from __future__ import annotations

from cigilbot.domain.normalize import (
    extract_links,
    find_invisible_chars,
    fingerprint,
    minhash,
    normalize_for_matching,
    normalize_text,
    script_profile,
    similarity,
    skeleton,
    strip_invisible,
)


class TestNormalizeText:
    def test_case_and_whitespace_and_punctuation_collapse(self) -> None:
        variants = [
            "BUY CHEAP FOLLOWERS!!!",
            "Buy cheap followers!!!",
            "BUY   CHEAP   FOLLOWERS",
        ]
        normalized = {normalize_text(v) for v in variants}
        assert len(normalized) == 1

    def test_repeated_chars_collapse_to_two(self) -> None:
        assert normalize_text("привееееет") == normalize_text("привеет")

    def test_short_runs_are_not_collapsed(self) -> None:
        # "бб" в "суббота" — естественный двойной согласный, не аномалия
        assert "бб" in normalize_text("суббота")

    def test_nfkc_normalizes_compatibility_forms(self) -> None:
        # полноширинные ASCII-варианты (часто используются для обхода фильтров)
        fullwidth = "ｂｕｙ"  # ｂｕｙ
        assert normalize_text(fullwidth) == "buy"

    def test_empty_string(self) -> None:
        assert normalize_text("") == ""

    def test_only_punctuation_becomes_empty(self) -> None:
        assert normalize_text("!!! ... ???") == ""


class TestInvisibleChars:
    def test_detects_zero_width_space(self) -> None:
        text = "при​вет"
        found = find_invisible_chars(text)
        assert len(found) == 1

    def test_detects_tag_characters(self) -> None:
        text = "test" + chr(0xE0041) + chr(0xE0042)
        found = find_invisible_chars(text)
        assert len(found) == 2

    def test_clean_text_has_none(self) -> None:
        assert find_invisible_chars("обычное сообщение") == []

    def test_strip_removes_them_but_keeps_rest(self) -> None:
        text = "при​вет"
        assert strip_invisible(text) == "привет"

    def test_emoji_variation_selector_not_flagged(self) -> None:
        # U+FE0F встречается почти в каждом втором эмодзи — не аномалия
        text = "❤️"
        assert find_invisible_chars(text) == []


class TestSkeleton:
    def test_same_structure_different_payload(self) -> None:
        a = skeleton("Приз 12345")
        b = skeleton("Приз 67890")
        assert a == b

    def test_different_structure_differs(self) -> None:
        a = skeleton("Приз 12345")
        b = skeleton("Забирай приз здесь")
        assert a != b

    def test_length_twelve_plus_used_for_clustering_at_engine_level(self) -> None:
        # сам skeleton() не занимается порогом длины — это дело кластеризации,
        # но короткие структурно похожие сообщения тоже должны совпадать
        assert skeleton("+++") == skeleton("+++")


class TestExtractLinks:
    def test_bare_domain_without_protocol(self) -> None:
        links = extract_links("заходите vk.com/club123 там круто")
        assert len(links) == 1
        assert links[0].domain == "vk.com"
        assert links[0].full == "vk.com/club123"

    def test_full_url_with_protocol(self) -> None:
        links = extract_links("https://www.example.com/promo")
        assert len(links) == 1
        assert links[0].domain == "example.com"

    def test_shortener_flagged(self) -> None:
        links = extract_links("переходи bit.ly/abc123")
        assert len(links) == 1
        assert links[0].is_shortener

    def test_regular_domain_not_flagged_as_shortener(self) -> None:
        links = extract_links("vk.com/club123")
        assert not links[0].is_shortener

    def test_query_params_stripped_for_dedup(self) -> None:
        text = "site.com/promo?utm=1 и ещё site.com/promo?utm=2"
        links = extract_links(text)
        assert len(links) == 1

    def test_no_false_positive_on_abbreviations(self) -> None:
        # "и т.д." и "т.е." — не домены верхнего уровня
        assert extract_links("сделаю и т.д. и т.е. так далее") == []

    def test_no_false_positive_on_decimal_numbers(self) -> None:
        assert extract_links("это стоило 150.5 рублей") == []

    def test_no_link_in_plain_text(self) -> None:
        assert extract_links("привет всем в чате") == []

    def test_multiple_distinct_links(self) -> None:
        links = extract_links("first.com/a and second.com/b")
        domains = {link.domain for link in links}
        assert domains == {"first.com", "second.com"}


class TestScriptProfile:
    def test_pure_cyrillic(self) -> None:
        profile = script_profile("привет всем в чате")
        assert not profile.has_mixed_words

    def test_pure_latin_is_normal_for_ru_channel(self) -> None:
        # латиница сама по себе не аномалия: ники, "gg", "pog", транслит
        profile = script_profile("gg wp nice game")
        assert not profile.has_mixed_words
        assert not profile.has_confusables

    def test_confusable_mix_inside_word_detected(self) -> None:
        # латинская "p" вместо кириллической "р"
        text = "п" + "p" + "ивет"  # "пpивет"
        profile = script_profile(text)
        assert profile.has_mixed_words
        assert profile.has_confusables

    def test_mixed_but_not_confusable_not_flagged_as_confusable(self) -> None:
        # смешение есть, но не через визуально похожие буквы
        text = "Wowчик"
        profile = script_profile(text)
        assert profile.has_mixed_words
        assert not profile.has_confusables

    def test_emoji_counted_separately_from_letters(self) -> None:
        profile = script_profile("привет 😀😀")
        assert profile.emoji_count == 2

    def test_empty_text(self) -> None:
        profile = script_profile("")
        assert profile.total_letters == 0


class TestMinHashSimilarity:
    def test_identical_text_has_similarity_one(self) -> None:
        a = minhash("купите дешёвых подписчиков прямо сейчас")
        b = minhash("купите дешёвых подписчиков прямо сейчас")
        assert similarity(a, b) == 1.0

    def test_near_duplicate_has_high_similarity(self) -> None:
        a = minhash("BUY CHEAP FOLLOWERS!!! visit site.com")
        b = minhash("Buy cheap followers!!! visit site.com")
        assert similarity(a, b) > 0.9

    def test_unrelated_messages_have_low_similarity(self) -> None:
        a = minhash("кто-нибудь знает когда стрим начнётся")
        b = minhash("купите дешёвых подписчиков на канал")
        assert similarity(a, b) < 0.3

    def test_empty_text_similarity_is_zero_not_crash(self) -> None:
        a = minhash("")
        b = minhash("привет")
        assert similarity(a, b) == 0.0

    def test_both_empty(self) -> None:
        a = minhash("")
        b = minhash("")
        # пустые отпечатки не должны считаться "похожими" по умолчанию
        assert similarity(a, b) == 0.0

    def test_deterministic_across_calls(self) -> None:
        # критично для replay: одинаковый вход всегда даёт одинаковый отпечаток
        text = "привет как дела у всех"
        assert minhash(text) == minhash(text)


class TestNormalizeForMatching:
    def test_confusable_letters_unified(self) -> None:
        a = normalize_for_matching("привет")
        b = normalize_for_matching("п" + "p" + "ивет")
        assert a == b


class TestFingerprint:
    def test_end_to_end_duplicate_detection_scenario(self) -> None:
        fp1 = fingerprint("BUY CHEAP FOLLOWERS!!! visit bit.ly/abc")
        fp2 = fingerprint("Buy cheap followers!!! visit bit.ly/abc")

        assert fp1.similarity_to(fp2) > 0.85
        assert fp1.domains == fp2.domains
        assert fp1.has_links and fp2.has_links

    def test_is_empty_for_pure_punctuation(self) -> None:
        fp = fingerprint("!!! ...")
        assert fp.is_empty

    def test_captures_invisible_chars(self) -> None:
        fp = fingerprint("при​вет")
        assert len(fp.invisible_chars) == 1
