"""Тесты загрузчика конфигурации: дефолты, парсинг YAML, защита от опечаток."""

from __future__ import annotations

from pathlib import Path

import pytest

from cigilbot.domain.config import (
    ConfigError,
    default_config,
    load_channel_profile,
    load_config,
)
from cigilbot.domain.types import Sensitivity, SignalFamily


class TestDefaultConfig:
    def test_loads_without_filesystem(self) -> None:
        cfg = default_config()
        assert cfg.sensitivity == Sensitivity.BALANCED

    def test_has_weight_for_every_detector_signal(self) -> None:
        # каждый сигнал, который реально выдают детекторы, должен иметь вес —
        # иначе scoring.py упадёт в проде на KeyError
        cfg = default_config()
        expected = {
            "user_message_burst", "channel_message_burst", "exact_duplicate",
            "near_duplicate", "skeleton_match", "link_present",
            "shared_link_multi_user", "url_shortener", "known_scam_domain",
            "invisible_chars", "homoglyph_mix", "script_mix_in_word",
            "unexpected_language", "new_account", "first_message", "no_history",
            "generated_username_pattern", "emote_spam", "zalgo_text_spam",
        }
        for name in expected:
            assert cfg.weight(name).name == name

    def test_language_weight_is_lowest(self) -> None:
        # инвариант из ТЗ: язык — самый слабый сигнал в системе
        cfg = default_config()
        lang_weight = cfg.weight("unexpected_language").weight
        other_weights = [
            w.weight for name, w in cfg.signal_weights.items() if name != "unexpected_language"
        ]
        assert lang_weight < min(other_weights)

    def test_language_weight_below_observe_threshold(self) -> None:
        # один только язык не должен доводить даже до уровня OBSERVE
        cfg = default_config()
        assert cfg.weight("unexpected_language").weight < cfg.risk.observe


class TestLoadConfigFromYaml:
    def test_loads_bundled_default_file(self) -> None:
        cfg = load_config()
        assert cfg.version == 1
        assert cfg.sensitivity == Sensitivity.BALANCED

    def test_risk_thresholds_match_spec_ranges(self) -> None:
        cfg = load_config()
        assert cfg.risk.observe == 30
        assert cfg.risk.timeout == 60
        assert cfg.risk.ban == 80

    def test_unknown_top_level_key_rejected(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yml"
        bad.write_text("version: 1\ntypo_field: 123\n", encoding="utf-8")
        with pytest.raises(ConfigError, match="typo_field"):
            load_config(bad)

    def test_unknown_key_in_risk_thresholds_rejected(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yml"
        bad.write_text("risk_thresholds:\n  observe: 10\n  bnа: 50\n", encoding="utf-8")
        with pytest.raises(ConfigError):
            load_config(bad)

    def test_unknown_detector_name_rejected(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yml"
        bad.write_text("detectors:\n  unknown_detector:\n    enabled: true\n", encoding="utf-8")
        with pytest.raises(ConfigError, match="unknown_detector"):
            load_config(bad)

    def test_invalid_signal_family_rejected(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yml"
        bad.write_text(
            "signals:\n  foo: {family: not_a_real_family, weight: 5}\n", encoding="utf-8"
        )
        with pytest.raises(ConfigError):
            load_config(bad)

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError):
            load_config(tmp_path / "does_not_exist.yml")

    def test_bad_risk_threshold_ordering_rejected(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yml"
        bad.write_text(
            "risk_thresholds:\n  observe: 80\n  timeout: 60\n  ban: 30\n", encoding="utf-8"
        )
        with pytest.raises(ConfigError):
            load_config(bad)

    def test_partial_override_keeps_other_defaults(self, tmp_path: Path) -> None:
        partial = tmp_path / "partial.yml"
        partial.write_text("mode: AGGRESSIVE\n", encoding="utf-8")
        cfg = load_config(partial)
        assert cfg.sensitivity == Sensitivity.AGGRESSIVE
        # остальное не тронуто дефолтов
        assert cfg.risk.observe == 30

    def test_invalid_sensitivity_rejected(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yml"
        bad.write_text("mode: SUPER_MEGA_MODE\n", encoding="utf-8")
        with pytest.raises(ConfigError):
            load_config(bad)


class TestLanguageWeightInvariant:
    """SEC-004 аудита: unexpected_language обязан оставаться строго слабее
    любого другого сигнала — весь дизайн защиты от false positive на языке
    держится на этом. Раньше это было верно только по умолчанию, ADMIN мог
    молча сломать инвариант правкой конфига через панель."""

    def test_language_weight_equal_to_another_signal_rejected(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yml"
        bad.write_text(
            "signals:\n"
            "  unexpected_language: {family: encoding, weight: 10}\n"
            "  new_account: {family: identity, weight: 10}\n",
            encoding="utf-8",
        )
        with pytest.raises(ConfigError, match="unexpected_language"):
            load_config(bad)

    def test_language_weight_above_another_signal_rejected(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yml"
        bad.write_text(
            "signals:\n"
            "  unexpected_language: {family: encoding, weight: 50}\n"
            "  new_account: {family: identity, weight: 10}\n",
            encoding="utf-8",
        )
        with pytest.raises(ConfigError):
            load_config(bad)

    def test_language_weight_strictly_below_others_accepted(self, tmp_path: Path) -> None:
        good = tmp_path / "good.yml"
        good.write_text(
            "signals:\n"
            "  unexpected_language: {family: encoding, weight: 1}\n"
            "  new_account: {family: identity, weight: 10}\n",
            encoding="utf-8",
        )
        cfg = load_config(good)
        assert cfg.weight("unexpected_language").weight == 1

    def test_signals_section_without_language_not_checked(self, tmp_path: Path) -> None:
        # Секция signals без unexpected_language вообще — проверка не
        # применима, не должна ложно срабатывать.
        good = tmp_path / "good.yml"
        good.write_text(
            "signals:\n  new_account: {family: identity, weight: 10}\n", encoding="utf-8"
        )
        cfg = load_config(good)
        assert cfg.weight("new_account").weight == 10

    def test_bundled_default_config_satisfies_invariant(self) -> None:
        # Сам config/moderation.yml проекта не должен нарушать собственный
        # инвариант — регрессионная проверка на реальный файл.
        cfg = load_config()
        lang_weight = cfg.weight("unexpected_language").weight
        assert all(
            w.weight > lang_weight
            for name, w in cfg.signal_weights.items()
            if name != "unexpected_language"
        )


class TestTrustConfig:
    def test_default_enabled_with_both_thresholds(self) -> None:
        cfg = default_config()
        assert cfg.trust.enabled is True
        assert cfg.trust.min_messages_for_regular > 0
        assert cfg.trust.min_days_for_regular > 0

    def test_bundled_yaml_has_trust_section(self) -> None:
        cfg = load_config()
        assert cfg.trust.enabled is True
        assert cfg.trust.regular_risk_multiplier < 1.0

    def test_unknown_key_in_trust_rejected(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yml"
        bad.write_text("trust:\n  enabled: true\n  typo_field: 1\n", encoding="utf-8")
        with pytest.raises(ConfigError, match="typo_field"):
            load_config(bad)

    def test_partial_trust_override(self, tmp_path: Path) -> None:
        partial = tmp_path / "partial.yml"
        partial.write_text("trust:\n  min_messages_for_regular: 50\n", encoding="utf-8")
        cfg = load_config(partial)
        assert cfg.trust.min_messages_for_regular == 50
        # остальное — из дефолтов TrustConfig, не из bundled YAML
        assert cfg.trust.regular_risk_multiplier == 0.7


class TestChannelProfile:
    def test_missing_channel_file_returns_defaults(self, tmp_path: Path) -> None:
        profile = load_channel_profile("nosuchchannel", channels_dir=tmp_path)
        assert profile.primary_language == "ru"
        assert profile.suspicious_languages == ()

    def test_loads_example_profile(self) -> None:
        profile = load_channel_profile("example")
        assert profile.primary_language == "ru"
        assert "pl" in profile.suspicious_languages

    def test_unknown_key_in_channel_profile_rejected(self, tmp_path: Path) -> None:
        bad = tmp_path / "mychan.yml"
        bad.write_text(
            "channel_profile:\n  primary_language: ru\n  typo_key: 1\n", encoding="utf-8"
        )
        with pytest.raises(ConfigError):
            load_channel_profile("mychan", channels_dir=tmp_path)


class TestRiskThresholdsValidation:
    def test_family_factor_saturates_at_max_key(self) -> None:
        cfg = default_config()
        # семейств сработало больше, чем есть ключей в конфиге — берём максимум,
        # а не падаем и не возвращаем 0
        assert cfg.confidence.family_factor_for(10) == cfg.confidence.family_factor_for(5)

    def test_family_factor_zero_when_no_families(self) -> None:
        cfg = default_config()
        assert cfg.confidence.family_factor_for(0) == 0.0


def test_signal_family_enum_matches_config_values() -> None:
    # страховка от рассинхрона имён семейств между types.py и YAML
    for family in SignalFamily:
        assert family.value in {"content", "timing", "identity", "encoding", "network", "history"}
