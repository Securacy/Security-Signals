"""Unit tests for the canonical internal<->public taxonomy mapping
(app/taxonomy.py) - the single source of truth used by both category
filtering (signals.py, search.py) and public category aggregation."""

import pytest

from app.db.models import SecurityCategoryType
from app.taxonomy import (
    PUBLIC_CATEGORIES,
    PUBLIC_CATEGORY_LABELS,
    UnknownPublicCategoryError,
    internal_categories_to_public,
    public_category_to_internal,
)


class TestPublicCategoryList:
    def test_exactly_eight_public_categories(self):
        assert len(PUBLIC_CATEGORIES) == 8

    def test_every_public_category_has_a_label(self):
        for slug in PUBLIC_CATEGORIES:
            assert slug in PUBLIC_CATEGORY_LABELS
            assert PUBLIC_CATEGORY_LABELS[slug]

    def test_old_internal_only_labels_are_not_public_categories(self):
        old_public_labels = {"Insecure Design", "App/API", "Cloud Security", "IAM"}
        assert not (old_public_labels & set(PUBLIC_CATEGORY_LABELS.values()))


class TestCategoryMapping:
    @pytest.mark.parametrize("internal,expected_public", [
        (SecurityCategoryType.INSECURE_DESIGN, "product_security"),
        (SecurityCategoryType.APP_API, "product_security"),
        (SecurityCategoryType.CLOUD_SECURITY, "cloud_identity_security"),
        (SecurityCategoryType.IAM, "cloud_identity_security"),
        (SecurityCategoryType.SUPPLY_CHAIN, "supply_chain"),
        (SecurityCategoryType.DATA_PRIVACY, "data_privacy"),
        (SecurityCategoryType.RANSOMWARE, "ransomware"),
        (SecurityCategoryType.THREAT_INTEL, "threat_intel"),
        (SecurityCategoryType.AI_SECURITY, "ai_security"),
        (SecurityCategoryType.INFRASTRUCTURE, "infrastructure"),
    ])
    def test_internal_to_public_mapping(self, internal, expected_public):
        assert internal_categories_to_public([internal]) == [expected_public]

    def test_ai_security_is_independent_not_merged(self):
        """AI Security must never collapse into Product Security or Cloud
        & Identity Security."""
        assert internal_categories_to_public([SecurityCategoryType.AI_SECURITY]) == ["ai_security"]

    def test_unknown_internal_value_is_skipped_not_raised(self):
        assert internal_categories_to_public(["not_a_real_category"]) == []


class TestMultiCategoryCollapse:
    def test_insecure_design_and_app_api_collapse_to_one_product_security(self):
        result = internal_categories_to_public([
            SecurityCategoryType.INSECURE_DESIGN, SecurityCategoryType.APP_API,
        ])
        assert result == ["product_security"]

    def test_cloud_security_and_iam_collapse_to_one_cloud_identity_security(self):
        result = internal_categories_to_public([
            SecurityCategoryType.CLOUD_SECURITY, SecurityCategoryType.IAM,
        ])
        assert result == ["cloud_identity_security"]

    def test_cloud_security_and_supply_chain_remain_two_distinct_categories(self):
        result = internal_categories_to_public([
            SecurityCategoryType.CLOUD_SECURITY, SecurityCategoryType.SUPPLY_CHAIN,
        ])
        assert result == ["cloud_identity_security", "supply_chain"]

    def test_three_internal_categories_collapse_to_two_public(self):
        result = internal_categories_to_public([
            SecurityCategoryType.INSECURE_DESIGN,
            SecurityCategoryType.APP_API,
            SecurityCategoryType.CLOUD_SECURITY,
        ])
        assert result == ["product_security", "cloud_identity_security"]

    def test_order_is_first_seen_not_alphabetical(self):
        result = internal_categories_to_public([
            SecurityCategoryType.SUPPLY_CHAIN, SecurityCategoryType.CLOUD_SECURITY,
        ])
        assert result == ["supply_chain", "cloud_identity_security"]

    def test_accepts_raw_string_values_not_just_enum_members(self):
        """SQLAlchemy may hand back either the enum member or its raw
        string value depending on the query path - both must work."""
        result = internal_categories_to_public(["cloud_security", "iam"])
        assert result == ["cloud_identity_security"]


class TestPublicToInternalFiltering:
    def test_product_security_includes_insecure_design_and_app_api(self):
        internals = public_category_to_internal("product_security")
        assert set(internals) == {SecurityCategoryType.INSECURE_DESIGN, SecurityCategoryType.APP_API}

    def test_cloud_identity_security_includes_cloud_security_and_iam(self):
        internals = public_category_to_internal("cloud_identity_security")
        assert set(internals) == {SecurityCategoryType.CLOUD_SECURITY, SecurityCategoryType.IAM}

    @pytest.mark.parametrize("public,expected_internal", [
        ("supply_chain", SecurityCategoryType.SUPPLY_CHAIN),
        ("data_privacy", SecurityCategoryType.DATA_PRIVACY),
        ("ransomware", SecurityCategoryType.RANSOMWARE),
        ("threat_intel", SecurityCategoryType.THREAT_INTEL),
        ("ai_security", SecurityCategoryType.AI_SECURITY),
        ("infrastructure", SecurityCategoryType.INFRASTRUCTURE),
    ])
    def test_one_to_one_mappings(self, public, expected_internal):
        assert public_category_to_internal(public) == [expected_internal]

    def test_unknown_public_category_raises(self):
        with pytest.raises(UnknownPublicCategoryError):
            public_category_to_internal("not_a_real_public_category")

    def test_old_internal_slugs_are_not_valid_public_category_filters(self):
        """A caller must not be able to filter by the raw internal slug
        'iam' or 'app_api' as if it were a public category - those only
        exist inside the aggregated public categories now."""
        with pytest.raises(UnknownPublicCategoryError):
            public_category_to_internal("iam")
        with pytest.raises(UnknownPublicCategoryError):
            public_category_to_internal("app_api")
