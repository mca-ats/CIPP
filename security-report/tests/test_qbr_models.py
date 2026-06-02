"""Tests for the shared QBR data model (qbr_models.py).

Covers the logic-bearing helpers — quarter labelling and secure-score trend
math — not the plain dataclass holders.
"""
from datetime import datetime, timezone

import pytest

from qbr_models import (
    KpiMetric,
    ScorePoint,
    QbrData,
    quarter_label,
    score_trend,
)


# --- quarter_label -------------------------------------------------------

@pytest.mark.parametrize("month,expected_q", [
    (1, "Q1"), (2, "Q1"), (3, "Q1"),
    (4, "Q2"), (5, "Q2"), (6, "Q2"),
    (7, "Q3"), (8, "Q3"), (9, "Q3"),
    (10, "Q4"), (11, "Q4"), (12, "Q4"),
])
def test_quarter_label_maps_month_to_calendar_quarter(month, expected_q):
    dt = datetime(2026, month, 15, tzinfo=timezone.utc)
    assert quarter_label(dt) == f"2026-{expected_q}"


def test_quarter_label_uses_year_from_date():
    assert quarter_label(datetime(2025, 5, 30, tzinfo=timezone.utc)) == "2025-Q2"


# --- score_trend ---------------------------------------------------------

def test_score_trend_empty_history_returns_none_fields():
    result = score_trend([])
    assert result["latest_pct"] is None
    assert result["delta"] is None
    assert result["direction"] == "flat"


def test_score_trend_single_point_has_no_delta():
    history = [ScorePoint(date="2026-05-30", score=42.0, max_score=60.0)]
    result = score_trend(history)
    assert result["latest_pct"] == 70.0  # 42/60
    assert result["delta"] is None
    assert result["direction"] == "flat"


def test_score_trend_computes_delta_and_up_direction():
    history = [
        ScorePoint(date="2026-02-01", score=30.0, max_score=60.0),  # 50%
        ScorePoint(date="2026-05-30", score=42.0, max_score=60.0),  # 70%
    ]
    result = score_trend(history)
    assert result["latest_pct"] == 70.0
    assert result["previous_pct"] == 50.0
    assert result["delta"] == 20.0
    assert result["direction"] == "up"


def test_score_trend_detects_down_direction():
    history = [
        ScorePoint(date="2026-02-01", score=42.0, max_score=60.0),  # 70%
        ScorePoint(date="2026-05-30", score=30.0, max_score=60.0),  # 50%
    ]
    result = score_trend(history)
    assert result["delta"] == -20.0
    assert result["direction"] == "down"


def test_score_trend_uses_chronological_latest_not_list_order():
    # Out-of-order input must be sorted by date before computing trend.
    history = [
        ScorePoint(date="2026-05-30", score=42.0, max_score=60.0),  # newest
        ScorePoint(date="2026-02-01", score=30.0, max_score=60.0),  # oldest
    ]
    result = score_trend(history)
    assert result["latest_pct"] == 70.0
    assert result["previous_pct"] == 50.0
    assert result["direction"] == "up"


# --- dataclass construction (smoke) -------------------------------------

def test_kpi_metric_holds_fields():
    m = KpiMetric(key="license_utilization", label="License Utilization",
                  value=83.0, unit="%", status="good", detail={"assigned": 10})
    assert m.key == "license_utilization"
    assert m.status == "good"
    assert m.detail["assigned"] == 10


def test_qbr_data_defaults_to_empty_collections():
    q = QbrData(tenant_name="Abate Tech", tenant_id="abc",
                default_domain="abatetech.io", period="2026-Q2")
    assert q.kpis == []
    assert q.score_history == []
