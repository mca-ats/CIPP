"""Tests for kpi.score_trend.collect_score_trend (file-persistence KPI).

This collector does NOT parse CIPP — it reads/writes a small JSON history
file keyed by tenant_id, upserts the current run's Secure Score reading, and
returns this tenant's points sorted ascending by date.

All tests use pytest's ``tmp_path`` so no real files are touched.
"""
import json
from pathlib import Path

import pytest

from qbr_models import ScorePoint
from kpi.score_trend import collect_score_trend


# --- happy path: first write creates file --------------------------------

def test_first_call_creates_file_and_returns_one_point(tmp_path):
    history = tmp_path / "score_history.json"
    points = collect_score_trend(
        tenant_id="t1", current_score=42.0, max_score=60.0,
        run_date="2026-05-30", history_path=history,
    )
    assert history.exists()
    assert len(points) == 1
    assert isinstance(points[0], ScorePoint)
    assert points[0].date == "2026-05-30"
    assert points[0].score == 42.0
    assert points[0].max_score == 60.0
    assert points[0].pct == 70.0  # 42/60

    # File persisted the point under the tenant key.
    on_disk = json.loads(history.read_text())
    assert on_disk["t1"][0]["score"] == 42.0


def test_first_call_creates_parent_dirs(tmp_path):
    history = tmp_path / "nested" / "deeper" / "score_history.json"
    points = collect_score_trend(
        tenant_id="t1", current_score=10.0, max_score=20.0,
        run_date="2026-05-30", history_path=history,
    )
    assert history.exists()
    assert len(points) == 1


# --- upsert semantics -----------------------------------------------------

def test_same_run_date_replaces_existing_point(tmp_path):
    history = tmp_path / "h.json"
    collect_score_trend(
        tenant_id="t1", current_score=42.0, max_score=60.0,
        run_date="2026-05-30", history_path=history,
    )
    points = collect_score_trend(
        tenant_id="t1", current_score=48.0, max_score=60.0,
        run_date="2026-05-30", history_path=history,
    )
    assert len(points) == 1          # upsert, not append
    assert points[0].score == 48.0   # value updated
    assert points[0].pct == 80.0     # 48/60

    on_disk = json.loads(history.read_text())
    assert len(on_disk["t1"]) == 1
    assert on_disk["t1"][0]["score"] == 48.0


def test_later_run_date_appends_and_sorts_ascending(tmp_path):
    history = tmp_path / "h.json"
    collect_score_trend(
        tenant_id="t1", current_score=30.0, max_score=60.0,
        run_date="2026-02-01", history_path=history,
    )
    points = collect_score_trend(
        tenant_id="t1", current_score=42.0, max_score=60.0,
        run_date="2026-05-30", history_path=history,
    )
    assert len(points) == 2
    assert [p.date for p in points] == ["2026-02-01", "2026-05-30"]
    assert points[-1].score == 42.0  # newest is last
    assert points[0].score == 30.0


def test_returned_points_sorted_even_when_earlier_date_written_last(tmp_path):
    history = tmp_path / "h.json"
    collect_score_trend(
        tenant_id="t1", current_score=42.0, max_score=60.0,
        run_date="2026-05-30", history_path=history,
    )
    points = collect_score_trend(
        tenant_id="t1", current_score=30.0, max_score=60.0,
        run_date="2026-02-01", history_path=history,  # older date written second
    )
    assert [p.date for p in points] == ["2026-02-01", "2026-05-30"]


# --- None current_score: read-only ---------------------------------------

def test_none_current_score_returns_existing_without_recording(tmp_path):
    history = tmp_path / "h.json"
    collect_score_trend(
        tenant_id="t1", current_score=42.0, max_score=60.0,
        run_date="2026-02-01", history_path=history,
    )
    points = collect_score_trend(
        tenant_id="t1", current_score=None, max_score=60.0,
        run_date="2026-05-30", history_path=history,
    )
    # No new point recorded for the None run.
    assert len(points) == 1
    assert points[0].date == "2026-02-01"

    on_disk = json.loads(history.read_text())
    assert len(on_disk["t1"]) == 1
    assert "2026-05-30" not in [p["date"] for p in on_disk["t1"]]


def test_none_max_score_does_not_record(tmp_path):
    history = tmp_path / "h.json"
    collect_score_trend(
        tenant_id="t1", current_score=42.0, max_score=60.0,
        run_date="2026-02-01", history_path=history,
    )
    points = collect_score_trend(
        tenant_id="t1", current_score=42.0, max_score=None,
        run_date="2026-05-30", history_path=history,
    )
    assert len(points) == 1
    assert points[0].date == "2026-02-01"


def test_none_current_score_on_fresh_path_returns_empty(tmp_path):
    history = tmp_path / "missing.json"
    points = collect_score_trend(
        tenant_id="t1", current_score=None, max_score=60.0,
        run_date="2026-05-30", history_path=history,
    )
    assert points == []


# --- robustness: missing / corrupt file ----------------------------------

def test_missing_file_treated_as_empty_then_records(tmp_path):
    history = tmp_path / "does_not_exist.json"
    points = collect_score_trend(
        tenant_id="t1", current_score=42.0, max_score=60.0,
        run_date="2026-05-30", history_path=history,
    )
    assert len(points) == 1
    assert history.exists()


def test_corrupt_json_does_not_raise_and_records(tmp_path):
    history = tmp_path / "corrupt.json"
    history.write_text("{not json")
    points = collect_score_trend(
        tenant_id="t1", current_score=42.0, max_score=60.0,
        run_date="2026-05-30", history_path=history,
    )
    assert len(points) == 1
    assert points[0].score == 42.0
    # File should now be valid JSON.
    on_disk = json.loads(history.read_text())
    assert on_disk["t1"][0]["score"] == 42.0


def test_non_dict_json_treated_as_empty(tmp_path):
    history = tmp_path / "list.json"
    history.write_text("[1, 2, 3]")  # valid JSON, wrong shape
    points = collect_score_trend(
        tenant_id="t1", current_score=42.0, max_score=60.0,
        run_date="2026-05-30", history_path=history,
    )
    assert len(points) == 1


# --- tenant isolation -----------------------------------------------------

def test_two_tenants_stay_isolated(tmp_path):
    history = tmp_path / "h.json"
    collect_score_trend(
        tenant_id="t1", current_score=42.0, max_score=60.0,
        run_date="2026-05-30", history_path=history,
    )
    t2_points = collect_score_trend(
        tenant_id="t2", current_score=10.0, max_score=20.0,
        run_date="2026-05-30", history_path=history,
    )
    assert len(t2_points) == 1
    assert t2_points[0].score == 10.0

    t1_points = collect_score_trend(
        tenant_id="t1", current_score=None, max_score=None,
        run_date="2026-05-30", history_path=history,
    )
    assert len(t1_points) == 1
    assert t1_points[0].score == 42.0

    on_disk = json.loads(history.read_text())
    assert set(on_disk.keys()) == {"t1", "t2"}
    assert len(on_disk["t1"]) == 1
    assert len(on_disk["t2"]) == 1


def test_unknown_tenant_returns_empty(tmp_path):
    history = tmp_path / "h.json"
    collect_score_trend(
        tenant_id="t1", current_score=42.0, max_score=60.0,
        run_date="2026-05-30", history_path=history,
    )
    points = collect_score_trend(
        tenant_id="ghost", current_score=None, max_score=None,
        run_date="2026-05-30", history_path=history,
    )
    assert points == []


# --- defensive type coercion ---------------------------------------------

def test_string_scores_in_existing_file_are_coerced(tmp_path):
    history = tmp_path / "h.json"
    # CIPP-style: numbers arrive as strings on disk.
    history.write_text(json.dumps({
        "t1": [{"date": "2026-02-01", "score": "30", "max_score": "60"}],
    }))
    points = collect_score_trend(
        tenant_id="t1", current_score=None, max_score=None,
        run_date="2026-05-30", history_path=history,
    )
    assert len(points) == 1
    assert points[0].score == 30.0
    assert points[0].max_score == 60.0
    assert points[0].pct == 50.0


def test_string_current_score_is_coerced(tmp_path):
    history = tmp_path / "h.json"
    points = collect_score_trend(
        tenant_id="t1", current_score="42", max_score="60",
        run_date="2026-05-30", history_path=history,
    )
    assert len(points) == 1
    assert points[0].score == 42.0
    assert points[0].max_score == 60.0


def test_accepts_string_path(tmp_path):
    history = tmp_path / "h.json"
    points = collect_score_trend(
        tenant_id="t1", current_score=42.0, max_score=60.0,
        run_date="2026-05-30", history_path=str(history),  # str, not Path
    )
    assert len(points) == 1
    assert history.exists()
