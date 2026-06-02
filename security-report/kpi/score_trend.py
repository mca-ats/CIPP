"""KPI collector: Secure Score trend with JSON file persistence.

Unlike the other KPI collectors, this one does not parse a CIPP response.
It maintains a small JSON history file, keyed by tenant_id, of Secure Score
readings so the QBR narrative can show a quarter-over-quarter trend.

Shape on disk::

    {
        "<tenant_id>": [
            {"date": "YYYY-MM-DD", "score": 42.0, "max_score": 60.0},
            ...
        ],
        ...
    }

The collector upserts the current run's reading (replace same-date, else
append) and returns this tenant's points sorted ascending by date. It is
defensive: a missing or corrupt history file is treated as empty, numeric
fields that arrive as strings are coerced, and it never raises on bad input.
"""

from __future__ import annotations

import json
import pathlib

from qbr_models import ScorePoint


def _coerce_float(value) -> float | None:
    """Best-effort float coercion. Returns None when not convertible."""
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _load_history(path: pathlib.Path) -> dict:
    """Load the history dict, tolerating a missing/corrupt/wrong-shaped file."""
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, FileNotFoundError):
        return {}
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return {}
    if not isinstance(data, dict):
        return {}
    return data


def _to_points(entries) -> list[ScorePoint]:
    """Turn on-disk dict entries into ScorePoint objects, sorted by date."""
    points: list[ScorePoint] = []
    if not isinstance(entries, list):
        return points
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        date = entry.get("date")
        score = _coerce_float(entry.get("score"))
        max_score = _coerce_float(entry.get("max_score"))
        if date is None or score is None or max_score is None:
            continue
        points.append(ScorePoint(date=str(date), score=score, max_score=max_score))
    points.sort(key=lambda p: p.date)
    return points


def collect_score_trend(
    tenant_id: str,
    current_score: float | None,
    max_score: float | None,
    run_date: str,
    history_path: str | pathlib.Path,
) -> list[ScorePoint]:
    """Upsert this run's Secure Score reading and return the tenant's trend.

    - Loads ``history_path`` (missing or corrupt -> treated as empty {}).
    - If both ``current_score`` and ``max_score`` coerce to a number, upserts a
      point for ``run_date`` into this tenant's list (replace same-date, else
      append) and writes the file back, creating parent directories.
    - If ``current_score`` is None (or not numeric), records nothing and just
      returns the existing history for this tenant.
    - Returns this tenant's points as ``list[ScorePoint]`` sorted ascending by
      date. Never raises on bad input.
    """
    path = pathlib.Path(history_path)
    history = _load_history(path)

    entries = history.get(tenant_id)
    if not isinstance(entries, list):
        entries = []

    score = _coerce_float(current_score)
    max_sc = _coerce_float(max_score)

    if score is not None and max_sc is not None:
        run_date_str = str(run_date)  # stored dates are strings; compare like-for-like
        new_entry = {"date": run_date_str, "score": score, "max_score": max_sc}
        replaced = False
        for i, entry in enumerate(entries):
            if isinstance(entry, dict) and entry.get("date") == run_date_str:
                entries[i] = new_entry
                replaced = True
                break
        if not replaced:
            entries.append(new_entry)

        history[tenant_id] = entries

        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(history, indent=2), encoding="utf-8")
        except OSError:
            # Persistence is best-effort; still return the in-memory result.
            pass

    return _to_points(entries)
