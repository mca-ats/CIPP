"""Regression test for Secure Score parsing.

CIPP's /api/ListGraphRequest for security/secureScores returns a dict
{"Metadata": ..., "Results": [ {currentScore, maxScore, controlScores} ]},
NOT a bare list. The original collector only handled a list, so it silently
dropped the score (returned None) — leaving the QBR's centerpiece empty.
"""
from collectors import collect_secure_score


class _StubClient:
    """Minimal CippClient stand-in: .get() returns a canned response."""
    def __init__(self, payload):
        self.payload = payload

    def get(self, path, params=None):
        return self.payload


# Real shape observed from the lab tenant.
_REAL = {
    "Metadata": {"foo": "bar"},
    "Results": [{
        "currentScore": 886.0,
        "maxScore": 1049.0,
        "controlScores": [
            {"controlName": "MFARegistrationV2", "score": 8, "maxScore": 10,
             "description": "Require MFA registration"},
        ],
    }],
}


def test_parses_dict_with_results_shape():
    client = _StubClient(_REAL)
    current, maximum, findings = collect_secure_score(client, "tid", "Tenant")
    assert current == 886.0
    assert maximum == 1049.0
    # control gap should still produce a finding
    assert any("MFARegistrationV2" in f.title for f in findings)


def test_still_parses_bare_list_shape():
    # Defensive: if CIPP ever returns a bare list, keep working.
    client = _StubClient([{"currentScore": 50.0, "maxScore": 60.0, "controlScores": []}])
    current, maximum, _ = collect_secure_score(client, "tid", "Tenant")
    assert current == 50.0
    assert maximum == 60.0


def test_empty_results_returns_none():
    client = _StubClient({"Metadata": {}, "Results": []})
    current, maximum, findings = collect_secure_score(client, "tid", "Tenant")
    assert current is None
    assert maximum is None
    assert findings == []
