import os
import json
import pytest
from unittest.mock import MagicMock, patch

from src.score import (
    Check,
    grade_for,
    check_branch_protection,
    check_dependabot_config,
    check_security_policy,
    check_codeowners,
    check_vulnerability_alerts,
    check_secret_scanning,
    check_signed_commits,
    main,
)


def test_grade_for():
    assert grade_for(95) == "A"
    assert grade_for(90) == "A"
    assert grade_for(89) == "B"
    assert grade_for(75) == "B"
    assert grade_for(74) == "C"
    assert grade_for(60) == "C"
    assert grade_for(59) == "D"
    assert grade_for(40) == "D"
    assert grade_for(39) == "F"
    assert grade_for(0) == "F"


def test_check_branch_protection():
    c = Check("Branch protection", 20)
    session = MagicMock()

    # Pass 200
    with patch("src.score.gh_get") as mock_get:
        mock_get.return_value.status_code = 200
        check_branch_protection(session, "owner", "repo", "main", c)
        assert c.status == "pass"

    # Fail 404
    with patch("src.score.gh_get") as mock_get:
        mock_get.return_value.status_code = 404
        check_branch_protection(session, "owner", "repo", "main", c)
        assert c.status == "fail"

    # Unknown 403
    with patch("src.score.gh_get") as mock_get:
        mock_get.return_value.status_code = 403
        check_branch_protection(session, "owner", "repo", "main", c)
        assert c.status == "unknown"

    # Network Error (None)
    with patch("src.score.gh_get") as mock_get:
        mock_get.return_value = None
        check_branch_protection(session, "owner", "repo", "main", c)
        assert c.status == "unknown"


def test_check_dependabot_config():
    c = Check("Dependabot config", 15)
    session = MagicMock()

    with patch("src.score.gh_get") as mock_get:
        mock_get.return_value.status_code = 200
        check_dependabot_config(session, "owner", "repo", c)
        assert c.status == "pass"

    with patch("src.score.gh_get") as mock_get:
        mock_get.return_value.status_code = 404
        check_dependabot_config(session, "owner", "repo", c)
        assert c.status == "fail"


def test_check_security_policy():
    c = Check("Security policy", 10)
    session = MagicMock()

    # Pass via community profile
    with patch("src.score.gh_get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"files": {"security": {"url": "..."}}}
        mock_get.return_value = mock_resp
        check_security_policy(session, "owner", "repo", c)
        assert c.status == "pass"

    # Pass via direct file fallback when community profile returns 404
    with patch("src.score.gh_get") as mock_get:
        prof_resp = MagicMock(status_code=404)
        file_resp = MagicMock(status_code=200)
        mock_get.side_effect = [prof_resp, file_resp]
        check_security_policy(session, "owner", "repo", c)
        assert c.status == "pass"

    # Fail when profile 404 and all fallbacks 404
    with patch("src.score.gh_get") as mock_get:
        prof_resp = MagicMock(status_code=404)
        file_resp = MagicMock(status_code=404)
        mock_get.side_effect = [prof_resp, file_resp, file_resp, file_resp]
        check_security_policy(session, "owner", "repo", c)
        assert c.status == "fail"


def test_check_codeowners():
    c = Check("CODEOWNERS", 10)
    session = MagicMock()

    # Pass 200
    with patch("src.score.gh_get") as mock_get:
        mock_resp = MagicMock(status_code=200)
        mock_get.return_value = mock_resp
        check_codeowners(session, "owner", "repo", c)
        assert c.status == "pass"

    # Fail only when all paths return 404
    with patch("src.score.gh_get") as mock_get:
        mock_resp = MagicMock(status_code=404)
        mock_get.return_value = mock_resp
        check_codeowners(session, "owner", "repo", c)
        assert c.status == "fail"

    # Unknown when forbidden / rate limited (403) instead of false fail
    with patch("src.score.gh_get") as mock_get:
        mock_resp = MagicMock(status_code=403)
        mock_get.return_value = mock_resp
        check_codeowners(session, "owner", "repo", c)
        assert c.status == "unknown"


def test_check_vulnerability_alerts():
    c = Check("Vulnerability alerts", 15)
    session = MagicMock()

    # Pass 204
    with patch("src.score.gh_get") as mock_get:
        mock_get.return_value.status_code = 204
        check_vulnerability_alerts(session, "owner", "repo", False, c)
        assert c.status == "pass"

    # Fail on 404 for Public Repo
    with patch("src.score.gh_get") as mock_get:
        mock_get.return_value.status_code = 404
        check_vulnerability_alerts(session, "owner", "repo", False, c)
        assert c.status == "fail"

    # Unknown on 404 for Private Repo (avoids false failure when token lacks permission)
    with patch("src.score.gh_get") as mock_get:
        mock_get.return_value.status_code = 404
        check_vulnerability_alerts(session, "owner", "repo", True, c)
        assert c.status == "unknown"


def test_check_secret_scanning():
    c = Check("Secret scanning", 15)
    session = MagicMock()

    # Pass
    with patch("src.score.gh_get") as mock_get:
        resp = MagicMock(status_code=200)
        resp.json.return_value = {"security_and_analysis": {"secret_scanning": {"status": "enabled"}}}
        mock_get.return_value = resp
        check_secret_scanning(session, "owner", "repo", c)
        assert c.status == "pass"

    # Unknown on missing field
    with patch("src.score.gh_get") as mock_get:
        resp = MagicMock(status_code=200)
        resp.json.return_value = {}
        mock_get.return_value = resp
        check_secret_scanning(session, "owner", "repo", c)
        assert c.status == "unknown"


def test_check_signed_commits():
    c = Check("Signed commits", 15)
    session = MagicMock()

    # Pass (all verified)
    with patch("src.score.gh_get") as mock_get:
        resp = MagicMock(status_code=200)
        resp.json.return_value = [
            {"commit": {"verification": {"verified": True}}},
            {"commit": {"verification": {"verified": True}}},
        ]
        mock_get.return_value = resp
        check_signed_commits(session, "owner", "repo", "main", c)
        assert c.status == "pass"

    # Resilient against null commit objects in payload
    with patch("src.score.gh_get") as mock_get:
        resp = MagicMock(status_code=200)
        resp.json.return_value = [
            {"commit": None},
            {"commit": {"verification": None}},
        ]
        mock_get.return_value = resp
        check_signed_commits(session, "owner", "repo", "feature/test", c)
        assert c.status == "fail"

    # Resilient against non-list JSON payload
    with patch("src.score.gh_get") as mock_get:
        resp = MagicMock(status_code=200)
        resp.json.return_value = {"message": "Git repository is empty."}
        mock_get.return_value = resp
        check_signed_commits(session, "owner", "repo", "main", c)
        assert c.status == "unknown"


def test_main_execution(tmp_path, monkeypatch):
    monkeypatch.setenv("INPUT_REPO", "octocat/Hello-World")
    monkeypatch.setenv("INPUT_FAIL_BELOW", "0")
    badge_file = tmp_path / "reposentinel-badge.json"
    monkeypatch.chdir(tmp_path)

    with patch("src.score.gh_get") as mock_get:
        repo_resp = MagicMock(status_code=200)
        repo_resp.json.return_value = {"default_branch": "main", "private": False}
        mock_get.return_value = repo_resp
        
        main()

    assert badge_file.exists()
    with open(badge_file) as f:
        data = json.load(f)
        assert "schemaVersion" in data
        assert "message" in data
