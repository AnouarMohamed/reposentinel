#!/usr/bin/env python3
"""
RepoSentinel - scores a GitHub repo's security posture.
Checks are weighted; each gracefully degrades to "unknown" if the
token doesn't have enough permission to answer it (instead of failing).
"""
import os
import sys
import json
import urllib.parse
import requests

API_BASE = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")


def gh_get(session, path):
    url = f"{API_BASE}{path}" if path.startswith("/") else f"{API_BASE}/{path}"
    try:
        r = session.get(url, timeout=15)
        return r
    except requests.exceptions.RequestException as err:
        return None


class Check:
    def __init__(self, name, weight):
        self.name = name
        self.weight = weight
        self.status = "unknown"   # pass | fail | unknown
        self.detail = ""

    @property
    def points(self):
        return self.weight if self.status == "pass" else 0


def check_branch_protection(session, owner, repo, default_branch, c: Check):
    safe_branch = urllib.parse.quote(default_branch, safe="")
    r = gh_get(session, f"/repos/{owner}/{repo}/branches/{safe_branch}/protection")
    if r is None:
        c.status = "unknown"
        c.detail = "Network error / timeout reaching GitHub API."
    elif r.status_code == 200:
        c.status = "pass"
        c.detail = "Branch protection enabled on default branch."
    elif r.status_code == 404:
        c.status = "fail"
        c.detail = "No branch protection on default branch."
    else:
        c.status = "unknown"
        c.detail = f"Could not verify (HTTP {r.status_code}, needs admin token)."


def check_dependabot_config(session, owner, repo, c: Check):
    r = gh_get(session, f"/repos/{owner}/{repo}/contents/.github/dependabot.yml")
    if r is None:
        c.status = "unknown"
        c.detail = "Network error / timeout reaching GitHub API."
    elif r.status_code == 200:
        c.status = "pass"
        c.detail = "dependabot.yml present."
    elif r.status_code == 404:
        c.status = "fail"
        c.detail = "No dependabot.yml found."
    else:
        c.status = "unknown"
        c.detail = f"Could not verify (HTTP {r.status_code})."


def check_security_policy(session, owner, repo, c: Check):
    r = gh_get(session, f"/repos/{owner}/{repo}/community/profile")
    if r is not None and r.status_code == 200:
        try:
            files = r.json().get("files", {}) or {}
        except (ValueError, AttributeError):
            files = {}
        if files.get("security"):
            c.status = "pass"
            c.detail = "SECURITY.md present."
            return

    # Fallback to direct path checks (useful for private repos where community profile endpoint may 404)
    status_codes = []
    for path in [".github/SECURITY.md", "SECURITY.md", "docs/SECURITY.md"]:
        r_file = gh_get(session, f"/repos/{owner}/{repo}/contents/{path}")
        if r_file is None:
            status_codes.append(None)
            continue
        status_codes.append(r_file.status_code)
        if r_file.status_code == 200:
            c.status = "pass"
            c.detail = f"{path} present."
            return

    if status_codes and all(sc == 404 for sc in status_codes):
        c.status = "fail"
        c.detail = "No SECURITY.md found."
    else:
        last_sc = next((sc for sc in reversed(status_codes) if sc is not None), "unknown")
        c.status = "unknown"
        c.detail = f"Could not verify SECURITY.md (HTTP {last_sc})."


def check_codeowners(session, owner, repo, c: Check):
    status_codes = []
    for path in [".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"]:
        r = gh_get(session, f"/repos/{owner}/{repo}/contents/{path}")
        if r is None:
            status_codes.append(None)
            continue
        status_codes.append(r.status_code)
        if r.status_code == 200:
            c.status = "pass"
            c.detail = f"{path} present."
            return

    if status_codes and all(sc == 404 for sc in status_codes):
        c.status = "fail"
        c.detail = "No CODEOWNERS file found."
    else:
        last_sc = next((sc for sc in reversed(status_codes) if sc is not None), "unknown")
        c.status = "unknown"
        c.detail = f"Could not verify CODEOWNERS (HTTP {last_sc})."


def check_vulnerability_alerts(session, owner, repo, is_private, c: Check):
    r = gh_get(session, f"/repos/{owner}/{repo}/vulnerability-alerts")
    if r is None:
        c.status = "unknown"
        c.detail = "Network error / timeout reaching GitHub API."
    elif r.status_code == 204:
        c.status = "pass"
        c.detail = "Dependency graph / vulnerability alerts enabled."
    elif r.status_code == 404:
        if is_private:
            c.status = "unknown"
            c.detail = "Vulnerability alerts status unverified (private repo requires admin token)."
        else:
            c.status = "fail"
            c.detail = "Vulnerability alerts not enabled."
    else:
        c.status = "unknown"
        c.detail = f"Could not verify (HTTP {r.status_code}, needs admin token)."


def check_secret_scanning(session, owner, repo, c: Check):
    r = gh_get(session, f"/repos/{owner}/{repo}")
    if r is None:
        c.status = "unknown"
        c.detail = "Network error / timeout reaching GitHub API."
        return
    if r.status_code == 200:
        try:
            data = r.json() if isinstance(r.json(), dict) else {}
        except Exception:
            data = {}
        analysis = data.get("security_and_analysis")
        if isinstance(analysis, dict):
            secret_scan = analysis.get("secret_scanning")
            if isinstance(secret_scan, dict):
                status = secret_scan.get("status")
                if status == "enabled":
                    c.status = "pass"
                    c.detail = "Secret scanning enabled."
                    return
                elif status == "disabled":
                    c.status = "fail"
                    c.detail = "Secret scanning disabled."
                    return
        c.status = "unknown"
        c.detail = "Secret scanning status not visible (needs admin token or private repo permissions)."
    else:
        c.status = "unknown"
        c.detail = f"Could not verify (HTTP {r.status_code})."


def check_signed_commits(session, owner, repo, default_branch, c: Check):
    safe_branch = urllib.parse.quote(default_branch, safe="")
    r = gh_get(session, f"/repos/{owner}/{repo}/commits?sha={safe_branch}&per_page=20")
    if r is None:
        c.status = "unknown"
        c.detail = "Network error / timeout reaching GitHub API."
        return
    if r.status_code == 200:
        try:
            commits = r.json()
        except Exception:
            c.status = "unknown"
            c.detail = "Invalid JSON response for commits."
            return

        if not isinstance(commits, list):
            c.status = "unknown"
            c.detail = "Unexpected API format for commits."
            return

        if not commits:
            c.status = "unknown"
            c.detail = "No commits found."
            return

        verified = 0
        for cm in commits:
            if isinstance(cm, dict):
                commit_obj = cm.get("commit")
                if isinstance(commit_obj, dict):
                    verification = commit_obj.get("verification")
                    if isinstance(verification, dict) and verification.get("verified"):
                        verified += 1

        ratio = verified / len(commits)
        c.detail = f"{verified}/{len(commits)} of last {len(commits)} commits verified."
        c.status = "pass" if ratio >= 0.5 else "fail"
    else:
        c.status = "unknown"
        c.detail = f"Could not verify (HTTP {r.status_code})."


def grade_for(score):
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def main():
    token = os.environ.get("INPUT_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN")
    repo_full = os.environ.get("INPUT_REPO") or os.environ.get("GITHUB_REPOSITORY")
    raw_fail_below = os.environ.get("INPUT_FAIL_BELOW", "0")
    try:
        fail_below = int(float(raw_fail_below))
    except (ValueError, TypeError):
        print(f"::warning::Invalid fail_below threshold '{raw_fail_below}', defaulting to 0")
        fail_below = 0

    if not repo_full or "/" not in repo_full:
        print("::error::repo input must be in format 'owner/name'")
        sys.exit(1)

    parts = [p.strip() for p in repo_full.strip().split("/", 1)]
    if len(parts) != 2 or not parts[0] or not parts[1]:
        print("::error::repo input must be in format 'owner/name'")
        sys.exit(1)
    owner, repo = parts[0], parts[1]

    session = requests.Session()
    session.headers.update({
        "Accept": "application/vnd.github+json",
        "User-Agent": "RepoSentinel-Action/1.0"
    })
    if token:
        session.headers.update({"Authorization": f"Bearer {token}"})

    repo_resp = gh_get(session, f"/repos/{owner}/{repo}")
    if repo_resp is None:
        print(f"::error::Could not connect to GitHub API at {API_BASE}")
        sys.exit(1)
    if repo_resp.status_code in (401, 403, 404):
        print(f"::error::Unable to access repository '{owner}/{repo}' (HTTP {repo_resp.status_code}). Check repository name and GITHUB_TOKEN permissions.")
        sys.exit(1)

    default_branch = "main"
    is_private = False
    if repo_resp.status_code == 200:
        try:
            repo_info = repo_resp.json() if isinstance(repo_resp.json(), dict) else {}
        except Exception:
            repo_info = {}
        default_branch = repo_info.get("default_branch", "main")
        is_private = bool(repo_info.get("private", False))

    checks = {
        "branch_protection": Check("Branch protection", 20),
        "dependabot": Check("Dependabot config", 15),
        "security_policy": Check("Security policy (SECURITY.md)", 10),
        "codeowners": Check("CODEOWNERS", 10),
        "vuln_alerts": Check("Dependency graph / vulnerability alerts", 15),
        "secret_scanning": Check("Secret scanning", 15),
        "signed_commits": Check("Signed commits (recent)", 15),
    }

    check_branch_protection(session, owner, repo, default_branch, checks["branch_protection"])
    check_dependabot_config(session, owner, repo, checks["dependabot"])
    check_security_policy(session, owner, repo, checks["security_policy"])
    check_codeowners(session, owner, repo, checks["codeowners"])
    check_vulnerability_alerts(session, owner, repo, is_private, checks["vuln_alerts"])
    check_secret_scanning(session, owner, repo, checks["secret_scanning"])
    check_signed_commits(session, owner, repo, default_branch, checks["signed_commits"])

    # unknowns don't count against the possible total (avoids punishing low-permission tokens)
    max_possible = sum(c.weight for c in checks.values() if c.status != "unknown")
    earned = sum(c.points for c in checks.values())
    score = round((earned / max_possible) * 100) if max_possible else 0
    grade = grade_for(score)

    result = {
        "repo": f"{owner}/{repo}",
        "score": score,
        "grade": grade,
        "checks": {
            key: {"name": c.name, "status": c.status, "detail": c.detail, "weight": c.weight}
            for key, c in checks.items()
        },
    }

    print(json.dumps(result, indent=2))

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a") as f:
            f.write(f"## RepoSentinel report — {owner}/{repo}\n\n")
            f.write(f"**Score: {score}/100 — Grade {grade}**\n\n")
            if max_possible == 0:
                f.write("> ⚠️ **Note:** All security checks returned 'unknown'. Verify that your GITHUB_TOKEN has sufficient permissions.\n\n")
            f.write("| Check | Weight | Status | Detail |\n|---|---|---|---|\n")
            for c in checks.values():
                icon = {"pass": "✅", "fail": "❌", "unknown": "❔"}[c.status]
                f.write(f"| {c.name} | {c.weight} | {icon} {c.status} | {c.detail} |\n")

    out_path = os.environ.get("GITHUB_OUTPUT")
    if out_path:
        with open(out_path, "a") as f:
            f.write(f"score={score}\n")
            f.write(f"grade={grade}\n")

    badge = {
        "schemaVersion": 1,
        "label": "RepoSentinel",
        "message": f"{score}/100 ({grade})",
        "color": {"A": "brightgreen", "B": "green", "C": "yellow", "D": "orange", "F": "red"}[grade],
    }
    with open("reposentinel-badge.json", "w") as f:
        json.dump(badge, f)

    if score < fail_below:
        print(f"::error::Score {score} is below required threshold {fail_below}")
        sys.exit(1)


if __name__ == "__main__":
    main()
