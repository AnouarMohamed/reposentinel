# RepoSentinel

A GitHub Action that scores a repository's security posture and gives it a letter grade (A–F).

## Security Checks (v1)

| Check | Weight | Verification API / Scope |
|---|---|---|
| Branch protection on default branch | 20 | `/repos/{owner}/{repo}/branches/{branch}/protection` (admin) |
| Dependency graph / vulnerability alerts | 15 | `/repos/{owner}/{repo}/vulnerability-alerts` (admin/security) |
| Secret scanning enabled | 15 | `/repos/{owner}/{repo}` (`security_and_analysis` field) |
| Signed commits (last 20 on default branch) | 15 | `/repos/{owner}/{repo}/commits` |
| Dependabot config | 15 | `.github/dependabot.yml` |
| Security policy | 10 | `/community/profile` or `SECURITY.md` |
| CODEOWNERS file | 10 | `.github/CODEOWNERS`, `CODEOWNERS`, `docs/CODEOWNERS` |

Checks that cannot be verified with the token provided (e.g. `secrets.GITHUB_TOKEN` lacking admin scope for branch protection) are gracefully marked `unknown` and excluded from the denominator — ensuring low-permission tokens don't unfairly tank the security grade.

---

## Usage

```yaml
- uses: actions/checkout@v4

- name: Score Security Posture
  id: reposentinel
  uses: AnouarMohamed/reposentinel@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    fail_below: "0"   # optional: fail CI if score drops below this threshold (0-100)

- name: Display Score
  run: |
    echo "Repo Security Score: ${{ steps.reposentinel.outputs.score }}"
    echo "Repo Security Grade: ${{ steps.reposentinel.outputs.grade }}"
```

### Inputs

| Input | Description | Required | Default |
|---|---|---|---|
| `github_token` | Token used to query the GitHub API. Uses `secrets.GITHUB_TOKEN` by default; admin-scoped token unlocks branch-protection and secret scanning checks. | Yes | N/A |
| `repo` | Target `owner/repo` to score. | No | `${{ github.repository }}` |
| `fail_below` | Threshold score (0–100) below which the action fails. `0` disables failure. | No | `"0"` |

### Outputs

| Output | Description |
|---|---|
| `score` | Score out of 100 |
| `grade` | Letter grade (`A`, `B`, `C`, `D`, `F`) |

---

## Features & Enterprise Support

- **Composite Action Output Binding:** Properly outputs step results for downstream action steps.
- **GitHub Enterprise Server (GHES):** Automatically respects `GITHUB_API_URL` environment variable for self-hosted instances.
- **Resilient Degredation:** Distinguishes HTTP 403 / 401 rate-limiting and permission barriers from genuine check failures (no false negatives).
- **Badge Artifact:** Always uploads `reposentinel-badge.json` (for [Shields.io endpoint badges](https://shields.io/badges/endpoint-badge)) even if the score triggers a workflow failure threshold.

---

## Local Development & Testing

Run unit tests locally using `pytest`:

```bash
# Install dependencies
pip install -r requirements.txt pytest

# Run unit tests
python3 -m pytest -v tests/
```

---

## Roadmap

- PR comment mode (post score diff on PRs)
- SARIF output for GitHub Security tab
- Additional checks: workflow permissions (least-privilege `GITHUB_TOKEN`), pinned action SHAs, OpenSSF Scorecard cross-check
