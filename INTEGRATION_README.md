# SecMate Enterprise + DeepTeam local integration demo

This folder is an isolated demo copy of SecMate Enterprise. It keeps the original
SecMate assessment engine intact and adds DeepTeam 1.0.9 as an optional AI red-team
stage. This demo is intentionally **local only** and has not been deployed.

## Folder layout

The repository is self-contained for deployment. DeepTeam is installed from the
pinned Paramount-Assure Git commit declared in `api/pyproject.toml` and
`requirements-integration.txt`. A vendored checkout is optional for offline
development and may use either of these layouts:

```text
SecMate-Enterprise/
├── integrations/              # adapter and composition layer
├── api/index.py               # existing API plus two opt-in actions
├── demo_server.py             # local frontend/API server
├── index.html                 # existing SecMate UI plus DeepTeam controls
└── vendor/deepteam/           # optional local DeepTeam checkout
```

## How the combination works

```text
SecMate UI
  -> POST /api action=deepteam_assess
  -> existing SecMate Combined Security Assessment
  -> DeepTeam red_team(...) against an authorized target callback
  -> normalize DeepTeam cases/findings into SecMate contracts
  -> recalculate verdict, posture, correlation, mappings and replay manifest
  -> validate and return one combined assessment record
```

The normal `action=assess` and `action=compare` contracts are unchanged.

## Target modes

- `secmate_demo`: DeepTeam evaluates the existing deterministic SecMate demo callback.
  Results are explicitly marked as simulated and must not be presented as a production scan.
- `http`: an analyst enters an approved HTTPS API endpoint in the UI. The hostname
  must be listed in `DEEPTEAM_ALLOWED_TARGET_HOSTS`; authentication remains in
  server-side environment variables and is never accepted from the browser.
  The API and browser never accept or return the bearer token.

Only scan systems and models that you own or are explicitly authorized to test.

## Local setup (PowerShell)

From `secmate-deepteam-demo`:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-integration.txt
$env:OPENAI_API_KEY = "your-key"
python demo_server.py --host 127.0.0.1 --port 4175
```

Open <http://127.0.0.1:4175>. Enable **DeepTeam AI red teaming** in the
assessment form to use the combined flow. Without the checkbox, SecMate behaves
exactly as before.

For HTTP mode, set `DEEPTEAM_ALLOWED_TARGET_HOSTS` and the optional authentication/
field settings shown in `.env.example`, then select **HTTP API endpoint** in the UI.
`DEEPTEAM_TARGET_URL` can still provide a server-managed default endpoint.

## API actions

- `POST /api` with `{"action":"deepteam_status"}`: safe readiness metadata only.
- `POST /api` with `{"action":"deepteam_assess", ...}`: combined SecMate + DeepTeam run.
- Existing `assess` and `compare` actions remain backward compatible.

Example request:

```json
{
  "action": "deepteam_assess",
  "target": "authorized-demo-agent",
  "intensity": "Basic",
  "evidence": "",
  "deepteam": {
    "target_mode": "secmate_demo",
    "vulnerabilities": ["PromptLeakage", "PIILeakage"],
    "attacks": ["PromptInjection", "Roleplay"],
    "attacks_per_vulnerability_type": 1
  }
}
```

## Honest readiness and limitations

- DeepTeam requires its dependencies and a valid evaluator/simulator model credential.
- No fabricated DeepTeam result is returned when dependencies or credentials are absent;
  the API returns a clear `deepteam_unavailable` error.
- The existing SecMate demo callback is deterministic and simulated by design.
- DeepTeam can be computationally expensive and long-running. This demo uses a local
  synchronous HTTP request and is not configured for Vercel serverless execution.
- No deployment was performed, as requested.

## Checks

```powershell
python -m pytest tests -q
python -m compileall api core integrations red_team blue_team vapt demo_server.py
```
