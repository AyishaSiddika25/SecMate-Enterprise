# SecMate — Agentic VAPT Integration Project

SecMate is a **Streamlit-based prototype** for AI-assisted security assessment.
It combines three modules into one workflow:

1. **Red Team** — generates adversarial prompts from a fixed template library (prompt injection, jailbreak, data exfiltration, harmful content elicitation, instruction override, context manipulation).
2. **Blue Team** — produces a **simulated** target response for each prompt and evaluates it with rule-based (keyword/pattern) logic to classify it as `Defended`, `Requires Review`, or `Potential Bypass`.
3. **VAPT Analysis** — runs rule-based pattern matching (regex) against analyst-supplied evidence/context text to surface unconfirmed security indicators.

Results are persisted to a local SQLite database and can be reviewed, annotated, and exported as JSON reports.

## ⚠️ What this project actually is (read before using)

This is a **demo / simulation prototype**, not a production penetration-testing tool:

- **No live targets are contacted.** Blue Team responses are deterministic, templated text generated locally in `blue_team/response_evaluator.py` — there is no call to any external AI model or API.
- **Evaluation is rule-based, not model-based.** Verdicts come from keyword/regex matching, not a trained classifier or LLM judge.
- **VAPT findings are unconfirmed indicators.** They flag patterns in text you provide; they are never presented as confirmed vulnerabilities, and none are fabricated — if you submit no evidence, no findings are generated.
- **Login is a demo gate, not real authentication.** Any non-empty email is accepted; there is no identity provider integration, no password verification, and no credential storage.
- **No scanning, exploitation, or network activity occurs.** The app performs no requests against external systems.

If you plan to connect a real target model or a real authentication provider, that requires new integration work beyond what's implemented here — the code is structured (see `core/engine.py`) so a real model call could replace `blue_team.response_evaluator.simulate_target_response` without touching the rest of the app, but **that swap has not been made**.

## Project Structure

```
SecMate-Enterprise/
├── app/
│   ├── streamlit_app.py       # All UI/orchestration logic
│   └── assets/
│       └── styles.css         # Dark navy enterprise theme
├── core/
│   ├── engine.py               # Orchestrates Red Team + Blue Team + VAPT per workflow
│   └── database.py             # SQLite persistence (CRUD + search + metrics)
├── red_team/
│   └── attack_generator.py     # Templated adversarial prompt library
├── blue_team/
│   └── response_evaluator.py   # Simulated response + rule-based evaluation
├── vapt/
│   ├── security_analyzer.py    # Regex-based evidence analysis
│   ├── security_decision.py    # Overall verdict aggregation
│   └── validate_llm_output.py  # Structural validation before persistence
├── config/
│   └── settings.yaml           # App settings (editable from the Settings page)
├── reports/                    # (reserved for future file-based report export)
├── data/                       # SQLite database file lives here (secmate.db)
├── tests/
│   └── test_basic.py           # unittest suite for core/red_team/blue_team/vapt
├── .streamlit/
│   └── config.toml             # Streamlit theme config
└── requirements.txt
```

## Setup (VS Code / local machine)

1. **Open the folder** `SecMate-Enterprise/` in VS Code (File → Open Folder).
2. **Create a virtual environment** (recommended) in a terminal inside VS Code:
   ```bash
   python -m venv venv
   ```
   Activate it:
   - Windows: `venv\Scripts\activate`
   - macOS/Linux: `source venv/bin/activate`
3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
4. **Run the app:**
   ```bash
   python -m streamlit run app/streamlit_app.py
   ```
5. Open the URL Streamlit prints (typically `http://localhost:8501`) in your browser.
6. On the login screen, enter any email and password (demo mode) and click **Sign In**, or click **SSO Demo**.

The SQLite database file is created automatically at `data/secmate.db` on first run — no manual setup needed.

## Feature Summary

- Split-screen demo login page with hero headline and sign-in panel.
- Command Center dashboard: live metrics (computed from actual SQLite records, never hardcoded), risk distribution chart, module cards, recent activity table, quick actions.
- Assessment Operations page:
  - **Create & Run**: configure target, workflow (Red-Blue / VAPT / Combined), intensity (Basic/Standard/Advanced — controls how many attack categories and prompts-per-category are generated), optional evidence text, then execute and save.
  - **History**: search by ID/target, filter by type and review status, inspect full detail, update review status/notes (persists across restarts), delete with a confirmation step, export individual or filtered-set JSON.
- VAPT Findings page: all findings across all assessments, severity-filterable, clearly labeled as unconfirmed rule-based indicators.
- Reports page: list, inspect, and download individual or all assessment reports as JSON.
- Settings page: shows actual current configuration; lets you edit and persist default target/workflow/intensity to `config/settings.yaml`.

## Tests performed before packaging

The following were actually run in the build environment (not just claimed):

- ✅ `python3 -m py_compile` on every `.py` file — all pass.
- ✅ Full `unittest` suite (`tests/test_basic.py`, 11 tests) — all pass, covering: attack generation and intensity scaling, Blue Team refusal/bypass classification, VAPT evidence pattern detection (including the "no evidence → no findings" rule), database save/retrieve/delete (including verifying deleting one record doesn't affect another), and both engine workflows (VAPT-only with no evidence, Combined).
- ✅ End-to-end integration run: executed a real `Combined Security Assessment` through `core.engine.run_assessment`, saved it to a real SQLite file, fetched it back, confirmed dashboard metrics updated correctly, then deleted it and confirmed deletion.
- ✅ `config/settings.yaml` parses cleanly with `PyYAML`.

### Not performed / could not be verified in this environment

- **`streamlit run` was not executed.** The sandbox used to build this project has no network access, so `streamlit` (and `plotly`) could not be `pip install`-ed and the actual Streamlit server/UI could not be launched or visually verified. All Streamlit-specific code (widgets, layout, session state usage) was written carefully against the current Streamlit API and reviewed manually, but you should run it locally as the first thing you do after downloading.
- No browser/visual regression testing (screenshots, responsive breakpoints) was performed, for the same reason.
- No multi-user or concurrent-write testing was performed against SQLite.

If `streamlit run` surfaces an issue, the most likely spots are minor widget-argument mismatches — please report back and it can be patched quickly.

## Known limitations

- SQLite is used directly for the CRUD needs, so filtering (`core/database.search_assessments`) is done in Python after fetching all rows — fine for a local prototype's scale, but not optimized for a large dataset.
- The Red Team prompt library is static/template-based; there's no live LLM call to generate novel attack variants.
- `reports/` is currently a reserved, empty directory — reports are generated on-demand as downloadable JSON rather than written to disk automatically. Extending "Reports" to also write files there would be a small follow-up.
- Settings page currently only makes the *default assessment configuration* editable; the other settings fields (execution mode, storage type, authentication mode) are informational/read-only because they reflect properties of the code itself, not configurable runtime values.
