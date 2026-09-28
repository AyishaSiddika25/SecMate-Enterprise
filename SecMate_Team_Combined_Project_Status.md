SecMate Enterprise – Team Project Status & DeepTeam Integration
Purpose: Shared project document combining the current SecMate status with the DeepTeam integration work.
Production: https://secmate-enterprise.vercel.app/
---
1. Project Overview
SecMate Enterprise is a security assessment platform for AI agents and AI-based applications.
It is designed to:
Assess AI applications for security vulnerabilities.
Use Red Teaming to generate adversarial attacks.
Test how the target AI responds.
Use Blue Team / defensive techniques to evaluate detection and resistance.
Store assessment evidence and present findings, attack paths, and reports.
The overall goal is to build a connected AI security-testing pipeline.
---
2. How SecMate and DeepTeam Work Together
Component	Main role
DeepTeam	Creates attack prompts, sends them to the target AI, evaluates replies, and returns a risk assessment.
SecMate	Manages the assessment workflow, stores evidence, and displays findings and reports.
Integration Adapter	Converts SecMate settings into the format DeepTeam needs and converts DeepTeam results back into SecMate data.
The adapter is the bridge between SecMate and the DeepTeam assessment engine. The team integration guide describes this separation of responsibilities. fileciteturn11file0L4-L22
Simple flow
```text
SecMate
   ↓
Configure Assessment
   ↓
DeepTeam
   ↓
Generate Attack
   ↓
Target AI
   ↓
AI Response
   ↓
DeepTeam Evaluation
   ↓
SecMate Evidence / Findings / Reports
```
---
3. Red Team and Blue Team
Red Team
Red Team means thinking like an attacker:
> How can the AI system be made to fail?
Examples:
Prompt injection
Prompt leakage
Attempts to bypass security rules
Attempts to expose protected information
Blue Team
Blue Team means thinking like a defender:
> Can the attack be detected, blocked, or resisted?
The defensive side is currently being researched, especially open-source models for prompt-injection and prompt-security detection.
---
4. What DeepTeam Does
DeepTeam is the Red Team / testing component.
It can:
Generate adversarial attack prompts.
Send attacks to an authorized target AI.
Evaluate the target's responses.
Return security results.
DeepTeam is not the defensive model. It is responsible for attacking and evaluating the target.
---
5. Current SecMate Application
The SecMate application contains the main assessment workflow and UI areas:
Dashboard
Endpoints
New Assessment
Live Agent Run
VAPT Findings
Attack Paths
Reports
Settings
The DeepTeam integration is connected to the assessment workflow so an assessment can select DeepTeam as the testing engine.
---
6. DeepTeam Integration Work
The integration work includes:
Installing DeepTeam with SecMate dependencies.
Creating the DeepTeam runner/adapter.
Updating the assessment runner so DeepTeam can be selected.
Adding DeepTeam settings to the assessment page.
Connecting the adapter to the authorized target AI HTTP API.
Running selected DeepTeam vulnerabilities and attacks.
Converting DeepTeam test cases into SecMate exchanges and findings.
Showing converted results in existing SecMate pages.
The team integration guide identifies the main integration files as:
`sec​mate_ui/deepteam_runner.py`
`sec​mate_ui/assessment_runner.py`
`sec​mate_ui/pages/1_New_Assessment.py`
`tests/test_integration_contract.py`
fileciteturn11file0L25-L56
---
7. PromptLeakage Testing
PromptLeakage was verified during the DeepTeam work.
The verified categories include:
`secrets_and_credentials`
`instructions`
`guard_exposure`
`permissions_and_roles`
PromptLeakage testing is intended to identify attempts to make an AI reveal hidden information such as instructions, secrets, guard rules, or permission details.
---
8. SecMate Callback / Adapter
The callback/adapter provides the connection between the DeepTeam attack and the SecMate target.
```text
DeepTeam Attack
      ↓
SecMate Adapter / Callback
      ↓
Target AI
      ↓
Target Response
      ↓
DeepTeam Evaluation
```
The documented target integration supports an authorized HTTP/HTTPS endpoint. The adapter can send attack text through message and prompt fields and handle common response formats and supported authentication methods. fileciteturn11file0L67-L72
---
9. How Results Enter SecMate
The adapter converts DeepTeam results into SecMate's existing data structure:
DeepTeam data	SecMate representation
Input prompt	Exchange evidence
Target reply	Target response
Vulnerability / attack method	Finding category / technique
Score / evaluator reason	Verdict / analyst note
CVSS information	Severity / remediation
This allows the existing SecMate result pages to display the converted output. fileciteturn11file0L75-L87
---
10. Assessment Result States
Each DeepTeam test can end in one of three basic states:
Result	Meaning
Resisted	The target did not follow the attack prompt.
Failed	The target showed a security or safety weakness.
Error	The test could not finish because the target, provider, or runner failed.
fileciteturn11file0L59-L66
---
11. Initial LLM Provider Blocker
During the earlier local DeepTeam execution, the main blocker was the lack of an LLM provider/API key required by DeepTeam's simulator/evaluation stage.
The execution reached the DeepTeam assessment stage but stopped when the provider could not be authenticated.
The deployed integration was later configured with `OPENAI_API_KEY` as a protected Vercel environment variable and redeployed.
API keys are not stored in this document.
---
12. Current Deployment
Production: https://secmate-enterprise.vercel.app
Reported deployment status:
Frontend working
DeepTeam integration panel present
Existing SecMate assessment API working
DeepTeam dependencies available
Provider key stored as a protected environment secret
DeepTeam assessment reported as completed
Reported assessment ID: `SM-4C2E3982`
Reported test cases: 4 generated and evaluated
---
13. Current Defensive Model Research
The next major area is the defensive layer.
DeepTeam provides the attacker/testing side. SecMate needs a defensive component that can help detect or classify malicious prompts and evaluate the target's resistance.
Shortlisted open-source candidates
Model	Source	Current purpose
Granite 4.2 – IBM Granite	https://www.ibm.com/granite/docs/models/granite4-2	Candidate for security-related and AI-agent evaluation/defensive workflows.
PIGuard	https://huggingface.co/leolee99/PIGuard	Candidate focused on prompt-injection defense.
Llama Prompt Guard 2 – 86M	https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M	Lightweight candidate for prompt-injection/jailbreak detection.
Current status: These are shortlisted candidates for evaluation. No defensive model is confirmed as integrated into production.
---
14. Current Pipeline
Working / demonstrated part
```text
SecMate UI
    ↓
Start Assessment
    ↓
DeepTeam
    ↓
Attack Generation
    ↓
SecMate Adapter / Callback
    ↓
Target AI
    ↓
AI Response
    ↓
DeepTeam Evaluation
    ↓
Security Result
```
Remaining integration
```text
DeepTeam Attack
       ↓
Target AI
       ↓
Defensive Model / Blue Team
       ↓
Detection / Classification
       ↓
Security Decision
       ↓
Findings
       ↓
Attack Paths
       ↓
Reports
```
---
15. What Is Completed
✓ SecMate UI completed
✓ SecMate repository available
✓ DeepTeam installed
✓ DeepTeam APIs verified
✓ Red-team API verified
✓ PromptLeakage verified
✓ SecMate callback tested
✓ DeepTeam runner/adapter created
✓ DeepTeam execution tested
✓ LLM provider configured for deployed integration
✓ Vercel deployment completed
✓ DeepTeam assessment reported as completed
✓ DeepTeam results mapped into SecMate exchanges/findings according to the team integration work
The team guide also reports offline contract tests for target rejection, result mapping, credential removal, and legacy compatibility. fileciteturn11file0L122-L129
---
16. Current Work
The remaining work is mainly around completing the defensive and end-to-end pipeline:
Evaluate the shortlisted defensive models.
Select the model based on actual project testing.
Decide where the defensive model should sit in the SecMate pipeline.
Connect the defensive layer with DeepTeam attacks.
Detect whether attacks are malicious and whether the target resisted them.
Connect security results to findings and attack paths.
Ensure results are reflected correctly in reports.
Expand testing beyond PromptLeakage.
Validate the complete workflow with realistic authorized scenarios.
---
17. Target Final Architecture
```text
                    SEC MATE
                       │
                       ▼
                Start Assessment
                       │
                       ▼
                 DEEPTEAM
                 RED TEAM
                       │
                       ▼
              Generate Attacks
                       │
                       ▼
                  TARGET AI
                       │
                       ▼
                AI Response
                       │
                       ▼
             DEFENSIVE MODEL
                 BLUE TEAM
                       │
                       ▼
             Detect / Classify
                       │
                       ▼
               Security Decision
                       │
                       ▼
               DeepTeam Evaluation
                       │
                       ▼
                  Findings
                       │
                       ▼
                Attack Paths
                       │
                       ▼
                   Reports
```
---
18. Current Status Summary
Area	Status
SecMate UI	✓ Completed
SecMate repository	✓ Available
VAPT structure	✓ Available
Red Team structure	✓ Available
Blue Team structure	✓ Available
DeepTeam installation	✓ Completed
DeepTeam API verification	✓ Completed
PromptLeakage testing	✓ Completed
SecMate callback	✓ Tested
DeepTeam adapter/runner	✓ Created
DeepTeam assessment	✓ Reported completed
Vercel deployment	✓ Completed
DeepTeam → SecMate result mapping	✓ Implemented / documented
Defensive model research	🔄 In Progress
Defensive model integration	⏳ Pending
DeepTeam → Defense connection	⏳ Pending
Complete end-to-end pipeline	⏳ Pending
---
19. Final Project Direction
The current SecMate + DeepTeam work establishes the red-team assessment side and the connection between DeepTeam and SecMate.
The next major step is to complete the blue-team/defensive layer and connect it to the existing assessment flow.
Final goal
> **Attack → Target AI → Defense → Evaluation → Findings → Reports**
This creates a single workflow for testing AI security from both the attacker and defender perspectives.
---
20. Production Readiness Note
The team integration guide describes the current connection as suitable for development and demonstrations. Before a production-grade rollout, it identifies additional areas such as approved access control, database storage, background workers, managed secrets, network allowlists, and evidence-retention rules. fileciteturn11file0L131-L134
