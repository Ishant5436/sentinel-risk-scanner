# DoraHacks BUIDL Submission: Sentinel Risk Scanner for Anna AI OS

**Hackathon Portal:** [Anna AI App Builder Program on DoraHacks](https://dorahacks.io/hackathon/anna-ai-app-builder-program/detail)  
**Program Pool:** Up to $80,000 USD Monthly Builder Grants (up to $6,000 launch boost per app)  
**Target Category:** Utilities / AI Safety & Security / System Hardening  
**Submission Timeline:** Open through November 30, 2026  
**Developer:** Ishant Panchal (`Ishant5436` / `ishant.p@somaiya.edu` / Mumbai, India)  
**App Name:** `Sentinel Risk Scanner`  
**App ID on Anna OS:** `315` (Live in Anna App Store under `utilities`)  
**Repository:** [https://github.com/Ishant5436/anna-sentinel-scanner](https://github.com/Ishant5436/anna-sentinel-scanner)  
**License:** Permissive open-source MIT License  

---

## 1. Project Overview & Tagline
* **App Slug:** `sentinel-risk-scanner`
* **Tagline:** `Real-Time Security Auditor, Permission Invariant Verifier & Attack Surface Scanner for Anna AI OS.`

---

## 2. Problem Statement
Autonomous AI operating systems run untrusted plugins, third-party executables, and multi-agent tools with access to user files, network sockets, and shell environments. Users lack visibility into what permissions an agent or tool actually requires versus what it requests, exposing systems to credential theft, privilege escalation, and silent remote execution.

Existing OS utilities fail to provide context-aware risk audits tailored specifically to the lifecycle of agentic AI runtime permissions.

---

## 3. The Solution: Sentinel Risk Scanner on Anna AI OS
Sentinel Risk Scanner operates as an autonomous security watchdog directly inside Anna AI OS:
1. **Dynamic Attack Surface Auditing:** Evaluates active apps and plugins for dangerous host permissions (`shell.execute`, `fs.write_outside_sandbox`, `network.unrestricted`).
2. **Deterministic Risk Scoring Kernel:** Bounded deterministic matrix computing composite risk indices (0–100) with zero arbitrary heuristics.
3. **Automated Remediation Recipes:** Generates least-privilege manifest patches with one-click recommendation delivery into Anna chat.
4. **Holzmann Power of 10 Invariants:** Zero dynamic memory on analysis loops, assertions enforcing state validity, and function lengths $\le 60$ LOC.
5. **Direct Anna Chat Integration:** Transmits security posture summaries directly into active chat threads via `anna.chat.write_message`.
6. **Dual Form-Factor Support:** Responsive interface optimized for both desktop dashboard views and mobile inspection sidebars.

---

## 4. Technical Architecture & Verification

```
+-----------------------------------------------------------------------------------+
|                            Anna AI Operating System                               |
+-----------------------------------------+-----------------------------------------+
                                          | Host API (tools.invoke, chat.write_message)
                                          v
+-----------------------------------------------------------------------------------+
|                      Sentinel Risk Scanner (App ID: 315)                          |
|                                                                                   |
|  +-----------------------+ +------------------------+ +------------------------+  |
|  | Permission Verifier   | | Composite Risk Scorer  | | Least-Privilege Patch  |  |
|  | Manifest AST Analyzer | | Bounded Matrix Metric  | | Remediation Generator  |  |
|  +----------+------------+ +-----------+------------+ +-----------+------------+  |
|             |                          |                          |               |
|             v                          v                          v               |
|  +-----------------------------------------------------------------------------+  |
|  | Executa Plugin: bundled:risk-scanner (JSON-RPC 2.0 stdio daemon)             |  |
|  | - Strictly bounded deterministic audits with zero network telemetry leaks   |  |
|  | - All routines <= 60 lines, assertion density >= 2 (Holzmann Power of 10)  |  |
|  +-----------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------+
```

- **Runtime Compatibility:** Anna App Schema 2 (`manifest.json`) validated under `@anna-ai/app-schema` v0.22.0.
- **Automated Verification:** 13 / 13 passing unit and invariant tests (`uv run pytest tests/`).
- **Store Status:** Successfully published and active on the Anna AI OS Store (App ID 315, Ranked #4 in Utilities).
