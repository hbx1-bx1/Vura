> [!CAUTION]
> **Development Status**
>
> This project is currently **under development** but has been **temporarily paused** due to my academic commitments while preparing for the Turkish High School Entrance Exam (LGS).
>
> As a result, some planned features have not yet been completed, and certain parts of the project may be incomplete or behave unexpectedly.
>
> I plan to resume development and continue improving this project after completing my LGS exam, as time permits.
>
> Thank you for your patience, understanding, and support.
---

```
 ██╗   ██╗██╗   ██╗██████╗  █████╗ 
 ██║   ██║██║   ██║██╔══██╗██╔══██╗
 ██║   ██║██║   ██║██████╔╝███████║
 ╚██╗ ██╔╝██║   ██║██╔══██╗██╔══██║
  ╚████╔╝ ╚██████╔╝██║  ██║██║  ██║
   ╚═══╝   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
```

<p align="center">
  <img src="https://img.shields.io/badge/VURA-v2.0.0-1abc9c?style=for-the-badge&logo=shield&logoColor=white" alt="Version"/>
  <img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="License"/>
  <img src="https://img.shields.io/badge/Price-Free-2ecc71?style=for-the-badge" alt="Free"/>
  <br/>
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey?style=flat-square" alt="Platform"/>
  <img src="https://img.shields.io/badge/AI_Providers-13%2B-ff6f00?style=flat-square" alt="AI Providers"/>
  <img src="https://img.shields.io/badge/PTY_Core-True%20Terminal-00d4aa?style=flat-square" alt="PTY"/>
  <img src="https://img.shields.io/badge/Encryption-Fernet%2FAES--128--CBC-9b59b6?style=flat-square" alt="Encryption"/>
  <img src="https://img.shields.io/badge/Recon-Parallel%20Async-0078D6?style=flat-square" alt="Recon"/>
</p>

<p align="center">
  <a href="https://github.com/hbx1-bx1/Vura/stargazers">
    <img src="https://img.shields.io/github/stars/hbx1-bx1/Vura?style=social" alt="Stars"/>
  </a>
  <a href="https://github.com/hbx1-bx1/Vura/network/members">
    <img src="https://img.shields.io/github/forks/hbx1-bx1/Vura?style=social" alt="Forks"/>
  </a>
</p>

<p align="center">
  <b>Autonomous Threat Analysis | Intelligent Reconnaissance | Military-Grade Security</b><br/>
  <i>From terminal to boardroom report -- powered by AI, hardened for enterprise.</i>
</p>

---

## Why VURA?

**VURA** (Vulnerability Reporting AI) is not a script -- it is an **enterprise-grade cybersecurity platform** that records terminal sessions, executes parallel reconnaissance, and generates boardroom-ready vulnerability reports using AI. All in one command. All for free.

| Feature | Traditional Tools | **VURA** |
|---------|:---:|:---:|
| Terminal Monitoring | Manual copy/paste | **Ghost PTY Engine** -- real-time, zero-injection |
| AI Provider Support | Single provider | **13+ providers** with auto-failover |
| Reconnaissance | Sequential, slow | **Parallel Async** -- 5 tools simultaneously |
| API Key Security | Plaintext config | **Fernet AES-128-CBC** -- military-grade encryption |
| Report Generation | Manual formatting | **4 formats x 14 languages** -- one click |
| User Interface | CLI only | **Dark GUI** + full CLI |

**No subscriptions. No license keys. No paywalls.** VURA is 100% free and open source.

---

## Core Architecture

### AI-Powered Orchestration

VURA's AI engine does not just call APIs -- it **orchestrates** them. A circuit breaker pattern monitors provider health in real-time, automatically failing over to backups when a provider degrades.

| Capability | Detail |
|---|---|
| **Provider Coverage** | OpenAI, OpenRouter, Anthropic, DeepSeek, Qwen, Gemini, Groq, Mistral, Together, Venice, GitHub, HuggingFace, Custom |
| **Circuit Breaker** | Auto-disables failing providers after 5 errors, re-tests after 300s recovery window |
| **Retry Strategy** | Exponential backoff with 3 attempts per provider |
| **Graceful Degradation** | If all providers fail, raw analysis still delivers actionable intelligence |
| **Smart Routing** | Provider selection based on scan type (defense/offense/recon/executive) |

```
Provider A --+
Provider B --|-- Circuit Breaker --> Active Provider --> Report
Provider C --+  monitors health       auto-selected
```

### Ghost Monitor & PTY Core

True terminal monitoring at the **pseudo-terminal (PTY) level** -- not screen scraping, not clipboard polling. VURA intercepts output at the kernel layer.

| Layer | Unix (macOS / Linux) | Windows 10/11 |
|---|---|---|
| **PTY Engine** | `pty.fork` + `script` | `pywinpty` / ConPTY / PowerShell Transcript |
| **HookAll** | `psutil`-driven process discovery | `psutil` + process tree traversal |
| **ANSI Stripping** | Centralized `strip_ansi()` | Centralized `strip_ansi_str()` |
| **Injection Prevention** | Arguments passed as list, never interpolated | Subprocess with `shell=False` |
| **Session State** | `TerminalState` enum with thread-safe locking | Same -- unified architecture |

```
Terminal --> PTY Layer --> HookAll Engine --> TerminalSession --> VURA Analysis
            (kernel)        (psutil)           (thread-safe)       (AI)
```

### Parallel Async Recon

Five reconnaissance tools execute **simultaneously** via `ThreadPoolExecutor` -- not sequentially. Per-tool progress callbacks feed real-time updates to the GUI.

| Tool | Purpose | Timeout |
|---|---|---|
| **Amass** | Subdomain enumeration | 600s |
| **Shodan API** | Internet-facing service discovery | 60s |
| **theHarvester** | OSINT email and host collection | 300s |
| **Nmap** | Port scanning and service detection | 600s |
| **Whois** | Domain registration intelligence | 30s |

Results are aggregated in completion order, not execution order -- meaning faster tools appear first in the output.

### Military-Grade Encryption

API keys are not stored in plaintext. VURA uses **Fernet symmetric encryption** (AES-128-CBC with HMAC-SHA256) with a dedicated master key file.

| Component | Detail |
|---|---|
| **Algorithm** | Fernet (AES-128-CBC + HMAC-SHA256) |
| **Master Key** | 32-byte random key stored in `data/.vura_master.key` |
| **Permissions** | `chmod 0o600` (owner-only read/write) |
| **Encrypted Keys** | `api_key`, `shodan_api_key`, `tg_bot_token`, `gophish_api_key` |
| **Detection** | `enc:` prefix identifies encrypted values vs plaintext |
| **Transparency** | Config layer auto-encrypts on save, auto-decrypts on load |

---

## Feature Matrix

### AI Engine
- [x] **13+ provider support** through unified OpenAI-compatible interface
- [x] **Circuit breaker pattern** -- auto-failover when providers degrade
- [x] **Exponential backoff retry** -- 3 attempts with increasing delays
- [x] **Response validation** -- `
</think>

` tag stripping, JSON parsing, format enforcement
- [x] **Specialized security prompts** -- defense, offense, recon, executive summary

### Terminal Monitoring
- [x] **Ghost Mode** (`-H`) -- opens new terminal with PTY recording
- [x] **HookAll** (`-Ha`) -- monitors ALL interactive terminals simultaneously
- [x] **Exclude Dialog** -- selectively exclude terminals from HookAll
- [x] **Cross-platform** -- Windows, macOS, Linux with platform-specific PTY backends
- [x] **Injection-safe** -- all commands passed as argument lists, never string-interpolated

### Professional Reports
| Format | Content | Languages |
|---|---|---|
| **Markdown** | Full analysis with CVEs | EN, AR, FR, ES, DE, JA, ZH, KO, RU, PT, IT, TR, NL, HI |
| **PDF** | WeasyPrint-rendered | Same |
| **DOCX** | python-docx generated | Same |
| **JSON** | Structured data export | Same |

- [x] **CVE enrichment** -- automatic vulnerability identifier expansion
- [x] **Compliance mapping** -- ISO 27001, NCA ECC, GDPR, PCI-DSS, OWASP Top 10
- [x] **Script generation** -- automated remediation scripts (optional)
- [x] **Dual reports** -- technical + executive summary in one scan

### Reconnaissance
- [x] **Parallel execution** -- 5 tools via `ThreadPoolExecutor`
- [x] **Per-tool progress** -- real-time callbacks to GUI progress bars
- [x] **Graceful degradation** -- one tool failure does not stop others
- [x] **Output persistence** -- all results saved to `data/recon/`
- [x] **AI aggregation** -- combined results sent to AI for unified analysis

### Desktop GUI (Flet)
- [x] **Dark theme** -- `#1abc9c` teal accent on `#0a0a1a` background
- [x] **Bilingual** -- full English/Arabic toggle with 99 translation keys
- [x] **6 pages** -- Home, Monitor, Analyze, Recon, Reports, Settings
- [x] **Page caching** -- instant navigation with state preservation
- [x] **Encryption status** -- visual indicator for config security
- [x] **Modular architecture** -- components, engine, pages separated

### Telegram Integration
- [x] **Severity-based formatting** -- Critical/High/Medium/Low breakdowns
- [x] **PDF file uploads** -- full report sent as attachment
- [x] **Short summary mode** -- quick alert with key findings

---

## Installation

### Prerequisites
- **Python 3.10+** -- [Download Python](https://www.python.org/downloads/)
- **Windows 10/11**, **macOS**, or **Linux**
- **An AI API key** (Gemini, OpenAI, DeepSeek, etc.)

### macOS / Linux -- Quick Start

```bash
git clone https://github.com/hbx1-bx1/Vura.git
cd Vura
bash install.sh
```

### Windows -- Quick Start

```powershell
git clone https://github.com/hbx1-bx1/Vura.git
cd Vura
.\install.bat
```

### No Git? Download ZIP

1. Go to **[github.com/hbx1-bx1/Vura](https://github.com/hbx1-bx1/Vura)**
2. Click **Code** -> **Download ZIP**
3. Extract and run the installer from the folder:
   - **Windows:** `.\install.bat`
   - **macOS/Linux:** `bash install.sh`

### What the installer does
- Installs all dependencies (Flet, cryptography, psutil, WeasyPrint, etc.)
- Creates an isolated virtual environment
- Generates `config.json` from template
- Registers the global **`vura`** command

After installation:
```bash
vura            # Launch the Desktop GUI
vura -h         # Show CLI help
vura -Ch        # Configure your AI provider & API key
```

<details>
<summary><b>Full dependency list</b></summary>

#### Core
| Package | Purpose |
|---|---|
| `rich` >= 13.0.0 | CLI output and tables |
| `openai` >= 1.0.0 | Unified AI provider client |
| `cryptography` >= 41.0.0 | Fernet encryption for API keys |
| `weasyprint` >= 60.0 | PDF report generation |
| `markdown` >= 3.5 | Markdown processing |
| `requests` >= 2.31.0 | HTTP client for APIs |
| `python-docx` >= 1.0.0 | DOCX report export |
| `psutil` >= 5.9.0 | Smart terminal detection |
| `flet` >= 0.28.0 | Desktop GUI framework |

#### Optional (Recon tools)
| Tool | Install |
|---|---|
| `nmap` | `brew install nmap` / `apt install nmap` |
| `amass` | `brew install amass` / `apt install amass` |
| `theharvester` | `pip install theharvester` |

</details>

---

## Usage

### Desktop GUI
```bash
vura
```
Navigate: **Home** -> **Monitor** -> **Analyze** -> **Recon** -> **Reports** -> **Settings**

### CLI Commands

```bash
# -- Ghost Monitor --
vura -H                              # Start PTY recording
vura -Ha                             # Monitor ALL open terminals
vura -e                              # Exclude terminal from HookAll
vura -R -F pdf -l Arabic             # Stop & generate PDF report in Arabic

# -- Analysis --
vura -f scan.log -A offense          # Analyze log file (attack perspective)
vura -m 'nmap output...' -S dual     # Dual report from manual input
vura -p 500 -F md                    # Analyze last 500 history lines

# -- Reconnaissance --
vura -r example.com -F pdf           # Parallel recon -> PDF report

# -- System --
vura -Ch                             # Configure AI provider & keys
vura -Ck                             # Run system diagnostics
vura -Hy                             # Browse report archive
vura -Rc                             # Retry last failed report
```

---

## Project Structure

```
Vura/
|-- main.py                      # CLI entry point
|-- run_gui.py                   # Flet desktop GUI launcher
|-- install.sh / install.bat     # One-command installers
|-- config.example.json          # Configuration template
|-- requirements.txt             # Python dependencies
|
|-- gui/                         # Modular GUI package
|   |-- main.py                  # App bootstrap + NavigationRail routing
|   |-- theme.py                 # Dark theme colors & typography
|   |-- i18n.py                  # Translation engine (14 languages)
|   |-- components/              # Reusable UI building blocks
|   |-- engine/                  # Ghost/HookAll hybrid engine
|   +-- pages/                   # Page builders (6 pages)
|
|-- app/
|   |-- cli.py                   # CLI command handler
|   |-- core/
|   |   |-- ai_engine.py         # Multi-provider AI + circuit breaker
|   |   |-- monitor.py           # Compatibility wrapper
|   |   |-- terminal/            # PTY core (session, unix_pty, win_conpty)
|   |   |-- recon.py             # Parallel recon engine
|   |   +-- database.py          # SQLite client
|   |-- utils/
|   |   |-- config.py            # Config with transparent encryption
|   |   |-- crypto.py            # Fernet key vault
|   |   |-- formatter.py         # Report export (MD/PDF/DOCX/JSON)
|   |   |-- notifier.py          # Telegram notifications
|   |   +-- logger.py            # Rotating log system
|   +-- modules/
|       |-- compliance.py        # ISO 27001, NCA ECC, PCI-DSS, GDPR
|       +-- phishing.py          # GoPhish campaign integration
|
|-- api/main.py                  # FastAPI REST API (optional)
|-- dashboard/app.py             # Streamlit web dashboard (optional)
|-- data/                        # Session logs, master key, recon output
+-- reports/                     # Generated reports (md/pdf/docx/json/sh)
```

---

## Configuration

```bash
cp config.example.json config.json
```

```json
{
    "provider": "gemini",
    "api_key": "YOUR_API_KEY",
    "model_name": "gemini-2.0-flash",
    "base_url": "",
    "tg_bot_token": "",
    "tg_chat_id": "",
    "shodan_api_key": "",
    "gophish_api_key": "",
    "gophish_url": "https://localhost:3333"
}
```

**Note:** Sensitive keys (`api_key`, `shodan_api_key`, `tg_bot_token`, `gophish_api_key`) are automatically encrypted with Fernet on save. The plaintext you see in `config.json` after saving will be prefixed with `enc:` -- VURA decrypts them transparently on load.

Or configure interactively:
```bash
vura -Ch
```

---

## Roadmap

| Phase | Feature | Status |
|---|---|---|
| **v1.0** | CLI foundation, basic AI engine, Ghost Monitor | Released |
| **v1.5** | Multi-provider AI, HookAll, Recon engine | Released |
| **v2.0** | PTY Core, modular GUI, encryption, parallel recon | **Current** |
| **v2.1** | Plugin system, real-time vulnerability feed | Planned |
| **v2.5** | REST API server, scheduled scans, webhook alerts | Planned |
| **v3.0** | Multi-user support, team dashboards, SSO | Planned |
| **Future** | Autonomous pentesting agent, CI/CD integration, compliance dashboard | Vision |

---

## Contributing

Contributions are welcome. Here is how:

1. **Fork** the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit your changes: `git commit -m 'Add amazing feature'`
4. Push to the branch: `git push origin feature/amazing-feature`
5. Open a **Pull Request**

### Development Setup
```bash
git clone https://github.com/hbx1-bx1/Vura.git
cd Vura
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install flet
```

### Code Style
- PEP 8 compliant
- Type hints required for all public functions
- Docstrings for modules, classes, and public methods
- No hardcoded secrets or API keys

---

## License

```
MIT License

Copyright (c) 2024-2026 Layth

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## Community

<p align="center">
  <a href="https://t.me/VURA_Official">
    <img src="https://img.shields.io/badge/Telegram-VURA__Official-26A5E4?style=for-the-badge&logo=telegram&logoColor=white" alt="Telegram"/>
  </a>
</p>

Join our official Telegram channel for updates, discussions, and support:

**[https://t.me/VURA_Official](https://t.me/VURA_Official)**

- **Bug Reports** -- Open an issue on GitHub or message on Telegram
- **Feature Requests** -- Start a discussion or reach out directly
- **Contributing** -- Pull requests are always welcome

---

<p align="center">
  <b>Built with precision by Layth</b><br/>
  <i>VURA -- Because security reports should not take hours.</i>
</p>

<p align="center">
  <sub>If VURA helped you, consider starring the repo -- it helps others find it.</sub>
</p>
