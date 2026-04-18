<p align="center">
  <img src="https://img.shields.io/badge/VURA-v1.0.0-1abc9c?style=for-the-badge&logo=shield&logoColor=white" alt="Version"/>
  <img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="License"/>
  <img src="https://img.shields.io/badge/Price-Free-2ecc71?style=for-the-badge" alt="Free"/>
  <img src="https://img.shields.io/badge/Windows-Supported-0078D6?style=for-the-badge&logo=windows&logoColor=white" alt="Windows"/>
  <img src="https://img.shields.io/badge/macOS-Supported-lightgrey?style=for-the-badge&logo=apple&logoColor=white" alt="macOS"/>
  <img src="https://img.shields.io/badge/Linux-Supported-FCC624?style=for-the-badge&logo=linux&logoColor=black" alt="Linux"/>
</p>

<h1 align="center">🛡️ VURA — Vulnerability Reporting AI</h1>

<p align="center">
  <b>AI-Powered Cybersecurity Analysis & Reporting Platform</b><br/>
  <i>Ghost Monitor · Smart HookAll · Multi-Provider AI Engine · Professional Reports</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/GUI-Flet-02569B?style=flat-square&logo=flutter&logoColor=white" alt="Flet"/>
  <img src="https://img.shields.io/badge/AI_Providers-12+-ff6f00?style=flat-square" alt="AI Providers"/>
  <img src="https://img.shields.io/badge/Open_Source-100%25_Free-2ecc71?style=flat-square" alt="Open Source"/>
</p>

---

## 📖 What is VURA?

**VURA** (Vulnerability Reporting AI) is a free, open-source cybersecurity platform that records your terminal sessions, captures tool output (Nmap, Nikto, SQLMap, etc.), and uses AI to generate professional vulnerability reports — all from a single command or a beautiful desktop GUI.

> 🚫 **No subscriptions. No license keys. No paywalls.** VURA is 100% free and open source.

---

## 🖥️ Platform Support

| Platform | Status | Ghost Monitor Method |
|----------|--------|---------------------|
| 🪟 **Windows** | ✅ Fully Supported | PowerShell `Start-Transcript` |
| 🍎 **macOS** | ✅ Fully Supported | Terminal.app / iTerm2 via `osascript` + `script` |
| 🐧 **Linux** | ✅ Fully Supported | Native terminal emulators + `script` |

VURA uses `pathlib` throughout the codebase for cross-platform file handling, and `psutil` for intelligent process detection on Windows, macOS, and Linux.

---

## ✨ Key Features

### 👻 Ghost Monitor — Terminal Recording
- **Start Ghost (`-H`)** — Opens a new terminal with `script` recording enabled
- **HookAll (`-Ha`)** — Reads ALL open interactive terminal sessions simultaneously
- **Stop & Report (`-R`)** — Stops recording and generates an AI-powered report instantly
- **Stop & Collect** — Saves raw data for later analysis on the Analyze page
- **Cross-platform** — Windows (PowerShell Transcript), macOS (osascript + Terminal.app/iTerm2), Linux (native emulators)

### 🧠 Smart Terminal Filtering (psutil-powered)
VURA uses `psutil` to scan running processes and detect only **real interactive terminals**:
- **macOS/Linux:** shells like `zsh`, `bash`, `fish`, `ksh`
- **Windows:** `cmd.exe`, `powershell.exe`, `pwsh.exe`, `WindowsTerminal.exe`

Background processes, IDE terminals, and daemons are automatically filtered out.

The **Exclude Terminal** dialog shows:
- Terminal name in monospace (`ttys000`)
- Active shell badge (`zsh`)
- Process ID
- Already-excluded terminals grayed out

### 🤖 Multi-Provider AI Engine
Supports **12 AI providers** through a unified OpenAI-compatible interface:

| Provider | Provider | Provider |
|----------|----------|----------|
| OpenAI | OpenRouter | Anthropic (via OpenRouter) |
| DeepSeek | Qwen | Google Gemini |
| Groq | Mistral | Together AI |
| Venice AI | GitHub Models | Custom endpoint |

Features: exponential backoff retry (3 attempts), response validation, `<think>` tag stripping, specialized security prompts.

### 📊 Professional Report Generation
- **Formats:** Markdown, PDF (WeasyPrint), DOCX, JSON
- **Languages:** English, Arabic, French, Spanish, German, Japanese, Chinese, Korean, Russian, and more
- **Approaches:** Defense (remediation-focused) or Offense (exploitation-focused)
- **Scan Types:** Terminal, Recon, Executive Summary, Dual (Technical + Executive)
- **Extras:** CVE enrichment, compliance mapping (ISO 27001, NCA ECC, GDPR, PCI-DSS, OWASP Top 10), automated script generation

### 🔍 Recon Engine — Automated Reconnaissance
Runs external tools and aggregates results for AI analysis:
- **Amass** — subdomain enumeration
- **Shodan** — internet-connected device search
- **theHarvester** — OSINT email/subdomain collection
- **Nmap** — port scanning & service detection
- **Whois** — domain registration info

### 📱 Telegram Notifications
Send scan results and alerts directly to Telegram with severity-based formatting:
- Short summary or full report
- PDF file uploads
- Critical/High/Medium/Low vulnerability breakdown

### 🎨 Desktop GUI (Flet)
Beautiful dark-themed desktop application with bilingual support (English/Arabic):
- **Home** — Dashboard with quick stats and actions
- **Monitor** — Full Ghost Monitor controls
- **Analyze** — Manual input, file analysis, ghost data, history
- **Recon** — Domain reconnaissance with tool status
- **Reports** — Archive browser with in-app preview
- **Settings** — AI provider, Telegram, Shodan, language config

---

## 📦 Installation

### 📋 Prerequisites
- **🐍 Python 3.10+** — [Download Python](https://www.python.org/downloads/)
- **🖥️ Windows 10/11**, **macOS**, or **Linux**
- **🔑 An AI API key** (OpenAI, DeepSeek, Groq, etc.)

> [!IMPORTANT]
> **🪟 Windows Users:** If you want to use `git clone` from the terminal, you must install [**Git for Windows**](https://gitforwindows.org/) first. If you don't have Git, see the [📥 No-Git alternative](#-alternative-download-zip-no-git-required) below.

---

### 🍎 Quick Start — macOS / Linux

```bash
git clone https://github.com/hbx1-bx1/Vura.git
cd Vura
bash install.sh
```

### 🪟 Quick Start — Windows

```powershell
git clone https://github.com/hbx1-bx1/Vura.git
cd Vura
.\install.bat
```

### 📥 Alternative: Download ZIP (No Git Required)

If you don't have Git installed, you can download the project directly:

1. 🌐 Go to [**github.com/hbx1-bx1/Vura**](https://github.com/hbx1-bx1/Vura)
2. 📦 Click the green **`<> Code`** button → **`Download ZIP`**
3. 📂 Extract the downloaded `Vura-main.zip` folder
4. 💻 Open **Terminal** (macOS/Linux) or **PowerShell** (Windows) inside the extracted folder
5. ▶️ Run the installer:

**Windows:**
```powershell
.\install.bat
```

**macOS / Linux:**
```bash
bash install.sh
```

---

### ✅ What the installer does

Both installers will:
- ✅ Install all Python dependencies (including Flet & psutil)
- ✅ Create a virtual environment (`.venv` on Windows)
- ✅ Create `config.json` from the template
- ✅ Register the global **`vura`** command so it works from anywhere

After installation, just type **`vura`** from any terminal:

```bash
vura            # 🎨 Launch the Desktop GUI
vura -h         # 📖 Show CLI help
vura -Ch        # 🔧 Configure your AI provider & API key (first time)
```

### 🔧 Manual Installation (Alternative)

<details>
<summary>Click to expand</summary>

**🍎 macOS / Linux:**
```bash
git clone https://github.com/hbx1-bx1/Vura.git
cd Vura
pip install -r requirements.txt
pip install flet
cp config.example.json config.json
python3 main.py -Ch     # Configure API keys
python3 gui.py          # Launch GUI
```

**🪟 Windows (PowerShell):**
```powershell
git clone https://github.com/hbx1-bx1/Vura.git
cd Vura
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
pip install flet
copy config.example.json config.json
python main.py -Ch      # Configure API keys
python gui.py           # Launch GUI
```

</details>

### Dependencies

#### Core (required)
| Package | Version | Purpose |
|---------|---------|---------|
| `rich` | ≥ 13.0.0 | Beautiful CLI output & tables |
| `openai` | ≥ 1.0.0 | Unified AI provider client |
| `cryptography` | ≥ 41.0.0 | Security utilities |
| `weasyprint` | ≥ 60.0 | PDF report generation |
| `markdown` | ≥ 3.5 | Markdown processing |
| `requests` | ≥ 2.31.0 | HTTP client for APIs |
| `python-docx` | ≥ 1.0.0 | DOCX report export |
| `psutil` | ≥ 5.9.0 | Smart terminal detection |
| `flet` | ≥ 0.21.0 | Desktop GUI framework |

#### Optional
| Package | Purpose |
|---------|---------|
| `fastapi` + `uvicorn` | REST API server |
| `streamlit` + `plotly` | Web dashboard |
| `apscheduler` | Scheduled scans |

#### External Tools (for Recon)
| Tool | Install |
|------|---------|
| `nmap` | `brew install nmap` / `apt install nmap` |
| `amass` | `brew install amass` / `apt install amass` |
| `theharvester` | `pip install theharvester` |

---

## 🚀 Usage

> After running `bash install.sh`, the **`vura`** command is available globally.
> - **No arguments** → launches the **Desktop GUI**
> - **With arguments** → runs the **CLI**

### Desktop GUI

```bash
vura
```

Navigate using the sidebar: Home → Monitor → Analyze → Recon → Reports → Settings

### CLI Commands

```bash
# ── Ghost Monitor ──
vura -H                              # Start recording terminal
vura -Ha                             # Record ALL open terminals
vura -e                              # Exclude terminal from hookall
vura -R -F pdf -l Arabic             # Stop & generate PDF report in Arabic

# ── Analysis ──
vura -f scan.log -A offense          # Analyze log file (attack scripts)
vura -m 'nmap output...' -S dual     # Dual report from manual input
vura -p 500 -F md                    # Analyze last 500 history lines

# ── Recon ──
vura -r example.com -F pdf           # Full recon → PDF report

# ── System ──
vura -Ch                             # Configure AI provider & keys
vura -Ck                             # Run system diagnostics
vura -Hy                             # Browse report archive
vura -Rc                             # Retry last failed report
```

---

## 🗂️ Project Structure

```
Vura/
├── main.py                      # CLI entry point
├── gui.py                       # Flet desktop GUI
├── install.sh                   # One-command installer (macOS/Linux)
├── install.bat                  # One-command installer (Windows)
├── config.example.json          # Configuration template
├── requirements.txt             # Python dependencies
├── build.sh                     # Nuitka compilation script
├── app/
│   ├── cli.py                   # CLI command handler
│   ├── core/
│   │   ├── ai_engine.py         # Multi-provider AI engine (12 providers)
│   │   ├── monitor.py           # Ghost Monitor recording engine
│   │   ├── recon.py             # Recon tools (Amass, Shodan, Nmap, etc.)
│   │   └── database.py          # SQLite client & scan database
│   ├── utils/
│   │   ├── config.py            # Configuration manager
│   │   ├── formatter.py         # Report export (MD/PDF/DOCX/JSON + CVE + Compliance)
│   │   ├── notifier.py          # Telegram notifications
│   │   └── logger.py            # Rotating log system
│   └── modules/
│       ├── compliance.py        # ISO 27001, NCA ECC, PCI-DSS, GDPR mapping
│       └── phishing.py          # GoPhish campaign integration
├── api/main.py                  # FastAPI REST API
├── dashboard/app.py             # Streamlit web dashboard
├── data/                        # Logs & session data
└── reports/                     # Generated reports (md/pdf/docx/json/sh)
```

---

## ⚙️ Configuration

Copy the template and add your API key:

```bash
cp config.example.json config.json
```

```json
{
    "provider": "openai",
    "api_key": "sk-...",
    "model_name": "gpt-4o",
    "base_url": "",
    "tg_bot_token": "",
    "tg_chat_id": "",
    "shodan_api_key": "",
    "gophish_api_key": "",
    "gophish_url": "https://localhost:3333"
}
```

Or configure interactively:
```bash
python3 main.py -Ch
```

---

## 💬 Feedback & Community

<p align="center">
  <a href="https://t.me/VURA_Official"><img src="https://img.shields.io/badge/Telegram-VURA__Official-26A5E4?style=for-the-badge&logo=telegram&logoColor=white" alt="Telegram"/></a>
</p>

Join our official Telegram channel for updates, discussions, and support:

👉 **https://t.me/VURA_Official**

- 🐛 **Bug Reports** — Open an issue on GitHub or report on Telegram
- 💡 **Feature Requests** — Open a discussion or reach out on Telegram
- 🤝 **Contributing** — Pull requests are welcome! Fork the repo, create a branch, and submit your PR

---

## 📄 License

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

<p align="center">
  <b>Made by Layth</b><br/>
  <i>VURA — Because security reports shouldn't take hours.</i>
</p>
