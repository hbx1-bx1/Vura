"""
VURA AI Engine — Phase 4 (Enhanced Error Handling + Failover)
═══════════════════════════════════════════════════════════════════════════
Multi-provider AI analysis engine with:
  - Circuit breaker pattern (tracks failures, auto-disables bad providers)
  - Automatic provider failover (tries backups when primary fails)
  - Graceful degradation (never crashes, always returns usable output)
  - Response validation and retry with exponential backoff
"""

import time
import re
import json
import threading
from datetime import datetime, timedelta
from typing import Optional

import requests
from openai import (
    OpenAI, APIConnectionError, RateLimitError,
    APIStatusError, APITimeoutError,
)
from rich.console import Console
from rich.panel import Panel
from app.utils.config import load_api_config

console = Console()

# ══════════════════════════════════════════════════════════════════════
# PROVIDER REGISTRY
# ══════════════════════════════════════════════════════════════════════

PROVIDER_ENDPOINTS = {
    "openai":      "https://api.openai.com/v1",
    "openrouter":  "https://openrouter.ai/api/v1",
    "anthropic":   "https://openrouter.ai/api/v1",
    "deepseek":    "https://api.deepseek.com/v1",
    "qwen":        "https://dashscope.aliyuncs.com/compatible-mode/v1",
    "gemini":      "https://generativelanguage.googleapis.com/v1beta/openai/",
    "groq":        "https://api.groq.com/openai/v1",
    "mistral":     "https://api.mistral.ai/v1",
    "together":    "https://api.together.xyz/v1",
    "venice":      "https://api.venice.ai/api/v1",
    "github":      "https://models.inference.ai.azure.com",
    "huggingface": "https://api-inference.huggingface.co/models/Qwen/Qwen2.5-Coder-32B-Instruct/v1",
    "custom":      None,
}

HUGGINGFACE_ENDPOINT = (
    "https://api-inference.huggingface.co/models/"
    "Qwen/Qwen2.5-Coder-32B-Instruct/v1/chat/completions"
)
HUGGINGFACE_DEFAULT_MODEL = "Qwen/Qwen2.5-Coder-32B-Instruct"

PROVIDER_SETTINGS = {
    "openai":      {"timeout": 120, "max_tokens": 4096, "temperature": 0.3},
    "openrouter":  {"timeout": 150, "max_tokens": 4096, "temperature": 0.3},
    "anthropic":   {"timeout": 150, "max_tokens": 4096, "temperature": 0.3},
    "deepseek":    {"timeout": 180, "max_tokens": 4096, "temperature": 0.3},
    "qwen":        {"timeout": 120, "max_tokens": 4096, "temperature": 0.3},
    "gemini":      {"timeout": 120, "max_tokens": 8192, "temperature": 0.3},
    "groq":        {"timeout": 60,  "max_tokens": 4096, "temperature": 0.3},
    "mistral":     {"timeout": 120, "max_tokens": 4096, "temperature": 0.3},
    "together":    {"timeout": 120, "max_tokens": 4096, "temperature": 0.3},
    "venice":      {"timeout": 120, "max_tokens": 4096, "temperature": 0.3},
    "github":      {"timeout": 120, "max_tokens": 4096, "temperature": 0.3},
    "huggingface": {"timeout": 180, "max_tokens": 4096, "temperature": 0.3},
}

_DEFAULT_SETTINGS = {"timeout": 120, "max_tokens": 4096, "temperature": 0.3}

RECOMMENDED_MODELS = {
    "openai":     "gpt-4o, gpt-4-turbo, gpt-3.5-turbo",
    "openrouter": "anthropic/claude-sonnet-4-6, google/gemini-2.0-flash-exp:free, deepseek/deepseek-chat",
    "deepseek":   "deepseek-chat, deepseek-coder",
    "qwen":       "qwen-max, qwen-turbo, qwen-plus",
    "gemini":     "gemini-2.0-flash, gemini-1.5-pro",
    "groq":       "llama-3.3-70b-versatile, mixtral-8x7b-32768",
    "mistral":    "mistral-large-latest, codestral-latest",
    "together":   "meta-llama/Llama-3-70b-chat-hf",
    "venice":     "deepseek-r1-671b, llama-3.3-70b",
    "github":     "DeepSeek-R1, gpt-4o",
    "huggingface":"Qwen/Qwen2.5-Coder-32B-Instruct (default), meta-llama/Llama-3.3-70B-Instruct",
}

# ── Retry Configuration ──────────────────────────────────────────────
MAX_RETRIES     = 3
RETRY_BASE_WAIT = 2
RETRY_BACKOFF   = 2

INPUT_WARN_CHARS  = 100_000
INPUT_LIMIT_CHARS = 400_000

# ── Circuit Breaker Configuration ────────────────────────────────────
CIRCUIT_FAILURE_THRESHOLD = 5    # failures before opening circuit
CIRCUIT_RECOVERY_TIME = 300      # seconds before allowing retries
CIRCUIT_HALF_OPEN_LIMIT = 1      # test requests in half-open state


# ══════════════════════════════════════════════════════════════════════
# Circuit Breaker
# ══════════════════════════════════════════════════════════════════════

class CircuitState:
    CLOSED = "closed"       # Normal operation
    OPEN = "open"           # Provider disabled due to failures
    HALF_OPEN = "half_open" # Testing if provider recovered


class CircuitBreaker:
    """
    Circuit breaker for AI providers.

    States:
      CLOSED   → normal, track failures
      OPEN     → provider disabled, return immediately
      HALF_OPEN → allow 1 test request, if succeeds → CLOSED, else → OPEN

    Thread-safe: all state transitions protected by lock.
    """

    def __init__(
        self,
        failure_threshold: int = CIRCUIT_FAILURE_THRESHOLD,
        recovery_time: int = CIRCUIT_RECOVERY_TIME,
    ):
        self._lock = threading.Lock()
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._failure_threshold = failure_threshold
        self._recovery_time = recovery_time
        self._last_failure_time: Optional[datetime] = None
        self._total_failures = 0
        self._total_successes = 0

    @property
    def state(self) -> str:
        with self._lock:
            self._check_recovery()
            return self._state

    @property
    def failure_count(self) -> int:
        with self._lock:
            return self._failure_count

    @property
    def stats(self) -> dict:
        with self._lock:
            return {
                "state": self._state,
                "failures": self._failure_count,
                "total_failures": self._total_failures,
                "total_successes": self._total_successes,
            }

    def can_execute(self) -> bool:
        """Check if a request is allowed through the circuit."""
        with self._lock:
            self._check_recovery()
            if self._state == CircuitState.CLOSED:
                return True
            if self._state == CircuitState.OPEN:
                return False
            # HALF_OPEN — allow one test request
            return True

    def record_success(self) -> None:
        """Record a successful request."""
        with self._lock:
            self._total_successes += 1
            if self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.CLOSED
                self._failure_count = 0
            elif self._state == CircuitState.CLOSED:
                self._failure_count = 0

    def record_failure(self) -> None:
        """Record a failed request."""
        with self._lock:
            self._failure_count += 1
            self._total_failures += 1
            self._last_failure_time = datetime.now()

            if self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.OPEN
            elif self._failure_count >= self._failure_threshold:
                self._state = CircuitState.OPEN

    def reset(self) -> None:
        """Manually reset the circuit breaker."""
        with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._last_failure_time = None

    def _check_recovery(self) -> None:
        """Check if enough time has passed to try a failed provider."""
        if (
            self._state == CircuitState.OPEN
            and self._last_failure_time
            and (datetime.now() - self._last_failure_time).total_seconds()
                >= self._recovery_time
        ):
            self._state = CircuitState.HALF_OPEN


# ── Global circuit breakers per provider ─────────────────────────────
_circuit_breakers: dict[str, CircuitBreaker] = {}
_cb_lock = threading.Lock()


def _get_breaker(provider: str) -> CircuitBreaker:
    """Get or create circuit breaker for a provider."""
    with _cb_lock:
        if provider not in _circuit_breakers:
            _circuit_breakers[provider] = CircuitBreaker()
        return _circuit_breakers[provider]


def get_all_circuit_stats() -> dict:
    """Get circuit breaker stats for all providers."""
    with _cb_lock:
        return {
            name: cb.stats
            for name, cb in _circuit_breakers.items()
        }


def reset_circuit_breaker(provider: str) -> None:
    """Manually reset a provider's circuit breaker."""
    _get_breaker(provider).reset()


# ══════════════════════════════════════════════════════════════════════
# SYSTEM PROMPTS
# ══════════════════════════════════════════════════════════════════════

PROMPTS = {
    "terminal": """You are VURA — an elite penetration testing AI engine reporting on actions executed in a live terminal session.

## IDENTITY RULES (NEVER BREAK):
- You ARE the penetration tester. You executed these commands. Say "We executed...", "We discovered..."
- NEVER say: "logs", "سجلات", "the user provided", "I noticed", "it appears", "based on the logs"
- The ENTIRE report MUST be in **{language}**. Only keep technical commands, CVE IDs, and tool names in English.

## ANALYSIS METHODOLOGY:
1. Parse every command, flag, and output line in the terminal data.
2. Cross-reference discovered services/versions with known CVE databases.
3. Classify severity using CVSS v3.1 scoring logic (Critical ≥9.0, High ≥7.0, Medium ≥4.0, Low <4.0).
4. Chain related findings — e.g., if port 22 runs OpenSSH 7.4 AND default creds work, that's a compound finding.

## REPORT STRUCTURE:

### 1. Terminal Execution Summary
- What target(s) were scanned
- Which tools were used and with what flags
- Timeline of the engagement

### 2. Vulnerability Findings
For EACH vulnerability found:
| Field | Detail |
|-------|--------|
| **CVE ID** | CVE-XXXX-XXXXX (or "No CVE — Misconfiguration") |
| **Severity** | Critical / High / Medium / Low |
| **CVSS Score** | Estimated score based on impact |
| **Component** | Service name + exact version |
| **Description** | What the vulnerability allows an attacker to do |
| **Evidence** | Exact terminal output proving this finding |
| **Remediation** | Specific fix (not generic advice) |

### 3. Risk Assessment
- Overall risk rating with justification
- Most critical attack path identified
- Data/systems at risk

### 4. Prioritized Recommendations
- P1 (Fix within 24h): Critical findings
- P2 (Fix within 1 week): High findings
- P3 (Fix within 1 month): Medium/Low findings

{script_instruction}""",

    "recon": """You are VURA — an elite reconnaissance AI analyst working for a professional red team operation.

## IDENTITY RULES (NEVER BREAK):
- You ARE the recon analyst. Your team collected this data. Say "Our team discovered...", "We identified..."
- NEVER say: "the user provided", "based on the data given", "I was given"
- The ENTIRE report MUST be in **{language}**. Keep domain names, IPs, and technical terms in English.

## ANALYSIS METHODOLOGY:
1. Correlate data from multiple recon sources (Amass, Shodan, theHarvester, DNS records).
2. Identify patterns — shared hosting, cloud providers, technology stack.
3. Map the complete attack surface from external perspective.
4. Prioritize findings by exploitability, not just quantity.

## REPORT STRUCTURE:

### 1. Target Intelligence Overview
- Organization identity confirmed
- Primary domains and IP ranges
- Hosting infrastructure (cloud provider, CDN, WAF detected)

### 2. Attack Surface Map
**Subdomains** (grouped by function):
- Production: www, app, portal
- Development/Staging: dev, staging, test, uat (HIGH RISK if exposed)
- Infrastructure: vpn, mail, dns, monitoring
- API: api, graphql, ws

**Open Ports & Services:**
| IP | Port | Service | Version | Risk |
|----|------|---------|---------|------|

**Technology Fingerprint:**
- Web servers, frameworks, CMS, languages, databases detected

### 3. Exposed Assets & Data Leaks
- Email addresses (grouped: executives, developers, support)
- Exposed admin panels, debug endpoints, API docs
- Cloud storage misconfigurations (S3 buckets, Azure blobs)
- Source code repositories, backup files, .env files
- SSL/TLS certificate intelligence (expiry, SANs, issuer)

### 4. Vulnerability Indicators
- Known CVEs matching discovered service versions
- Default credentials likely to work
- Missing security headers

### 5. OSINT Findings
- Breached credentials from public databases
- Social media intelligence
- Job postings revealing internal technology

### 6. Prioritized Attack Vectors
Ranked by probability of success:
| Priority | Vector | Target | Success Likelihood |
|----------|--------|--------|--------------------|

{script_instruction}""",

    "executive": """You are VURA — a senior cybersecurity consultant preparing a confidential executive briefing for C-level management.

## WRITING RULES (NEVER BREAK):
- The ENTIRE briefing MUST be in **{language}**.
- ZERO technical jargon. No CVE IDs, no command outputs, no code, no port numbers.
- Write as if presenting to a CEO who has 5 minutes to read this.
- Maximum 2 pages. Every sentence must earn its place.
- Translate risk into MONEY, REPUTATION, and COMPLIANCE language.

## BRIEFING STRUCTURE:

### 1. Security Assessment Summary
- 2-3 sentences: What was tested, scope, and timeframe.
- One sentence: Overall security posture (Strong / Needs Improvement / Critical Gaps).

### 2. Key Findings at a Glance

| Risk Level | Issues Found | Business Impact |
|------------|-------------|-----------------|
| Critical | X | [Business impact in plain language] |
| High | X | [Business impact in plain language] |
| Medium | X | [Business impact in plain language] |

### 3. What's at Stake
Answer in plain business language:
- **Data Exposure**: What sensitive data could be stolen?
- **Financial Impact**: Estimated cost of a breach
- **Reputation Risk**: Would this make the news?
- **Regulatory Risk**: Are we violating any regulations?

### 4. Recommended Actions
**Immediate (24-48 hours):**
- [Action items that prevent the most likely attack NOW]

**Short-term (1-2 weeks):**
- [Improvements that significantly reduce risk]

**Strategic (1-3 months):**
- [Long-term security posture improvements]

### 5. Investment & Next Steps
- High-level effort/cost estimate
- Recommended follow-up engagement

DO NOT include any Bash scripts, code blocks, technical commands, or CVE IDs in this briefing.""",
}

SCRIPT_INSTRUCTIONS = {
    "offense_yes": """
### 5. Exploitation Script
AT THE VERY END of the report, provide a complete Linux Bash script to EXPLOIT the discovered vulnerabilities.
Rules for the script:
- Enclose ONLY in ```bash tags
- Start with `#!/bin/bash`
- Add comments explaining each exploit step
- Include safety checks (target validation, confirmation prompts)""",

    "defense_yes": """
### 5. Remediation Script
AT THE VERY END of the report, provide a complete Linux Bash script to PATCH and DEFEND against the discovered vulnerabilities.
Rules for the script:
- Enclose ONLY in ```bash tags
- Start with `#!/bin/bash`
- Add comments explaining each patch step
- Include rollback instructions in comments
- Use `set -euo pipefail` for safety""",

    "no_script": """
### 5. IMPORTANT
DO NOT generate any Bash scripts, code blocks, or executable commands. Focus ONLY on analysis, findings, and recommendations.""",
}


# ══════════════════════════════════════════════════════════════════════
# Internal Helpers
# ══════════════════════════════════════════════════════════════════════

def _validate_config(config):
    """Validate config before connecting. Returns (is_valid, error_message)."""
    if not config:
        return False, "config.json is empty or missing. Run: vura -Ch"

    provider = config.get("provider", "").strip().lower()
    api_key = config.get("api_key", "").strip()

    if not provider:
        return False, "No 'provider' set in config.json. Run: vura -Ch"
    if not api_key:
        return False, f"No 'api_key' set for provider '{provider}'. Run: vura -Ch"
    if provider == "custom" and not config.get("base_url", "").strip():
        return False, "provider='custom' requires 'base_url' in config.json"
    if provider not in PROVIDER_ENDPOINTS:
        supported = ", ".join(sorted(PROVIDER_ENDPOINTS.keys()))
        return False, f"Unknown provider '{provider}'. Supported: {supported}"

    if provider == "openrouter" and not api_key.startswith("sk-or-"):
        console.print(
            "[dim yellow][!] VURA: OpenRouter keys usually start with "
            "'sk-or-'. Double-check your key.[/dim yellow]"
        )
    if provider == "openai" and not api_key.startswith("sk-"):
        console.print(
            "[dim yellow][!] VURA: OpenAI keys usually start with "
            "'sk-'. Double-check your key.[/dim yellow]"
        )

    return True, ""


def _build_headers(provider):
    """Build HTTP headers per provider."""
    if provider in ("openrouter", "anthropic"):
        return {
            "HTTP-Referer": "https://vura-sec.com",
            "X-Title": "VURA Security Engine",
        }
    return None


def _resolve_base_url(provider, config):
    """Resolve base_url. Returns None for custom provider without URL."""
    if provider == "custom":
        return config["base_url"].strip()
    return PROVIDER_ENDPOINTS[provider]


def _estimate_tokens(text):
    """Estimate token count (~4 chars per token)."""
    return len(text) // 4


def _check_input_size(raw_data, provider):
    """Check input size limits. Returns (can_proceed, warning)."""
    char_count = len(raw_data)
    est_tokens = _estimate_tokens(raw_data)

    if char_count > INPUT_LIMIT_CHARS:
        return False, (
            f"Input too large: ~{est_tokens:,} tokens ({char_count:,} chars). "
            f"Maximum: ~{_estimate_tokens('x' * INPUT_LIMIT_CHARS):,} tokens. "
            f"Trim your data or split into multiple analyses."
        )

    if char_count > INPUT_WARN_CHARS:
        console.print(
            f"[dim yellow][!] VURA: Large input (~{est_tokens:,} tokens). "
            f"Some providers may truncate. Processing anyway...[/dim yellow]"
        )

    return True, ""


def _build_system_prompt(scan_type, language, approach,
                         include_script, output_format):
    """Build system prompt based on scan type."""
    if output_format == "json":
        return (
            f"You are VURA security analysis engine. "
            f"Extract ALL vulnerabilities from the data.\n"
            f"Language: {language}.\n"
            f"Respond ONLY with a valid JSON array. "
            f"No markdown, no explanation, no preamble.\n"
            f"Format: [{{\"cve\": \"CVE-XXXX-XXXXX\", "
            f"\"severity\": \"Critical|High|Medium|Low\", "
            f"\"component\": \"...\", \"vulnerability\": \"...\", "
            f"\"remediation\": \"...\"}}]\n"
            f"If no vulnerabilities found, return: []"
        )

    if scan_type == "executive":
        return PROMPTS["executive"].format(language=language)

    prompt_template = PROMPTS.get(scan_type, PROMPTS["terminal"])

    if not include_script:
        script_instruction = SCRIPT_INSTRUCTIONS["no_script"]
    elif approach == "offense":
        script_instruction = SCRIPT_INSTRUCTIONS["offense_yes"]
    else:
        script_instruction = SCRIPT_INSTRUCTIONS["defense_yes"]

    return prompt_template.format(
        language=language, script_instruction=script_instruction
    )


def _build_user_message(raw_data, scan_type, report_context=""):
    """Build user message with label."""
    labels = {
        "terminal":  "=== TERMINAL SESSION OUTPUT ===",
        "recon":     "=== RECONNAISSANCE DATA ===",
        "executive": "=== SECURITY ASSESSMENT DATA ===",
    }
    label = labels.get(scan_type, "=== TERMINAL SESSION OUTPUT ===")

    context_block = ""
    if report_context:
        context_block = (
            "=== REPORT CONTEXT ===\n"
            f"The analyst has classified this data as: {report_context}\n"
            "Tailor your analysis specifically to this context.\n"
            "=== END CONTEXT ===\n\n"
        )

    return f"{context_block}{label}\n\n{raw_data}\n\n=== END OF DATA ==="


def _validate_response(content, output_format):
    """Validate AI response quality. Returns (is_valid, cleaned_content)."""
    if not content:
        return False, ""

    content = content.strip()

    # Remove <think> tags
    if "<think>" in content:
        content = re.sub(
            r"<think>.*?</think>", "", content, flags=re.DOTALL
        ).strip()

    if len(content) < 50:
        return False, content

    if output_format == "json":
        clean = content.replace("```json", "").replace("```", "").strip()
        try:
            json.loads(clean)
        except (json.JSONDecodeError, ValueError):
            console.print(
                "[dim yellow][!] VURA: AI response is not valid JSON. "
                "Passing raw content.[/dim yellow]"
            )

    return True, content


def _format_error(error, provider, model_name, output_format):
    """Format errors into user-friendly messages."""
    recommendations = RECOMMENDED_MODELS.get(
        provider, "Check your provider's documentation"
    )

    if isinstance(error, RateLimitError):
        msg = (
            f"Rate limit hit on {provider.upper()}. "
            f"All {MAX_RETRIES} retry attempts exhausted.\n"
            f"Solutions:\n"
            f"  1. Wait 1-2 minutes and try again\n"
            f"  2. Switch to a paid model (free models have strict limits)\n"
            f"  3. Try a different provider in config.json\n"
            f"  Recommended models for {provider}: {recommendations}"
        )
    elif isinstance(error, APITimeoutError):
        msg = (
            f"Timeout: {provider.upper()} took too long to respond.\n"
            f"Solutions:\n"
            f"  1. Try again — server may be under heavy load\n"
            f"  2. Use a faster provider (groq is fastest)\n"
            f"  3. Reduce input size"
        )
    elif isinstance(error, APIConnectionError):
        msg = (
            f"Cannot connect to {provider.upper()}.\n"
            f"Solutions:\n"
            f"  1. Check your internet connection\n"
            f"  2. Verify the provider is not down\n"
            f"  3. If using custom provider, verify base_url in config.json"
        )
    elif isinstance(error, APIStatusError):
        status = getattr(error, "status_code", "unknown")
        if status == 401:
            msg = (
                f"Authentication failed on {provider.upper()} (401).\n"
                f"Your API key is invalid or expired.\n"
                f"Run: vura -Ch to update your key"
            )
        elif status == 404:
            msg = (
                f"Model '{model_name}' not found on {provider.upper()} (404).\n"
                f"Recommended models for {provider}: {recommendations}\n"
                f"Update model_name in config.json"
            )
        elif status == 402:
            msg = (
                f"Insufficient credits on {provider.upper()} (402).\n"
                f"Top up your account or switch to a free model.\n"
                f"Free options on OpenRouter: google/gemini-2.0-flash-exp:free"
            )
        elif status == 429:
            msg = (
                f"Too many requests to {provider.upper()} (429).\n"
                f"Wait a few minutes or switch to a different provider."
            )
        else:
            msg = f"{provider.upper()} returned error {status}: {error}"
    else:
        msg = f"{provider.upper()} error: {error}"

    if output_format == "json":
        return json.dumps({"error": msg}, ensure_ascii=False)
    return f"# Connection Error\n{msg}"


# ══════════════════════════════════════════════════════════════════════
# Hugging Face Connector (defensive)
# ══════════════════════════════════════════════════════════════════════

HF_COLD_START_SENTINEL = "__HF_COLD_START__"


def _huggingface_chat(api_key, messages, *,
                      model_name=HUGGINGFACE_DEFAULT_MODEL,
                      temperature=0.3, max_tokens=4096, timeout=180):
    """
    Hugging Face connector via OpenAI-compatible endpoint.
    Returns (content, error) tuple.
    """
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type":  "application/json",
    }
    payload = {
        "model": model_name,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "stream": False,
    }

    try:
        response = requests.post(
            HUGGINGFACE_ENDPOINT,
            headers=headers, json=payload, timeout=timeout,
        )
    except requests.exceptions.Timeout:
        return None, (
            "Hugging Face request timed out. "
            "Try again in 1-2 minutes."
        )
    except requests.exceptions.ConnectionError:
        return None, (
            "Cannot reach Hugging Face. "
            "Check your internet connection."
        )
    except requests.exceptions.RequestException as e:
        return None, f"Hugging Face request failed: {e}"

    status = response.status_code

    if status == 503:
        console.print(Panel.fit(
            "[bold yellow]Hugging Face Model is Loading (Cold Start)[/bold yellow]\n\n"
            "The model is warming up on serverless infrastructure.\n"
            "Usually takes ~30 seconds.\n\n"
            "Wait 30 seconds, then re-run: vura -Rc",
            title="[bold]VURA — Hugging Face Notice[/bold]",
            border_style="yellow",
        ))
        return None, HF_COLD_START_SENTINEL

    if status in (401, 403):
        return None, (
            f"Hugging Face authentication failed (HTTP {status}). "
            "Get a new token: https://huggingface.co/settings/tokens"
        )
    if status == 404:
        return None, (
            f"Hugging Face model '{model_name}' not found (404)."
        )
    if status == 429:
        return None, "Hugging Face rate limit hit (429). Wait a few minutes."
    if status >= 400:
        snippet = ""
        try:
            snippet = (response.text or "")[:300]
        except Exception:
            pass
        return None, f"Hugging Face returned HTTP {status}. Body: {snippet}"

    try:
        data = response.json()
    except ValueError:
        return None, "Hugging Face returned a non-JSON response."

    if not isinstance(data, dict):
        return None, f"Unexpected JSON type: {type(data).__name__}"

    if "error" in data and "choices" not in data:
        return None, f"Hugging Face API error: {data.get('error')}"

    choices = data.get("choices")
    if not choices or not isinstance(choices, list):
        return None, (
            "Hugging Face response missing 'choices' array. "
            f"Raw keys: {list(data.keys())}"
        )

    first = choices[0]
    if not isinstance(first, dict):
        return None, "Hugging Face: 'choices[0]' is not an object."

    message = first.get("message")
    if not message or not isinstance(message, dict):
        return None, "Hugging Face: 'choices[0].message' is missing."

    content = message.get("content")
    if not isinstance(content, str) or not content.strip():
        return None, "Hugging Face: 'choices[0].message.content' is empty."

    return content, None


# ══════════════════════════════════════════════════════════════════════
# Single Provider Execution
# ══════════════════════════════════════════════════════════════════════

def _try_provider(provider, api_key, model_name, base_url, headers,
                  settings, messages, output_format, scan_type):
    """
    Attempt to get a response from a single provider.
    Returns (content, error) — never raises.
    """
    timeout_sec = settings["timeout"]

    # ── Hugging Face special path ────────────────────────────────────
    if provider == "huggingface":
        console.print(
            f"[dim yellow][~] VURA AI Engine → HUGGINGFACE | "
            f"Model: {model_name} | Mode: {scan_type.upper()}[/dim yellow]"
        )

        last_error = None
        for attempt in range(1, MAX_RETRIES + 1):
            if attempt > 1:
                wait = RETRY_BASE_WAIT * (RETRY_BACKOFF ** (attempt - 2))
                console.print(
                    f"[dim yellow]  Retry {attempt}/{MAX_RETRIES} "
                    f"(waiting {wait}s)...[/dim yellow]"
                )
                time.sleep(wait)

            content, err = _huggingface_chat(
                api_key, messages,
                model_name=model_name,
                temperature=settings["temperature"],
                max_tokens=settings["max_tokens"],
                timeout=timeout_sec,
            )

            if err == HF_COLD_START_SENTINEL:
                return None, "Hugging Face model is warming up. Wait ~30s."

            if content is not None:
                is_valid, cleaned = _validate_response(content, output_format)
                if not is_valid:
                    console.print(
                        f"[dim yellow][!] VURA: HF unusable response "
                        f"(attempt {attempt}/{MAX_RETRIES}).[/dim yellow]"
                    )
                    last_error = Exception("HF returned unusable response")
                    continue
                if attempt > 1:
                    console.print(
                        f"[dim green]  Succeeded on attempt {attempt}.[/dim green]"
                    )
                return cleaned, None

            last_error = Exception(err or "Unknown HF error")
            err_lower = (err or "").lower()
            if any(tok in err_lower for tok in ("401", "403", "404", "auth")):
                break

        return None, str(last_error) if last_error else "Unknown HF error"

    # ── Standard OpenAI-compatible path ──────────────────────────────
    try:
        client = OpenAI(
            base_url=base_url,
            api_key=api_key,
            timeout=timeout_sec,
            max_retries=0,
            default_headers=headers,
        )
    except Exception as e:
        return None, f"Failed to initialize {provider.upper()} client: {e}"

    request_params = {
        "model": model_name,
        "messages": messages,
        "temperature": settings["temperature"],
        "max_tokens": settings["max_tokens"],
        "stream": False,
    }

    console.print(
        f"[dim yellow][~] VURA AI Engine → {provider.upper()} | "
        f"Model: {model_name} | Mode: {scan_type.upper()}[/dim yellow]"
    )

    last_error = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            if attempt > 1:
                wait = RETRY_BASE_WAIT * (RETRY_BACKOFF ** (attempt - 2))
                console.print(
                    f"[dim yellow]  Retry {attempt}/{MAX_RETRIES} "
                    f"(waiting {wait}s)...[/dim yellow]"
                )
                time.sleep(wait)

            response = client.chat.completions.create(**request_params)
            content = response.choices[0].message.content

            is_valid, cleaned = _validate_response(content, output_format)
            if not is_valid:
                console.print(
                    f"[dim yellow][!] VURA: AI unusable response "
                    f"(attempt {attempt}/{MAX_RETRIES}).[/dim yellow]"
                )
                last_error = Exception("AI returned unusable response")
                continue

            if attempt > 1:
                console.print(
                    f"[dim green]  Succeeded on attempt {attempt}.[/dim green]"
                )
            return cleaned, None

        except RateLimitError as e:
            last_error = e
            if attempt < MAX_RETRIES:
                wait = RETRY_BASE_WAIT * (RETRY_BACKOFF ** (attempt - 1))
                console.print(
                    f"[dim yellow]  Rate limited by {provider.upper()} "
                    f"(attempt {attempt}/{MAX_RETRIES}). "
                    f"Waiting {wait}s...[/dim yellow]"
                )
                time.sleep(wait)
                continue
            break

        except APITimeoutError as e:
            last_error = e
            if attempt < MAX_RETRIES:
                console.print(
                    f"[dim yellow]  Timeout on {provider.upper()} "
                    f"(attempt {attempt}/{MAX_RETRIES}).[/dim yellow]"
                )
                continue
            break

        except (APIConnectionError, APIStatusError) as e:
            last_error = e
            break

        except Exception as e:
            last_error = e
            break

    return None, _format_error(last_error, provider, model_name, output_format)


# ══════════════════════════════════════════════════════════════════════
# PUBLIC API
# ══════════════════════════════════════════════════════════════════════

def generate_report(raw_data, language="English", output_format="md",
                    approach="defense", include_script=True,
                    scan_type="terminal", report_context=""):
    """
    Generate VURA report with AI — with circuit breaker + failover.

    Flow:
      1. Validate input
      2. Check circuit breaker for primary provider
      3. Try primary provider with retry
      4. If fails and fallback enabled, try backup providers
      5. Return formatted result or graceful error

    Parameters:
        raw_data         : Raw terminal/recon data
        language         : Report language
        output_format    : md, json, pdf
        approach         : offense or defense
        include_script   : Include bash script
        scan_type        : terminal, recon, executive
        report_context   : Report classification context

    Returns:
        str — Report content or formatted error message
    """
    # ── Input validation ─────────────────────────────────────────────
    try:
        if not raw_data or len(raw_data.strip()) < 5:
            if output_format == "json":
                return '{"error": "No valid data captured"}'
            return "# VURA Error\nNo valid data."

        config = load_api_config()
        is_valid, config_error = _validate_config(config)
        if not is_valid:
            if output_format == "json":
                return json.dumps({"error": config_error}, ensure_ascii=False)
            return f"# Error\n{config_error}"

        primary_provider = config["provider"].strip().lower()
        api_key = config["api_key"].strip()
        model_name = config.get("model_name", "").strip()

        if not model_name:
            recs = RECOMMENDED_MODELS.get(primary_provider, "Check docs")
            err = f"No model_name. Recommended for {primary_provider}: {recs}"
            if output_format == "json":
                return json.dumps({"error": err}, ensure_ascii=False)
            return f"# Error\n{err}"

        can_proceed, size_error = _check_input_size(raw_data, primary_provider)
        if not can_proceed:
            if output_format == "json":
                return json.dumps({"error": size_error}, ensure_ascii=False)
            return f"# VURA Error\n{size_error}"

        # Anthropic warning
        if primary_provider == "anthropic":
            console.print(
                "[bold yellow][!] VURA: provider='anthropic' routes through "
                "OpenRouter. Your api_key must be an OpenRouter key, "
                "NOT a raw Anthropic key.[/bold yellow]"
            )

        # Build messages
        base_url = _resolve_base_url(primary_provider, config)
        headers = _build_headers(primary_provider)
        settings = PROVIDER_SETTINGS.get(primary_provider, _DEFAULT_SETTINGS)

        system_prompt = _build_system_prompt(
            scan_type, language, approach, include_script, output_format
        )
        user_message = _build_user_message(raw_data, scan_type, report_context)

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ]

        # ── Try primary provider with circuit breaker ────────────────
        breaker = _get_breaker(primary_provider)

        if not breaker.can_execute():
            console.print(
                f"[dim red][!] {primary_provider.upper()} circuit breaker "
                f"OPEN ({breaker.failure_count} failures). "
                f"Trying fallback...[/dim red]"
            )
        else:
            console.print(
                f"[dim]Circuit: {primary_provider} = {breaker.state}[/dim]"
            )

            content, error = _try_provider(
                primary_provider, api_key, model_name, base_url,
                headers, settings, messages, output_format, scan_type,
            )

            if content is not None:
                breaker.record_success()
                return content

            breaker.record_failure()
            console.print(
                f"[dim yellow][!] {primary_provider.upper()} failed: "
                f"{error[:100]}[/dim yellow]"
            )

        # ── Fallback: try other configured providers ─────────────────
        console.print(
            "[dim yellow][~] Primary provider failed. "
            "Attempting fallback...[/dim yellow]"
        )

        # Fallback order: prefer fast/free providers
        fallback_order = [
            "groq", "gemini", "openrouter", "together",
            "mistral", "deepseek", "qwen", "venice", "github",
        ]

        for fb_provider in fallback_order:
            if fb_provider == primary_provider:
                continue

            fb_breaker = _get_breaker(fb_provider)
            if not fb_breaker.can_execute():
                continue

            # Check if we have an API key for this provider
            fb_key = config.get(f"{fb_provider}_api_key", "").strip()
            if not fb_key:
                # Try using the primary key (many providers use OpenAI format)
                fb_key = api_key

            fb_url = PROVIDER_ENDPOINTS.get(fb_provider)
            fb_settings = PROVIDER_SETTINGS.get(fb_provider, _DEFAULT_SETTINGS)

            content, error = _try_provider(
                fb_provider, fb_key, model_name, fb_url,
                _build_headers(fb_provider), fb_settings,
                messages, output_format, scan_type,
            )

            if content is not None:
                fb_breaker.record_success()
                console.print(
                    f"[dim green][+] Fallback succeeded: "
                    f"{fb_provider.upper()}[/dim green]"
                )
                return content

            fb_breaker.record_failure()

        # ── All providers failed ─────────────────────────────────────
        return _format_error(
            Exception("All AI providers failed. Check API keys and network."),
            primary_provider, model_name, output_format,
        )

    except Exception as e:
        # Catch-all: never crash
        console.print(
            f"[bold red][!] VURA AI Engine crashed: {e}[/bold red]"
        )
        if output_format == "json":
            return json.dumps({"error": f"Unexpected error: {e}"}, ensure_ascii=False)
        return f"# VURA Error\nUnexpected error: {e}"


# ── Convenience: check if a specific provider is available ──────────

def is_provider_available(provider: str) -> bool:
    """Check if a provider's circuit breaker allows requests."""
    breaker = _get_breaker(provider)
    return breaker.can_execute()


def get_provider_stats(provider: str) -> dict:
    """Get circuit breaker stats for a provider."""
    return _get_breaker(provider).stats
