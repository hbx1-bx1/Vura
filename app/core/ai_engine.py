"""
VURA AI Engine — Vulnerability Reporting AI
═══════════════════════════════════════════════════════════
Multi-provider AI analysis engine with automatic retry,
response validation, and specialized security prompts.
"""

import time
from openai import OpenAI, APIConnectionError, RateLimitError, APIStatusError, APITimeoutError
from rich.console import Console
from app.utils.config import load_api_config

console = Console()

# ═══════════════════════════════════════════════════════════════════════════════
# PROVIDER REGISTRY
# ═══════════════════════════════════════════════════════════════════════════════
# كل مزود يدعم OpenAI-compatible API — نفس الـ client يعمل مع الجميع.
# base_url هو الفرق الوحيد بين المزودين.

PROVIDER_ENDPOINTS = {
    "openai":      "https://api.openai.com/v1",
    "openrouter":  "https://openrouter.ai/api/v1",
    "anthropic":   "https://openrouter.ai/api/v1",        # لا يدعم OpenAI client مباشرة — يُمرَّر عبر OpenRouter
    "deepseek":    "https://api.deepseek.com/v1",
    "qwen":        "https://dashscope.aliyuncs.com/compatible-mode/v1",
    "gemini":      "https://generativelanguage.googleapis.com/v1beta/openai/",
    "groq":        "https://api.groq.com/openai/v1",
    "mistral":     "https://api.mistral.ai/v1",
    "together":    "https://api.together.xyz/v1",
    "venice":      "https://api.venice.ai/api/v1",
    "github":      "https://models.inference.ai.azure.com",
    "custom":      None,  # يُقرأ من config["base_url"]
}

# ─── إعدادات لكل مزود ──────────────────────────────────────────────────────
# timeout: ثواني الانتظار قبل اعتبار الاتصال فاشل
# max_tokens: الحد الأقصى لطول الرد — بعض المزودين لا يدعم قيم عالية
# temperature: 0.3 = تقارير دقيقة بدون هلوسة، أعلى = أكثر إبداعاً

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
}

_DEFAULT_SETTINGS = {"timeout": 120, "max_tokens": 4096, "temperature": 0.3}

# ─── نماذج موصى بها لكل مزود ─────────────────────────────────────────────
# تظهر فقط عند الخطأ لمساعدة المستخدم يختار نموذج صحيح

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
}

# ─── Retry Configuration ────────────────────────────────────────────────────
MAX_RETRIES     = 3      # عدد المحاولات الإجمالي
RETRY_BASE_WAIT = 2      # ثانية — الانتظار الأولي قبل إعادة المحاولة
RETRY_BACKOFF   = 2      # المضاعف — كل محاولة تنتظر ضعف السابقة

# ─── تقدير حجم الـ input ─────────────────────────────────────────────────────
# معظم النماذج تدعم 8K-128K tokens. كل 4 أحرف ≈ 1 token تقريباً.
INPUT_WARN_CHARS  = 100_000   # 100K حرف ≈ 25K token — تحذير
INPUT_LIMIT_CHARS = 400_000   # 400K حرف ≈ 100K token — رفض


# ═══════════════════════════════════════════════════════════════════════════════
# SYSTEM PROMPTS — متخصصة حسب نوع الفحص
# ═══════════════════════════════════════════════════════════════════════════════

PROMPTS = {
    # ══════════════════════════════════════════════════════════════════════════
    # TERMINAL — تحليل مخرجات Terminal (nmap, nikto, sqlmap, etc.)
    # ══════════════════════════════════════════════════════════════════════════
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

    # ══════════════════════════════════════════════════════════════════════════
    # RECON — تحليل بيانات الاستطلاع (Amass, Shodan, theHarvester)
    # ══════════════════════════════════════════════════════════════════════════
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

    # ══════════════════════════════════════════════════════════════════════════
    # EXECUTIVE — ملخص تنفيذي للإدارة العليا
    # ══════════════════════════════════════════════════════════════════════════
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
| 🔴 Critical | X | [Business impact in plain language] |
| 🟠 High | X | [Business impact in plain language] |
| 🟡 Medium | X | [Business impact in plain language] |

### 3. What's at Stake
Answer in plain business language:
- **Data Exposure**: What sensitive data could be stolen? (customer records, financial data, trade secrets)
- **Financial Impact**: Estimated cost of a breach (fines, lawsuits, recovery, lost revenue)
- **Reputation Risk**: Would this make the news? Impact on customer trust?
- **Regulatory Risk**: Are we violating any regulations? (GDPR, NCA ECC, PCI-DSS, ISO 27001)

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

# ─── Script Instructions ─────────────────────────────────────────────────────
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


# ═══════════════════════════════════════════════════════════════════════════════
# INTERNAL FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def _validate_config(config):
    """
    التحقق من صحة الإعدادات قبل محاولة الاتصال.
    يرجع (is_valid, error_message).
    """
    if not config:
        return False, "config.json is empty or missing. Run: vura -Ch"

    provider = config.get("provider", "").strip().lower()
    api_key  = config.get("api_key", "").strip()

    if not provider:
        return False, "No 'provider' set in config.json. Run: vura -Ch"

    if not api_key:
        return False, f"No 'api_key' set for provider '{provider}'. Run: vura -Ch"

    if provider == "custom" and not config.get("base_url", "").strip():
        return False, "provider='custom' requires 'base_url' in config.json"

    if provider not in PROVIDER_ENDPOINTS:
        supported = ", ".join(sorted(PROVIDER_ENDPOINTS.keys()))
        return False, f"Unknown provider '{provider}'. Supported: {supported}"

    # تحذير إذا كان المفتاح يبدأ بـ prefix غير متوقع
    if provider == "openrouter" and not api_key.startswith("sk-or-"):
        console.print("[dim yellow][!] VURA: OpenRouter keys usually start with 'sk-or-'. Double-check your key.[/dim yellow]")

    if provider == "openai" and not api_key.startswith("sk-"):
        console.print("[dim yellow][!] VURA: OpenAI keys usually start with 'sk-'. Double-check your key.[/dim yellow]")

    return True, ""


def _build_headers(provider):
    """بناء HTTP Headers حسب المزود."""
    if provider in ("openrouter", "anthropic"):
        return {
            "HTTP-Referer": "https://vura-sec.com",
            "X-Title": "VURA Security Engine",
        }
    return None


def _resolve_base_url(provider, config):
    """تحديد الـ base_url — يرفع ValueError إذا كان المزود غير معروف."""
    if provider == "custom":
        return config["base_url"].strip()

    return PROVIDER_ENDPOINTS[provider]


def _estimate_tokens(text):
    """تقدير تقريبي لعدد الـ tokens — كل 4 أحرف ≈ 1 token."""
    return len(text) // 4


def _check_input_size(raw_data, provider):
    """
    فحص حجم البيانات المدخلة.
    يرجع (can_proceed, warning_message).
    """
    char_count = len(raw_data)
    est_tokens = _estimate_tokens(raw_data)

    if char_count > INPUT_LIMIT_CHARS:
        return False, (
            f"Input too large: ~{est_tokens:,} tokens ({char_count:,} chars). "
            f"Maximum recommended: ~{_estimate_tokens('x' * INPUT_LIMIT_CHARS):,} tokens. "
            f"Trim your data or split into multiple analyses."
        )

    if char_count > INPUT_WARN_CHARS:
        console.print(
            f"[dim yellow][!] VURA: Large input detected (~{est_tokens:,} tokens). "
            f"Some providers may truncate or reject this. Processing anyway...[/dim yellow]"
        )

    return True, ""


def _build_system_prompt(scan_type, language, approach, include_script, output_format):
    """بناء الـ System Prompt المناسب حسب نوع الفحص وصيغة الإخراج."""

    # ── JSON — استخراج ثغرات فقط ──
    if output_format == "json":
        return (
            f"You are VURA security analysis engine. Extract ALL vulnerabilities from the data.\n"
            f"Language: {language}.\n"
            f"Respond ONLY with a valid JSON array. No markdown, no explanation, no preamble.\n"
            f"Format: [{{\"cve\": \"CVE-XXXX-XXXXX\", \"severity\": \"Critical|High|Medium|Low\", "
            f"\"component\": \"...\", \"vulnerability\": \"...\", \"remediation\": \"...\"}}]\n"
            f"If no vulnerabilities found, return: []"
        )

    # ── Executive — لا script أبداً ──
    if scan_type == "executive":
        return PROMPTS["executive"].format(language=language)

    # ── Terminal أو Recon ──
    prompt_template = PROMPTS.get(scan_type, PROMPTS["terminal"])

    if not include_script:
        script_instruction = SCRIPT_INSTRUCTIONS["no_script"]
    elif approach == "offense":
        script_instruction = SCRIPT_INSTRUCTIONS["offense_yes"]
    else:
        script_instruction = SCRIPT_INSTRUCTIONS["defense_yes"]

    return prompt_template.format(language=language, script_instruction=script_instruction)


def _build_user_message(raw_data, scan_type, report_context=""):
    """بناء رسالة المستخدم مع label حسب نوع الفحص وسياق التقرير."""
    labels = {
        "terminal":  "=== TERMINAL SESSION OUTPUT ===",
        "recon":     "=== RECONNAISSANCE DATA ===",
        "executive": "=== SECURITY ASSESSMENT DATA ===",
    }
    label = labels.get(scan_type, "=== TERMINAL SESSION OUTPUT ===")

    context_block = ""
    if report_context:
        context_block = (
            f"=== REPORT CONTEXT ===\n"
            f"The analyst has classified this data as: {report_context}\n"
            f"Tailor your analysis specifically to this context.\n"
            f"=== END CONTEXT ===\n\n"
        )

    return f"{context_block}{label}\n\n{raw_data}\n\n=== END OF DATA ==="


def _validate_response(content, output_format):
    """
    فحص جودة الرد من الـ AI.
    يرجع (is_valid, cleaned_content).
    """
    if not content:
        return False, ""

    content = content.strip()

    # ── بعض النماذج تُضيف <think>...</think> — نحذفها ──
    if "<think>" in content:
        import re
        content = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()

    # ── فحص إذا كان الرد قصير جداً (أقل من 50 حرف = غير مفيد) ──
    if len(content) < 50:
        return False, content

    # ── فحص JSON ──
    if output_format == "json":
        import json
        clean = content.replace("```json", "").replace("```", "").strip()
        try:
            json.loads(clean)
        except (json.JSONDecodeError, ValueError):
            # ليس JSON صالح لكن قد يحتوي بيانات مفيدة — نمرره مع تحذير
            console.print("[dim yellow][!] VURA: AI response is not valid JSON. Passing raw content.[/dim yellow]")

    return True, content


def _format_error(error, provider, model_name, output_format):
    """تحويل الأخطاء لرسائل واضحة وقابلة للتنفيذ."""

    recommendations = RECOMMENDED_MODELS.get(provider, "Check your provider's documentation")

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
            f"  2. Verify the provider is not down: check their status page\n"
            f"  3. If using custom provider, verify base_url in config.json"
        )

    elif isinstance(error, APIStatusError):
        status = getattr(error, "status_code", "unknown")
        if status == 401:
            msg = (
                f"Authentication failed on {provider.upper()} (401 Unauthorized).\n"
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
        import json
        return json.dumps({"error": msg}, ensure_ascii=False)
    else:
        return f"# Connection Error\n{msg}"


# ═══════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ═══════════════════════════════════════════════════════════════════════════════

def generate_report(raw_data, language="English", output_format="md",
                    approach="defense", include_script=True, scan_type="terminal",
                    report_context=""):
    """
    توليد تقرير VURA باستخدام AI — مع retry تلقائي وvalidation كامل.

    Parameters:
        raw_data        : البيانات الخام من الـ terminal أو أدوات الاستطلاع
        language         : لغة التقرير (English, Arabic, etc.)
        output_format    : md, json, pdf
        approach         : offense أو defense — يحدد نوع السكربت
        include_script   : هل يُضاف سكربت Bash في النهاية
        scan_type        : نوع الفحص — "terminal" | "recon" | "executive"
        report_context   : سياق التقرير — يُخبر الـ AI بنوع التحليل المطلوب

    Returns:
        str — التقرير الكامل (md/json) أو رسالة خطأ مُنسّقة

    Backward Compatible:
        cli.py يستدعي بدون scan_type أو report_context — القيم الافتراضية تحافظ على التوافق.
    """
    # ── التحقق من وجود بيانات ──
    if not raw_data or len(raw_data.strip()) < 5:
        if output_format == "json":
            return '{"error": "No valid data captured"}'
        return "# VURA Error\nNo valid data."

    # ── تحميل وفحص الإعدادات ──
    config = load_api_config()
    is_valid, config_error = _validate_config(config)
    if not is_valid:
        if output_format == "json":
            return f'{{"error": "{config_error}"}}'
        return f"# Error\n{config_error}"

    provider   = config["provider"].strip().lower()
    api_key    = config["api_key"].strip()
    model_name = config.get("model_name", "").strip()

    if not model_name:
        recommendations = RECOMMENDED_MODELS.get(provider, "Check your provider's docs")
        if output_format == "json":
            return f'{{"error": "No model_name in config.json. Recommended for {provider}: {recommendations}"}}'
        return f"# Error\nNo model_name in config.json.\nRecommended for {provider}: {recommendations}"

    # ── فحص حجم المدخلات ──
    can_proceed, size_error = _check_input_size(raw_data, provider)
    if not can_proceed:
        if output_format == "json":
            return f'{{"error": "{size_error}"}}'
        return f"# VURA Error\n{size_error}"

    # ── تنبيه Anthropic ──
    if provider == "anthropic":
        console.print(
            "[dim yellow][!] VURA: Anthropic direct API is not OpenAI-compatible — "
            "routing through OpenRouter. Ensure your key works with OpenRouter, "
            "or set provider='openrouter' in config.json.[/dim yellow]"
        )

    # ── تجهيز الاتصال ──
    base_url    = _resolve_base_url(provider, config)
    headers     = _build_headers(provider)
    settings    = PROVIDER_SETTINGS.get(provider, _DEFAULT_SETTINGS)
    timeout_sec = settings["timeout"]

    client = OpenAI(
        base_url=base_url,
        api_key=api_key,
        timeout=timeout_sec,
        max_retries=0,  # نتحكم بالـ retry يدوياً
        default_headers=headers,
    )

    system_prompt = _build_system_prompt(scan_type, language, approach, include_script, output_format)
    user_message  = _build_user_message(raw_data, scan_type, report_context)

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user",   "content": user_message},
    ]

    # ── إعدادات الطلب ──
    request_params = {
        "model":       model_name,
        "messages":    messages,
        "temperature": settings["temperature"],
        "max_tokens":  settings["max_tokens"],
        "stream":      False,
    }

    # ── الإرسال مع Retry ──
    scan_label = scan_type.upper()
    console.print(
        f"[dim yellow][~] VURA AI Engine → {provider.upper()} | "
        f"Model: {model_name} | Mode: {scan_label}[/dim yellow]"
    )

    last_error = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            if attempt > 1:
                wait = RETRY_BASE_WAIT * (RETRY_BACKOFF ** (attempt - 2))
                console.print(
                    f"[dim yellow]  ↻ Retry {attempt}/{MAX_RETRIES} "
                    f"(waiting {wait}s)...[/dim yellow]"
                )
                time.sleep(wait)

            response = client.chat.completions.create(**request_params)
            content  = response.choices[0].message.content

            # ── فحص الرد ──
            is_valid_resp, cleaned = _validate_response(content, output_format)
            if not is_valid_resp:
                console.print(
                    f"[dim yellow][!] VURA: AI returned an unusable response "
                    f"(attempt {attempt}/{MAX_RETRIES}).[/dim yellow]"
                )
                last_error = Exception("AI returned empty or unusable response")
                continue  # retry

            # ── نجاح! ──
            if attempt > 1:
                console.print(f"[dim green]  ✓ Succeeded on attempt {attempt}.[/dim green]")

            return cleaned

        except RateLimitError as e:
            last_error = e
            if attempt < MAX_RETRIES:
                wait = RETRY_BASE_WAIT * (RETRY_BACKOFF ** (attempt - 1))
                console.print(
                    f"[dim yellow]  ⚠ Rate limited by {provider.upper()} "
                    f"(attempt {attempt}/{MAX_RETRIES}). "
                    f"Waiting {wait}s...[/dim yellow]"
                )
                time.sleep(wait)
                continue
            # آخر محاولة — نخرج بالخطأ
            break

        except APITimeoutError as e:
            last_error = e
            if attempt < MAX_RETRIES:
                console.print(
                    f"[dim yellow]  ⚠ Timeout on {provider.upper()} "
                    f"(attempt {attempt}/{MAX_RETRIES}).[/dim yellow]"
                )
                continue
            break

        except (APIConnectionError, APIStatusError) as e:
            # أخطاء لا تستفيد من retry — نخرج فوراً
            last_error = e
            break

        except Exception as e:
            # خطأ غير متوقع — نخرج فوراً
            last_error = e
            break

    # ── كل المحاولات فشلت ──
    return _format_error(last_error, provider, model_name, output_format)
