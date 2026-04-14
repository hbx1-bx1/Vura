"""
VURA Dashboard — Streamlit Web Interface
═════════════════════════════════════════
Client-facing dashboard for the VURA SaaS platform.

Dependencies (add to requirements.txt):
    streamlit>=1.30.0
    plotly>=5.18.0

Run:
    streamlit run dashboard/app.py --server.port 8501

Access:
    http://localhost:8501
"""

import os
import sys
import datetime

# ── مسار المشروع ──
_DASHBOARD_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_DASHBOARD_DIR)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import streamlit as st

# ═══════════════════════════════════════════════════════════════════════════════
# PAGE CONFIG
# ═══════════════════════════════════════════════════════════════════════════════

st.set_page_config(
    page_title="VURA Security Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ──
st.markdown("""
<style>
    .main-header { font-size: 2.5rem; font-weight: bold; color: #1abc9c; margin-bottom: 0; }
    .sub-header  { font-size: 1rem; color: #7f8c8d; margin-top: 0; }
    .metric-card { background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
                   padding: 20px; border-radius: 10px; color: white; text-align: center; }
    .metric-number { font-size: 2.5rem; font-weight: bold; margin: 10px 0; }
    .metric-label  { font-size: 0.9rem; color: #bdc3c7; }
    .status-ok   { color: #2ecc71; } .status-warn { color: #f1c40f; } .status-err { color: #e74c3c; }
    div[data-testid="stSidebar"] { background: linear-gradient(180deg, #1a1a2e 0%, #16213e 100%); }
</style>
""", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════════
# DATABASE HELPER
# ═══════════════════════════════════════════════════════════════════════════════

@st.cache_resource
def get_db():
    """اتصال واحد بقاعدة البيانات — cached."""
    from app.core.database import VuraDB
    return VuraDB()


def refresh_db():
    """إعادة إنشاء اتصال DB."""
    get_db.clear()
    return get_db()


# ═══════════════════════════════════════════════════════════════════════════════
# SIDEBAR — Navigation
# ═══════════════════════════════════════════════════════════════════════════════

st.sidebar.markdown("## 🛡️ VURA")
st.sidebar.markdown("*Vulnerability Reporting AI*")
st.sidebar.markdown("---")

page = st.sidebar.radio(
    "Navigation",
    ["📊 Dashboard", "👥 Clients", "🔍 Scans", "📋 Compliance", "⏰ Scheduler", "💳 Plans", "⚙️ Settings"],
    label_visibility="collapsed",
)

st.sidebar.markdown("---")
st.sidebar.markdown("VURA v1.0.0")


# ═══════════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def _display_assessment(comp, assessment):
    """عرض نتائج تقييم الامتثال."""
    st.subheader("Assessment Results")
    cols = st.columns(len(assessment["summary"]))
    for idx, (fw, s) in enumerate(assessment["summary"].items()):
        with cols[idx]:
            pct = s["compliance_percentage"]
            color = "🟢" if pct >= 80 else "🟡" if pct >= 60 else "🔴"
            st.metric(
                s["framework_name"],
                f"{color} {pct}%",
                delta=f"-{s['affected_controls']} gaps",
                delta_color="inverse",
            )

    if assessment["matched_vulns"]:
        st.warning(f"Vulnerability patterns detected: **{', '.join(assessment['matched_vulns'])}**")

    for fw, gaps in assessment["gaps"].items():
        if gaps:
            fw_name = comp.frameworks[fw]["name"]
            with st.expander(f"📋 {fw_name} — {len(gaps)} gap(s)"):
                gap_data = []
                for ctrl_id, info in sorted(gaps.items()):
                    gap_data.append({
                        "Control": ctrl_id,
                        "Name": info["name"],
                        "Triggered By": ", ".join(info["vulns"]),
                        "Status": "⚠️ Gap",
                    })
                st.dataframe(gap_data, use_container_width=True, hide_index=True)

    if st.button("📄 Generate Full Compliance Report"):
        report = comp.generate_compliance_report(
            report_content="\n".join(assessment["matched_vulns"]),
            frameworks=list(assessment["summary"].keys()),
        )
        st.markdown(report)
        st.download_button("📥 Download Report", report, file_name="vura_compliance_report.md")


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: DASHBOARD — الصفحة الرئيسية
# ═══════════════════════════════════════════════════════════════════════════════

if page == "📊 Dashboard":
    st.markdown('<p class="main-header">VURA Dashboard</p>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">Vulnerability Reporting AI</p>', unsafe_allow_html=True)

    db = get_db()
    stats = db.get_global_stats()

    # ── Metrics Row ──
    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        st.metric("Total Clients", stats.get("total_clients", 0))
    with col2:
        st.metric("Active Clients", stats.get("active_clients", 0))
    with col3:
        st.metric("Total Scans", stats.get("total_scans", 0))
    with col4:
        st.metric("Completed", stats.get("completed_scans", 0))
    with col5:
        critical = stats.get("total_critical", 0)
        st.metric("Critical Findings", critical, delta=None)

    st.markdown("---")

    # ── Recent Scans ──
    col_left, col_right = st.columns([2, 1])

    with col_left:
        st.subheader("Recent Scans")
        recent = db.list_scans(limit=10)
        if recent:
            scan_data = []
            for s in recent:
                scan_data.append({
                    "ID": s["id"],
                    "Target": s["target"][:30],
                    "Type": s["scan_type"],
                    "Status": s["status"],
                    "Findings": s.get("findings_count") or 0,
                    "Critical": s.get("critical_count") or 0,
                    "Date": s["created_at"][:16],
                })
            st.dataframe(scan_data, use_container_width=True, hide_index=True)
        else:
            st.info("No scans yet. Run your first scan from CLI or API.")

    with col_right:
        st.subheader("Scan Status")
        completed = stats.get("completed_scans", 0) or 0
        failed = stats.get("failed_scans", 0) or 0
        total_scans = stats.get("total_scans", 0) or 0
        pending = max(0, total_scans - completed - failed)

        if total_scans > 0:
            try:
                import plotly.graph_objects as go
                fig = go.Figure(data=[go.Pie(
                    labels=["Completed", "Failed", "Pending"],
                    values=[completed, failed, pending],
                    marker_colors=["#2ecc71", "#e74c3c", "#f1c40f"],
                    hole=0.5,
                )])
                fig.update_layout(
                    margin=dict(t=0, b=0, l=0, r=0),
                    height=250,
                    paper_bgcolor="rgba(0,0,0,0)",
                    font_color="white",
                    showlegend=True,
                    legend=dict(orientation="h", y=-0.1),
                )
                st.plotly_chart(fig, use_container_width=True)
            except ImportError:
                st.write(f"✅ Completed: {completed}")
                st.write(f"❌ Failed: {failed}")
                st.write(f"⏳ Pending: {pending}")
        else:
            st.info("No scan data to display.")


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: CLIENTS
# ═══════════════════════════════════════════════════════════════════════════════

elif page == "👥 Clients":
    st.header("👥 Client Management")

    db = get_db()

    # ── Add Client Form ──
    with st.expander("➕ Add New Client", expanded=False):
        with st.form("add_client"):
            col1, col2 = st.columns(2)
            with col1:
                name = st.text_input("Company Name *")
                domain = st.text_input("Domain (e.g., example.com)")
            with col2:
                email = st.text_input("Contact Email")
                plan = st.selectbox("Plan", ["free", "pro_individual", "pro_team", "pro_enterprise", "max_individual", "max_team", "max_enterprise"])

            notes = st.text_area("Notes", height=68)
            submitted = st.form_submit_button("Create Client")

            if submitted and name:
                try:
                    client = db.add_client(name, domain, email, plan, notes)
                    st.success(f"Client created! API Token: `{client['api_token']}`")
                    st.info("Save this token — it's the client's API key.")
                except Exception as e:
                    st.error(f"Error: {e}")

    # ── Client List ──
    st.subheader("All Clients")

    filter_col1, filter_col2 = st.columns(2)
    with filter_col1:
        search_query = st.text_input("Search", placeholder="Name, domain, or email...")
    with filter_col2:
        filter_plan = st.selectbox("Filter by Plan", ["All", "free", "pro_individual", "pro_team", "pro_enterprise", "max_individual", "max_team", "max_enterprise"])

    if search_query:
        clients = db.search_clients(search_query)
    else:
        clients = db.list_clients(plan=filter_plan if filter_plan != "All" else None)

    if clients:
        for c in clients:
            stats = db.get_client_stats(c["id"])
            status_emoji = "🟢" if c["active"] else "🔴"

            with st.expander(f"{status_emoji} {c['name']} — {c.get('domain', 'No domain')} ({c['plan']})"):
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.write(f"**ID:** {c['id']}")
                    st.write(f"**Email:** {c.get('contact_email') or 'N/A'}")
                    st.write(f"**Created:** {c['created_at'][:10]}")
                with col2:
                    st.write(f"**Plan:** {c['plan']}")
                    st.write(f"**Status:** {'Active' if c['active'] else 'Inactive'}")
                    st.write(f"**Token:** `{c['api_token'][:20]}...`")
                with col3:
                    st.write(f"**Total Scans:** {stats.get('total_scans', 0)}")
                    st.write(f"**Critical:** {stats.get('critical', 0)}")
                    st.write(f"**Completed:** {stats.get('completed', 0)}")

                if c.get("notes"):
                    st.write(f"**Notes:** {c['notes']}")
    else:
        st.info("No clients found.")


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: SCANS
# ═══════════════════════════════════════════════════════════════════════════════

elif page == "🔍 Scans":
    st.header("🔍 Scan History")

    db = get_db()

    # ── Filters ──
    col1, col2, col3 = st.columns(3)
    with col1:
        status_filter = st.selectbox("Status", ["All", "completed", "failed", "running", "pending"])
    with col2:
        type_filter = st.selectbox("Scan Type", ["All", "terminal", "recon", "executive", "dual"])
    with col3:
        limit = st.slider("Results", 10, 200, 50)

    scans = db.list_scans(
        status=status_filter if status_filter != "All" else None,
        scan_type=type_filter if type_filter != "All" else None,
        limit=limit,
    )

    if scans:
        scan_table = []
        for s in scans:
            scan_table.append({
                "ID": s["id"],
                "Target": s["target"][:40],
                "Type": s["scan_type"],
                "Approach": s["approach"],
                "Status": s["status"],
                "Findings": s.get("findings_count") or 0,
                "Critical": s.get("critical_count") or 0,
                "Language": s["language"],
                "Created": s["created_at"][:16],
            })

        st.dataframe(scan_table, use_container_width=True, hide_index=True)

        # ── View Report ──
        st.subheader("View Report")
        scan_id = st.number_input("Enter Scan ID", min_value=1, step=1)
        if st.button("Load Report"):
            scan = db.get_scan(scan_id)
            if scan and scan.get("report_md"):
                report_path = scan["report_md"]
                if os.path.exists(report_path):
                    with open(report_path, "r", encoding="utf-8") as f:
                        content = f.read()
                    st.markdown(content)

                    with open(report_path, "rb") as f:
                        st.download_button("📥 Download Report (MD)", f, file_name=os.path.basename(report_path))

                    if scan.get("report_pdf") and os.path.exists(scan["report_pdf"]):
                        with open(scan["report_pdf"], "rb") as f:
                            st.download_button("📥 Download Report (PDF)", f, file_name=os.path.basename(scan["report_pdf"]))
                else:
                    st.warning("Report file not found on disk.")
            else:
                st.warning("Scan not found or no report available.")
    else:
        st.info("No scans found with current filters.")


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: COMPLIANCE
# ═══════════════════════════════════════════════════════════════════════════════

elif page == "📋 Compliance":
    st.header("📋 Compliance Assessment")

    from app.modules.compliance import VuraCompliance
    comp = VuraCompliance()

    # ── Supported Frameworks ──
    st.subheader("Supported Frameworks")
    frameworks = comp.list_frameworks()
    fw_data = []
    for fw_id, info in frameworks.items():
        fw_data.append({
            "ID": fw_id,
            "Framework": info["name"],
            "Version": info["version"],
            "Country": info["country"],
            "Controls": info["total_controls"],
        })
    st.dataframe(fw_data, use_container_width=True, hide_index=True)

    st.markdown("---")

    # ── Run Assessment ──
    st.subheader("Run Assessment")

    assess_method = st.radio("Assessment Source", ["From Scan ID", "From Text Input"], horizontal=True)

    selected_frameworks = st.multiselect(
        "Frameworks to assess",
        list(frameworks.keys()),
        default=list(frameworks.keys()),
        format_func=lambda x: frameworks[x]["name"],
    )

    if assess_method == "From Scan ID":
        scan_id = st.number_input("Scan ID", min_value=1, step=1)
        if st.button("Run Compliance Assessment"):
            with st.spinner("Analyzing compliance gaps..."):
                assessment = comp.assess_from_scan(scan_id, frameworks=selected_frameworks)
                if "error" in assessment:
                    st.error(assessment["error"])
                else:
                    _display_assessment(comp, assessment)
    else:
        text_input = st.text_area("Paste report content or scan output", height=200)
        if st.button("Run Compliance Assessment") and text_input:
            with st.spinner("Analyzing compliance gaps..."):
                assessment = comp.assess_from_text(text_input, frameworks=selected_frameworks)
                _display_assessment(comp, assessment)


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: SCHEDULER
# ═══════════════════════════════════════════════════════════════════════════════

elif page == "⏰ Scheduler":
    st.header("⏰ Scheduled Scans")

    try:
        from app.core.scheduler import VuraScheduler, _check_apscheduler

        if not _check_apscheduler():
            st.error("APScheduler not installed. Run: `pip install apscheduler`")
        else:
            st.info("Scheduler management. Jobs are managed via CLI or API. View status here.")

            # ── Load scheduler state ──
            scheduler_state_path = os.path.join(_PROJECT_ROOT, "data", ".vura_scheduler.json")
            if os.path.exists(scheduler_state_path):
                import json
                with open(scheduler_state_path, "r") as f:
                    jobs = json.load(f)

                if jobs:
                    job_data = []
                    for job_id, config in jobs.items():
                        job_data.append({
                            "Job ID": job_id,
                            "Type": config.get("job_type", "?"),
                            "Target": config.get("domain", config.get("target", "?")),
                            "Interval": f"{config.get('interval_hours', '?')}h",
                            "Language": config.get("language", "English"),
                        })
                    st.dataframe(job_data, use_container_width=True, hide_index=True)
                else:
                    st.info("No scheduled jobs. Add jobs via CLI or API.")
            else:
                st.info("No scheduled jobs configured yet.")

    except Exception as e:
        st.error(f"Scheduler error: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: PLANS
# ═══════════════════════════════════════════════════════════════════════════════

elif page == "💳 Plans":
    st.header("💳 Subscription Plans")

    from app.core.billing import PLANS

    # ── Group by tier ──
    tiers = {"free": [], "pro": [], "max": []}
    for plan_id, plan in PLANS.items():
        tier = plan.get("tier", "free")
        tiers.setdefault(tier, []).append((plan_id, plan))

    # ── Free ──
    st.subheader("🆓 Free")
    for plan_id, plan in tiers.get("free", []):
        st.markdown(f"**{plan['name']}** — Free | {plan['scans_per_month']} scans/month")
        for feat in plan.get("features", []):
            st.markdown(f"- {feat}")
    st.markdown("---")

    # ── Pro ($5/mo) ──
    st.subheader("⚡ Pro Plans — $5/month")
    pro_cols = st.columns(len(tiers.get("pro", [])) or 1)
    for idx, (plan_id, plan) in enumerate(tiers.get("pro", [])):
        with pro_cols[idx]:
            price = plan.get("price_note", f"${plan['price_monthly']}/mo") if plan["price_monthly"] == 0 else f"${plan['price_monthly']}/mo"
            scans = "Custom" if plan["scans_per_month"] == -1 else str(plan["scans_per_month"])
            st.markdown(f"### {plan['name']}")
            st.markdown(f"**{price}**")
            st.markdown(f"📊 {scans} scans/month")
            for feat in plan.get("features", []):
                st.markdown(f"- ✅ {feat}")
    st.markdown("---")

    # ── Max ($20/mo) ──
    st.subheader("👑 Max Plans — $20/month — The Golden Choice")
    max_cols = st.columns(len(tiers.get("max", [])) or 1)
    for idx, (plan_id, plan) in enumerate(tiers.get("max", [])):
        with max_cols[idx]:
            price = plan.get("price_note", f"${plan['price_monthly']}/mo") if plan["price_monthly"] == 0 else f"${plan['price_monthly']}/mo"
            scans = "Negotiated" if plan["scans_per_month"] == -1 else str(plan["scans_per_month"])
            st.markdown(f"### {plan['name']}")
            st.markdown(f"**{price}**")
            st.markdown(f"📊 {scans} scans/month")
            for feat in plan.get("features", []):
                st.markdown(f"- ✅ {feat}")


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: SETTINGS
# ═══════════════════════════════════════════════════════════════════════════════

elif page == "⚙️ Settings":
    st.header("⚙️ System Settings")

    from app.utils.config import load_api_config

    config = load_api_config() or {}

    st.subheader("AI Engine Configuration")
    col1, col2 = st.columns(2)
    with col1:
        st.write(f"**Provider:** {config.get('provider', 'Not set')}")
        st.write(f"**Model:** {config.get('model_name', 'Not set')}")
    with col2:
        has_key = bool(config.get("api_key"))
        st.write(f"**API Key:** {'✅ Configured' if has_key else '❌ Missing'}")
        has_tg = bool(config.get("tg_bot_token"))
        st.write(f"**Telegram:** {'✅ Configured' if has_tg else '❌ Missing'}")

    st.markdown("---")

    st.subheader("Database Info")
    db = get_db()
    stats = db.get_global_stats()
    st.write(f"**Database Path:** `{db.db_path}`")
    st.write(f"**Total Clients:** {stats.get('total_clients', 0)}")
    st.write(f"**Total Scans:** {stats.get('total_scans', 0)}")
    st.write(f"**Total Findings:** {stats.get('total_findings', 0)}")

    st.markdown("---")

    st.subheader("API Endpoints")
    st.code("uvicorn api.main:app --host 0.0.0.0 --port 8000", language="bash")
    st.write("**Docs:** http://localhost:8000/docs")
    st.write("**Health:** http://localhost:8000/health")
