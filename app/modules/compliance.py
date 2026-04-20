"""
VURA Compliance Module — Regulatory Framework Mapping & Assessment
══════════════════════════════════════════════════════════════════════
Complete compliance mapping database for ISO 27001, NCA ECC, GDPR, PCI-DSS.
Generates compliance gap analysis reports from scan findings.

Usage:
    from app.modules.compliance import VuraCompliance

    comp = VuraCompliance()
    gaps = comp.assess_from_scan(scan_id=1)
    report = comp.generate_compliance_report(scan_id=1, frameworks=["nca_ecc", "iso_27001"])
"""

import os
import json
import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table

console = Console()

_PROJECT_ROOT = Path(__file__).resolve().parents[2]

# ═══════════════════════════════════════════════════════════════════════════════
# COMPLETE FRAMEWORK DATABASE
# ═══════════════════════════════════════════════════════════════════════════════

FRAMEWORKS = {
    # ══════════════════════════════════════════════════════════════════════════
    # NCA ECC — National Cybersecurity Authority Essential Cybersecurity Controls
    # الهيئة الوطنية للأمن السيبراني — الضوابط الأساسية
    # ══════════════════════════════════════════════════════════════════════════
    "nca_ecc": {
        "name": "NCA Essential Cybersecurity Controls (ECC)",
        "version": "2024",
        "country": "Saudi Arabia",
        "domains": {
            "1-1": {
                "name": "Cybersecurity Governance",
                "controls": {
                    "1-1-1": "Cybersecurity Strategy",
                    "1-1-2": "Cybersecurity Management",
                    "1-1-3": "Cybersecurity Policies and Procedures",
                    "1-1-4": "Cybersecurity Roles and Responsibilities",
                    "1-1-5": "Cybersecurity Awareness",
                },
            },
            "1-2": {
                "name": "Cybersecurity Defense",
                "controls": {
                    "1-2-1": "Asset Management",
                    "1-2-2": "Identity and Access Management",
                    "1-2-3": "Information System Protection",
                    "1-2-4": "Email Protection",
                    "1-2-5": "Network Security Management",
                    "1-2-6": "Mobile Device Security",
                },
            },
            "1-3": {
                "name": "Cybersecurity Resilience",
                "controls": {
                    "1-3-1": "Vulnerability Management",
                    "1-3-2": "Threat Management",
                    "1-3-3": "Cybersecurity Incident Management",
                    "1-3-4": "Business Continuity Management",
                },
            },
            "1-4": {
                "name": "Third-Party Cybersecurity",
                "controls": {
                    "1-4-1": "Third-Party Cybersecurity",
                    "1-4-2": "Cloud Computing Security",
                },
            },
            "1-5": {
                "name": "Industrial Control Systems",
                "controls": {
                    "1-5-1": "ICS/OT Cybersecurity",
                },
            },
        },
    },

    # ══════════════════════════════════════════════════════════════════════════
    # ISO 27001:2022 — Annex A Controls
    # ══════════════════════════════════════════════════════════════════════════
    "iso_27001": {
        "name": "ISO/IEC 27001:2022",
        "version": "2022",
        "country": "International",
        "domains": {
            "A.5": {
                "name": "Organizational Controls",
                "controls": {
                    "A.5.1": "Policies for information security",
                    "A.5.2": "Information security roles and responsibilities",
                    "A.5.3": "Segregation of duties",
                    "A.5.7": "Threat intelligence",
                    "A.5.23": "Information security for use of cloud services",
                    "A.5.29": "Information security during disruption",
                },
            },
            "A.6": {
                "name": "People Controls",
                "controls": {
                    "A.6.1": "Screening",
                    "A.6.3": "Information security awareness, education and training",
                    "A.6.5": "Responsibilities after termination",
                },
            },
            "A.7": {
                "name": "Physical Controls",
                "controls": {
                    "A.7.1": "Physical security perimeters",
                    "A.7.4": "Physical security monitoring",
                },
            },
            "A.8": {
                "name": "Technological Controls",
                "controls": {
                    "A.8.1": "User endpoint devices",
                    "A.8.2": "Privileged access rights",
                    "A.8.3": "Information access restriction",
                    "A.8.5": "Secure authentication",
                    "A.8.7": "Protection against malware",
                    "A.8.8": "Management of technical vulnerabilities",
                    "A.8.9": "Configuration management",
                    "A.8.10": "Information deletion",
                    "A.8.12": "Data leakage prevention",
                    "A.8.15": "Logging",
                    "A.8.16": "Monitoring activities",
                    "A.8.20": "Networks security",
                    "A.8.21": "Security of network services",
                    "A.8.22": "Segregation of networks",
                    "A.8.23": "Web filtering",
                    "A.8.24": "Use of cryptography",
                    "A.8.25": "Secure development life cycle",
                    "A.8.26": "Application security requirements",
                    "A.8.28": "Secure coding",
                    "A.8.34": "Protection of information systems during audit testing",
                },
            },
        },
    },

    # ══════════════════════════════════════════════════════════════════════════
    # PCI-DSS v4.0
    # ══════════════════════════════════════════════════════════════════════════
    "pci_dss": {
        "name": "PCI-DSS v4.0",
        "version": "4.0",
        "country": "International",
        "domains": {
            "Req1": {
                "name": "Install and maintain network security controls",
                "controls": {
                    "1.1": "Processes defined for network security controls",
                    "1.2": "Network security controls configured and maintained",
                    "1.3": "Network access to and from cardholder data environment restricted",
                },
            },
            "Req2": {
                "name": "Apply secure configurations to all system components",
                "controls": {
                    "2.1": "Processes defined for secure configurations",
                    "2.2": "System components configured and managed securely",
                },
            },
            "Req6": {
                "name": "Develop and maintain secure systems and software",
                "controls": {
                    "6.1": "Processes to identify security vulnerabilities",
                    "6.2": "Bespoke software developed securely",
                    "6.3": "Security vulnerabilities identified and addressed",
                    "6.4": "Public-facing web applications protected",
                    "6.5": "Changes managed securely",
                },
            },
            "Req8": {
                "name": "Identify users and authenticate access",
                "controls": {
                    "8.1": "Processes to identify and authenticate access defined",
                    "8.2": "User identification and accounts managed",
                    "8.3": "Strong authentication established",
                    "8.6": "Use of application and system accounts managed",
                },
            },
            "Req10": {
                "name": "Log and monitor all access",
                "controls": {
                    "10.1": "Processes to log and monitor defined",
                    "10.2": "Audit logs implemented",
                    "10.4": "Audit logs reviewed for anomalies",
                },
            },
            "Req11": {
                "name": "Test security of systems and networks regularly",
                "controls": {
                    "11.3": "External and internal penetration testing performed",
                    "11.4": "Intrusion detection mechanisms deployed",
                    "11.5": "Network intrusions and file changes detected and responded to",
                },
            },
        },
    },

    # ══════════════════════════════════════════════════════════════════════════
    # GDPR — General Data Protection Regulation
    # ══════════════════════════════════════════════════════════════════════════
    "gdpr": {
        "name": "GDPR (EU General Data Protection Regulation)",
        "version": "2016/679",
        "country": "European Union",
        "domains": {
            "Chapter_II": {
                "name": "Principles",
                "controls": {
                    "Art.5(1)(f)": "Integrity and confidentiality (security)",
                    "Art.5(2)": "Accountability",
                },
            },
            "Chapter_IV": {
                "name": "Controller and Processor",
                "controls": {
                    "Art.25": "Data protection by design and by default",
                    "Art.28": "Processor obligations",
                    "Art.30": "Records of processing activities",
                    "Art.32": "Security of processing",
                    "Art.33": "Notification of personal data breach to supervisory authority",
                    "Art.34": "Communication of personal data breach to data subject",
                    "Art.35": "Data protection impact assessment",
                },
            },
        },
    },

    # ══════════════════════════════════════════════════════════════════════════
    # OWASP Top 10 (2021)
    # ══════════════════════════════════════════════════════════════════════════
    "owasp": {
        "name": "OWASP Top 10 (2021)",
        "version": "2021",
        "country": "International",
        "domains": {
            "A01": {
                "name": "Broken Access Control",
                "controls": {
                    "A01:2021": "Broken Access Control",
                },
            },
            "A02": {
                "name": "Cryptographic Failures",
                "controls": {
                    "A02:2021": "Cryptographic Failures",
                },
            },
            "A03": {
                "name": "Injection",
                "controls": {
                    "A03:2021": "Injection (SQLi, XSS, Command Injection, etc.)",
                },
            },
            "A04": {
                "name": "Insecure Design",
                "controls": {
                    "A04:2021": "Insecure Design",
                },
            },
            "A05": {
                "name": "Security Misconfiguration",
                "controls": {
                    "A05:2021": "Security Misconfiguration",
                },
            },
            "A06": {
                "name": "Vulnerable and Outdated Components",
                "controls": {
                    "A06:2021": "Vulnerable and Outdated Components",
                },
            },
            "A07": {
                "name": "Identification and Authentication Failures",
                "controls": {
                    "A07:2021": "Identification and Authentication Failures",
                },
            },
            "A08": {
                "name": "Software and Data Integrity Failures",
                "controls": {
                    "A08:2021": "Software and Data Integrity Failures",
                },
            },
            "A09": {
                "name": "Security Logging and Monitoring Failures",
                "controls": {
                    "A09:2021": "Security Logging and Monitoring Failures",
                },
            },
            "A10": {
                "name": "Server-Side Request Forgery (SSRF)",
                "controls": {
                    "A10:2021": "Server-Side Request Forgery",
                },
            },
        },
    },
}
# ═══════════════════════════════════════════════════════════════════════════════
# يربط أنواع الثغرات/المشاكل الأمنية بـ controls محددة في كل framework

VULN_TO_CONTROLS = {
    "sql injection": {
        "nca_ecc": ["1-2-3", "1-3-1"],
        "iso_27001": ["A.8.25", "A.8.26", "A.8.28"],
        "pci_dss": ["6.2", "6.3"],
        "gdpr": ["Art.25", "Art.32"],
        "owasp": ["A03:2021"],
    },
    "cross-site scripting": {
        "nca_ecc": ["1-2-3"],
        "iso_27001": ["A.8.25", "A.8.28"],
        "pci_dss": ["6.2", "6.4"],
        "gdpr": ["Art.32"],
        "owasp": ["A03:2021"],
    },
    "xss": {
        "nca_ecc": ["1-2-3"],
        "iso_27001": ["A.8.25", "A.8.28"],
        "pci_dss": ["6.2", "6.4"],
        "gdpr": ["Art.32"],
        "owasp": ["A03:2021"],
    },
    "remote code execution": {
        "nca_ecc": ["1-3-1", "1-3-2"],
        "iso_27001": ["A.8.8", "A.8.25"],
        "pci_dss": ["6.1", "6.3"],
        "gdpr": ["Art.32", "Art.33"],
        "owasp": ["A03:2021"],
    },
    "command injection": {
        "nca_ecc": ["1-2-3", "1-3-1"],
        "iso_27001": ["A.8.25", "A.8.28"],
        "pci_dss": ["6.2", "6.3"],
        "gdpr": ["Art.32"],
        "owasp": ["A03:2021"],
    },
    "authentication bypass": {
        "nca_ecc": ["1-2-2"],
        "iso_27001": ["A.8.2", "A.8.5"],
        "pci_dss": ["8.2", "8.3"],
        "gdpr": ["Art.25", "Art.32"],
        "owasp": ["A07:2021"],
    },
    "default credentials": {
        "nca_ecc": ["1-2-2", "1-2-3"],
        "iso_27001": ["A.8.2", "A.8.5", "A.8.9"],
        "pci_dss": ["2.2", "8.3"],
        "gdpr": ["Art.32"],
        "owasp": ["A07:2021", "A05:2021"],
    },
    "weak password": {
        "nca_ecc": ["1-2-2"],
        "iso_27001": ["A.8.5"],
        "pci_dss": ["8.3"],
        "gdpr": ["Art.32"],
        "owasp": ["A07:2021"],
    },
    "brute force": {
        "nca_ecc": ["1-2-2", "1-3-2"],
        "iso_27001": ["A.8.5", "A.8.16"],
        "pci_dss": ["8.3", "10.2"],
        "gdpr": ["Art.32"],
        "owasp": ["A07:2021"],
    },
    "open port": {
        "nca_ecc": ["1-2-5"],
        "iso_27001": ["A.8.20", "A.8.22"],
        "pci_dss": ["1.2", "1.3"],
        "gdpr": ["Art.32"],
        "owasp": ["A05:2021"],
    },
    "unencrypted": {
        "nca_ecc": ["1-2-3"],
        "iso_27001": ["A.8.24"],
        "pci_dss": ["4.1"],
        "gdpr": ["Art.32"],
        "owasp": ["A02:2021"],
    },
    "ssl": {
        "nca_ecc": ["1-2-3"],
        "iso_27001": ["A.8.24"],
        "pci_dss": ["4.1"],
        "gdpr": ["Art.32"],
        "owasp": ["A02:2021"],
    },
    "tls": {
        "nca_ecc": ["1-2-3"],
        "iso_27001": ["A.8.24"],
        "pci_dss": ["4.1"],
        "gdpr": ["Art.32"],
        "owasp": ["A02:2021"],
    },
    "outdated software": {
        "nca_ecc": ["1-3-1"],
        "iso_27001": ["A.8.8", "A.8.9"],
        "pci_dss": ["6.1", "6.3"],
        "gdpr": ["Art.32"],
        "owasp": ["A06:2021"],
    },
    "missing patch": {
        "nca_ecc": ["1-3-1"],
        "iso_27001": ["A.8.8"],
        "pci_dss": ["6.3"],
        "gdpr": ["Art.32"],
        "owasp": ["A06:2021"],
    },
    "data exposure": {
        "nca_ecc": ["1-2-3"],
        "iso_27001": ["A.8.3", "A.8.12"],
        "pci_dss": ["3.4", "6.5"],
        "gdpr": ["Art.5(1)(f)", "Art.32", "Art.33"],
        "owasp": ["A01:2021", "A02:2021"],
    },
    "information disclosure": {
        "nca_ecc": ["1-2-3"],
        "iso_27001": ["A.8.3", "A.8.12"],
        "pci_dss": ["6.5"],
        "gdpr": ["Art.5(1)(f)"],
        "owasp": ["A01:2021"],
    },
    "directory listing": {
        "nca_ecc": ["1-2-3"],
        "iso_27001": ["A.8.9", "A.8.25"],
        "pci_dss": ["6.5"],
        "gdpr": ["Art.32"],
        "owasp": ["A01:2021", "A05:2021"],
    },
    "misconfiguration": {
        "nca_ecc": ["1-2-3"],
        "iso_27001": ["A.8.9"],
        "pci_dss": ["2.2"],
        "gdpr": ["Art.32"],
        "owasp": ["A05:2021"],
    },
    "missing header": {
        "nca_ecc": ["1-2-3"],
        "iso_27001": ["A.8.25"],
        "pci_dss": ["6.4"],
        "gdpr": ["Art.25"],
        "owasp": ["A05:2021"],
    },
    "privilege escalation": {
        "nca_ecc": ["1-2-2"],
        "iso_27001": ["A.8.2", "A.8.3"],
        "pci_dss": ["8.2", "8.6"],
        "gdpr": ["Art.32"],
        "owasp": ["A01:2021"],
    },
    "no logging": {
        "nca_ecc": ["1-3-3"],
        "iso_27001": ["A.8.15", "A.8.16"],
        "pci_dss": ["10.1", "10.2"],
        "gdpr": ["Art.5(2)"],
        "owasp": ["A09:2021"],
    },
    "phishing": {
        "nca_ecc": ["1-1-5", "1-2-4"],
        "iso_27001": ["A.6.3", "A.8.7"],
        "pci_dss": ["12.6"],
        "gdpr": ["Art.32"],
        "owasp": ["A07:2021"],
    },
}


# ═══════════════════════════════════════════════════════════════════════════════
# COMPLIANCE ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class VuraCompliance:
    """
    محرك تقييم الامتثال — يربط نتائج الفحص بالمعايير التنظيمية.
    """

    def __init__(self):
        self.frameworks = FRAMEWORKS
        self.mapping = VULN_TO_CONTROLS

    # ═══════════════════════════════════════════════════════════════════════
    # ASSESSMENT — تقييم من تقرير أو نص
    # ═══════════════════════════════════════════════════════════════════════

    def assess_from_text(self, report_content, frameworks=None):
        """
        تحليل نص تقرير واستخراج gaps الامتثال.

        Parameters:
            report_content : محتوى التقرير (Markdown string)
            frameworks     : قائمة المعايير (None = كلها)

        Returns:
            dict: {
                "matched_vulns": [...],
                "gaps": {framework: {control_id: {name, vulns}}},
                "summary": {framework: {total_controls, affected, compliance_pct}},
            }
        """
        active_frameworks = frameworks or list(self.frameworks.keys())
        content_lower = report_content.lower()

        # ── اكتشاف الثغرات في النص ──
        matched_vulns = []
        for vuln_keyword in self.mapping:
            if vuln_keyword in content_lower:
                matched_vulns.append(vuln_keyword)

        # ── ربط بالـ controls ──
        gaps = {fw: {} for fw in active_frameworks}

        for vuln in matched_vulns:
            vuln_mapping = self.mapping.get(vuln, {})
            for fw in active_frameworks:
                control_ids = vuln_mapping.get(fw, [])
                for ctrl_id in control_ids:
                    if ctrl_id not in gaps[fw]:
                        gaps[fw][ctrl_id] = {
                            "name": self._get_control_name(fw, ctrl_id),
                            "vulns": [],
                        }
                    if vuln not in gaps[fw][ctrl_id]["vulns"]:
                        gaps[fw][ctrl_id]["vulns"].append(vuln)

        # ── ملخص ──
        summary = {}
        for fw in active_frameworks:
            total = self._count_total_controls(fw)
            affected = len(gaps[fw])
            pct = round(((total - affected) / max(total, 1)) * 100, 1)
            summary[fw] = {
                "framework_name": self.frameworks[fw]["name"],
                "total_controls_checked": total,
                "affected_controls": affected,
                "compliance_percentage": pct,
            }

        return {
            "matched_vulns": matched_vulns,
            "gaps": gaps,
            "summary": summary,
        }

    def assess_from_scan(self, scan_id, frameworks=None):
        """
        تقييم من فحص محفوظ في قاعدة البيانات.

        Parameters:
            scan_id    : ID الفحص في VuraDB
            frameworks : قائمة المعايير

        Returns:
            dict: نفس format الـ assess_from_text
        """
        from app.core.database import VuraDB

        db = VuraDB()
        scan = db.get_scan(scan_id)
        db.close()

        if not scan:
            return {"error": f"Scan {scan_id} not found"}

        # قراءة التقرير
        report_path = scan.get("report_md")
        if not report_path or not os.path.exists(report_path):
            return {"error": f"Report file not found for scan {scan_id}"}

        with open(report_path, "r", encoding="utf-8") as f:
            content = f.read()

        return self.assess_from_text(content, frameworks)

    # ═══════════════════════════════════════════════════════════════════════
    # REPORT GENERATION — تقرير الامتثال
    # ═══════════════════════════════════════════════════════════════════════

    def generate_compliance_report(self, report_content=None, scan_id=None,
                                    frameworks=None, language="English"):
        """
        توليد تقرير امتثال كامل.

        يُعطى إما report_content (نص) أو scan_id (يقرأ من DB).

        Returns:
            str: تقرير Markdown كامل
        """
        # ── جلب التقييم ──
        if scan_id:
            assessment = self.assess_from_scan(scan_id, frameworks)
        elif report_content:
            assessment = self.assess_from_text(report_content, frameworks)
        else:
            return "# Error\nProvide either report_content or scan_id."

        if "error" in assessment:
            return f"# Error\n{assessment['error']}"

        # ── بناء التقرير ──
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report = []

        report.append("# VURA Compliance Gap Analysis Report")
        report.append(f"\n*Generated: {timestamp}*\n")

        # ── ملخص عام ──
        report.append("## Executive Summary\n")
        report.append("| Framework | Controls Checked | Gaps Found | Compliance |")
        report.append("|-----------|-----------------|------------|------------|")

        for fw, stats in assessment["summary"].items():
            name = stats["framework_name"]
            total = stats["total_controls_checked"]
            affected = stats["affected_controls"]
            pct = stats["compliance_percentage"]
            status = "🟢" if pct >= 80 else "🟡" if pct >= 60 else "🔴"
            report.append(f"| {name} | {total} | {affected} | {status} {pct}% |")

        report.append(f"\n**Vulnerability patterns detected:** {len(assessment['matched_vulns'])}")
        if assessment["matched_vulns"]:
            vulns_list = ", ".join(assessment["matched_vulns"])
            report.append(f"\n*Patterns:* {vulns_list}")

        # ── تفاصيل لكل framework ──
        for fw, gaps in assessment["gaps"].items():
            if not gaps:
                continue

            fw_name = self.frameworks[fw]["name"]
            report.append(f"\n---\n\n## {fw_name}\n")

            report.append("| Control ID | Control Name | Triggered By | Status |")
            report.append("|-----------|-------------|-------------|--------|")

            for ctrl_id, info in sorted(gaps.items()):
                vulns = ", ".join(info["vulns"])
                report.append(f"| {ctrl_id} | {info['name']} | {vulns} | ⚠️ Gap |")

        # ── توصيات ──
        report.append("\n---\n\n## Recommendations\n")
        report.append("### Immediate Actions (P1)")
        report.append("- Address all identified compliance gaps in Critical/High severity findings")
        report.append("- Implement missing security controls identified above")
        report.append("- Document remediation plans with assigned owners and deadlines\n")

        report.append("### Short-Term (P2)")
        report.append("- Conduct a formal gap assessment with qualified auditors")
        report.append("- Update security policies to address identified weaknesses")
        report.append("- Implement automated compliance monitoring\n")

        report.append("### Strategic (P3)")
        report.append("- Integrate compliance checks into CI/CD pipelines")
        report.append("- Establish continuous compliance monitoring program")
        report.append("- Schedule periodic third-party audits\n")

        # ── Disclaimer ──
        report.append("> **Disclaimer:** This report is AI-assisted and based on automated pattern matching. "
                      "It does NOT constitute a formal audit or certification. "
                      "Engage a qualified auditor for official compliance assessment.")

        return "\n".join(report)

    # ═══════════════════════════════════════════════════════════════════════
    # HELPERS
    # ═══════════════════════════════════════════════════════════════════════

    def _get_control_name(self, framework, control_id):
        """جلب اسم control من الـ database."""
        fw_data = self.frameworks.get(framework, {})
        for domain_id, domain in fw_data.get("domains", {}).items():
            controls = domain.get("controls", {})
            if control_id in controls:
                return controls[control_id]
        return control_id  # fallback: يرجع الـ ID نفسه

    def _count_total_controls(self, framework):
        """عدّ إجمالي الـ controls في framework."""
        total = 0
        fw_data = self.frameworks.get(framework, {})
        for domain in fw_data.get("domains", {}).values():
            total += len(domain.get("controls", {}))
        return total

    def list_frameworks(self):
        """قائمة المعايير المدعومة."""
        return {
            fw_id: {
                "name": fw["name"],
                "version": fw["version"],
                "country": fw["country"],
                "total_controls": self._count_total_controls(fw_id),
            }
            for fw_id, fw in self.frameworks.items()
        }

    def get_framework_details(self, framework):
        """تفاصيل framework كاملة."""
        return self.frameworks.get(framework)

    # ═══════════════════════════════════════════════════════════════════════
    # DISPLAY — عرض في Terminal
    # ═══════════════════════════════════════════════════════════════════════

    def show_frameworks(self):
        """عرض جدول المعايير المدعومة."""
        table = Table(title="VURA Supported Compliance Frameworks", show_header=True, header_style="bold magenta")
        table.add_column("ID", style="bold cyan")
        table.add_column("Framework")
        table.add_column("Version", justify="center")
        table.add_column("Country")
        table.add_column("Controls", justify="center")

        for fw_id, info in self.list_frameworks().items():
            table.add_row(
                fw_id,
                info["name"],
                info["version"],
                info["country"],
                str(info["total_controls"]),
            )

        console.print(table)

    def show_assessment(self, assessment):
        """عرض نتائج التقييم في Terminal."""
        if "error" in assessment:
            console.print(f"[red]{assessment['error']}[/red]")
            return

        # ── ملخص ──
        table = Table(title="VURA Compliance Assessment", show_header=True, header_style="bold magenta")
        table.add_column("Framework", style="bold cyan")
        table.add_column("Controls", justify="center")
        table.add_column("Gaps", justify="center")
        table.add_column("Compliance", justify="center")

        for fw, stats in assessment["summary"].items():
            pct = stats["compliance_percentage"]
            color = "green" if pct >= 80 else "yellow" if pct >= 60 else "red"
            table.add_row(
                stats["framework_name"],
                str(stats["total_controls_checked"]),
                str(stats["affected_controls"]),
                f"[{color}]{pct}%[/{color}]",
            )

        console.print(table)

        # ── ثغرات مكتشفة ──
        if assessment["matched_vulns"]:
            console.print(f"\n[bold yellow]Vulnerability patterns found: {', '.join(assessment['matched_vulns'])}[/bold yellow]")
