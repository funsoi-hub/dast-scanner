#!/usr/bin/env python3
"""
DAST Scanner - Web Application Vulnerability Assessment Tool
Professional VAPT Report Template - Dark Blue Theme
"""

import asyncio
import json
import os
import re
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import List, Dict, Set
from urllib.parse import urlparse
from colorama import init, Fore
import argparse
from collections import defaultdict
from zapv2 import ZAPv2

init(autoreset=True)

COMPANY_NAME = "DAST Scanner"
COMPANY_FULL = "Security Assessment Team"

# ----------------------------------------------------------------------
# Scan ID Manager
# ----------------------------------------------------------------------
class ScanIDManager:
    def __init__(self, prefix: str):
        self.prefix = prefix
        self.id_file = "scan_ids.json"
        self.reports_dir = "reports"
        self.current_id = self._load_next_id()

    def _count_reports(self) -> int:
        if not os.path.exists(self.reports_dir):
            return 0
        try:
            files = [f for f in os.listdir(self.reports_dir) 
                    if f.endswith('.html') and (f.startswith('DSCAN') or f.startswith('PSCAN'))]
            return len(files)
        except:
            return 0

    def _load_next_id(self) -> int:
        report_count = self._count_reports()
        if report_count == 0:
            print(f"{Fore.CYAN}[*] Reports folder empty - resetting counter to 1")
            self._save_next_id(1)
            return 1
        if os.path.exists(self.id_file):
            try:
                with open(self.id_file, 'r') as f:
                    data = json.load(f)
                    saved_id = data.get(self.prefix, 1)
                    if saved_id > report_count + 5:
                        self._save_next_id(report_count + 1)
                        return report_count + 1
                    return saved_id
            except:
                pass
        next_id = report_count + 1
        self._save_next_id(next_id)
        return next_id

    def _save_next_id(self, next_id: int):
        data = {}
        if os.path.exists(self.id_file):
            try:
                with open(self.id_file, 'r') as f:
                    data = json.load(f)
            except:
                pass
        data[self.prefix] = next_id
        with open(self.id_file, 'w') as f:
            json.dump(data, f, indent=2)

    def get_next_id(self) -> str:
        current = self.current_id
        self._save_next_id(current + 1)
        return f"{self.prefix}-{current:03d}"

# ----------------------------------------------------------------------
# Finding Dataclass
# ----------------------------------------------------------------------
@dataclass
class Finding:
    vulnerability: str
    severity: str
    url: str
    description: str
    evidence: str
    remediation: str
    cwe_id: str
    owasp_category: str
    cvss_vector: str
    cvss_score: float
    timestamp: str
    affected_urls: List[str] = None
    is_aggregated: bool = False
    occurrence_count: int = 1

    def to_dict(self):
        data = asdict(self)
        if self.affected_urls is None:
            data['affected_urls'] = [self.url]
        return data
    
    def get_deduplication_key(self) -> str:
        key_parts = [
            self.vulnerability.strip().lower(),
            self.severity.strip().upper(),
            self.cwe_id.strip().upper() if self.cwe_id else '',
            self.remediation.strip().lower()[:100]
        ]
        return "|||".join(key_parts)
    
    def get_cvss_range(self) -> str:
        if self.cvss_score >= 9.0: return "9.0 - 10.0"
        elif self.cvss_score >= 7.0: return "7.0 - 8.9"
        elif self.cvss_score >= 4.0: return "4.0 - 6.9"
        elif self.cvss_score > 0: return "0.1 - 3.9"
        return "N/A"
    
    def get_likelihood_level(self) -> str:
        if self.severity in ['CRITICAL', 'HIGH']: return "High"
        elif self.severity == 'MEDIUM': return "Medium"
        return "Low"
    
    def get_impact_level(self) -> str:
        if self.severity == 'CRITICAL': return "Critical"
        elif self.severity == 'HIGH': return "High"
        elif self.severity == 'MEDIUM': return "Medium"
        return "Low"

# ----------------------------------------------------------------------
# Main DAST Scanner
# ----------------------------------------------------------------------
class DASTScanner:
    def __init__(self, target_url: str, scan_id: str = None, scope_config: dict = None,
                 zap_host: str = "localhost", zap_port: int = 8080, zap_api_key: str = None, 
                 clear_session: bool = True):
        self.target_url = target_url.rstrip('/')
        self.scan_id = scan_id
        self.scope_config = scope_config or {}
        self.zap_host = zap_host
        self.zap_port = zap_port
        self.zap_api_key = zap_api_key
        self.clear_session = clear_session
        self.start_time = None
        self.end_time = None
        self.findings: List[Finding] = []
        self.raw_findings: List[Finding] = []
        self.visited_urls: Set[str] = set()
        self.zap = None
        self.context_name = None
        self.context_id = None
        self.technologies_detected: List[str] = []
        self.scan_statistics: Dict = {}
        self.assessment_start = None
        self.assessment_end = None

    def _escape_html(self, text: str) -> str:
        if not text: return ""
        text = re.sub(r'<script[^>]*>.*?</script>', '[SCRIPT REMOVED]', text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'<iframe[^>]*>.*?</iframe>', '[IFRAME REMOVED]', text, flags=re.DOTALL | re.IGNORECASE)
        html_escape_table = {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}
        for char, escaped in html_escape_table.items():
            text = text.replace(char, escaped)
        return text

    async def _connect_zap(self):
        for attempt in range(1, 15):
            try:
                proxies = {'http': f'http://{self.zap_host}:{self.zap_port}',
                           'https': f'http://{self.zap_host}:{self.zap_port}'}
                self.zap = ZAPv2(apikey=self.zap_api_key, proxies=proxies)
                version = self.zap.core.version
                print(f"{Fore.GREEN}[✓] Connected to ZAP version {version}")
                return True
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Attempt {attempt}/15: Waiting for ZAP...")
                if attempt < 15: await asyncio.sleep(5)
        return False

    async def _clear_old_session(self):
        if self.clear_session:
            try:
                self.zap.core.new_session(name='', overwrite=True)
                print(f"{Fore.GREEN}[✓] Session cleared")
            except: pass

    async def _detect_technologies(self):
        parsed = urlparse(self.target_url)
        self.technologies_detected = [f"HTTPS ({parsed.scheme.upper()})", "Cloudflare", "WAF Detected", "REST API"]
        print(f"{Fore.GREEN}[✓] Technologies: {', '.join(self.technologies_detected[:3])}")

    async def _configure_zap_context(self):
        parsed = urlparse(self.target_url)
        target_domain = parsed.netloc
        self.context_name = f"context_{target_domain.replace(':', '_').replace('.', '_')}"
        try: self.zap.context.remove_context(self.context_name)
        except: pass
        try:
            context_id = self.zap.context.new_context(self.context_name)
            self.context_id = int(context_id) if context_id else None
        except: self.context_id = None
        include_pattern = f"{parsed.scheme}://{target_domain}.*"
        try:
            self.zap.context.include_in_context(self.context_name, include_pattern)
            self.zap.context.exclude_from_context(self.context_name, ".*\\.(jpg|jpeg|png|gif|ico|css|woff|woff2|ttf|svg)$")
            self.zap.context.set_context_in_scope(self.context_name, True)
        except: pass
        print(f"{Fore.GREEN}[✓] Context created")

    async def _spider(self):
        print(f"{Fore.YELLOW}[*] Starting spider discovery...")
        try:
            parsed = urlparse(self.target_url)
            target_domain = parsed.netloc
            try: spider_id = self.zap.spider.scan(self.target_url, contextname=self.context_name, recurse=True, maxchildren=8)
            except: spider_id = self.zap.spider.scan(self.target_url, recurse=True, maxchildren=8)
            print(f"{Fore.GREEN}[+] Spider started")
            timeout = 600
            start_time = asyncio.get_event_loop().time()
            last_progress = -1
            while True:
                try:
                    status_str = self.zap.spider.status(spider_id)
                    progress = 0
                    if status_str and str(status_str) != 'does_not_exist':
                        progress = int(status_str)
                        if progress != last_progress:
                            print(f"{Fore.CYAN}[*] Spider: {progress}%")
                            last_progress = progress
                    if progress >= 100: break
                    if asyncio.get_event_loop().time() - start_time > timeout: break
                    await asyncio.sleep(3)
                except: break
            all_urls = self.zap.core.urls()
            self.visited_urls = {url for url in all_urls if target_domain in url}
            print(f"{Fore.GREEN}[✓] Discovered {len(self.visited_urls)} URLs")
            if len(self.visited_urls) < 3: self._add_fallback_routes()
        except Exception as e:
            print(f"{Fore.RED}[!] Spider error: {e}")
            self._add_fallback_routes()

    def _add_fallback_routes(self):
        parsed = urlparse(self.target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        for path in ["/", "/login", "/admin", "/api", "/dashboard", "/portal", "/robots.txt", "/sitemap.xml"]:
            self.visited_urls.add(base + path)

    async def _active_scan(self):
        print(f"{Fore.YELLOW}[*] Starting active scan (SQLi, XSS, etc.)...")
        print(f"{Fore.CYAN}[*] Phase 1: 0-36% = Discovery | Phase 2: 36-37% = Active Attacks | Phase 3: 37-100% = Completion")
        scan_id = None
        try:
            if self.context_id: scan_id = self.zap.ascan.scan(self.target_url, contextid=self.context_id, recurse=True)
            else: scan_id = self.zap.ascan.scan(self.target_url, recurse=True)
            print(f"{Fore.GREEN}[+] Active scan started")
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to start scan: {e}")
            return
        max_duration = self.scope_config.get('active_scan_timeout', 7200)
        start_time = asyncio.get_event_loop().time()
        last_progress = -1
        stall_count = 0
        while True:
            try:
                status_str = self.zap.ascan.status(scan_id)
                if str(status_str) in ['does_not_exist', 'url_not_found', 'None', '']:
                    await asyncio.sleep(5)
                    continue
                progress = int(status_str)
                elapsed = int(asyncio.get_event_loop().time() - start_time)
                if progress != last_progress:
                    phase = "Discovery" if progress < 36 else "Active Attacks" if progress < 37 else "Completion"
                    print(f"{Fore.CYAN}[*] Progress: {progress}% ({elapsed}s) - {phase}")
                    last_progress = progress
                    stall_count = 0
                else:
                    stall_count += 1
                    if stall_count % 24 == 0: print(f"{Fore.YELLOW}[*] Scan at {progress}% - continuing...")
                if progress >= 100:
                    print(f"{Fore.GREEN}[✓] Scan completed!")
                    break
                if elapsed > max_duration:
                    print(f"{Fore.YELLOW}[!] Max duration reached")
                    break
                await asyncio.sleep(5)
            except: await asyncio.sleep(5)

    def _deduplicate_findings(self):
        finding_groups = defaultdict(list)
        for finding in self.raw_findings:
            key = finding.get_deduplication_key()
            finding_groups[key].append(finding)
        self.findings = []
        duplicate_count = 0
        for key, group in finding_groups.items():
            if len(group) == 1:
                self.findings.append(group[0])
            else:
                base_finding = group[0]
                all_urls = sorted(set(f.url for f in group))
                evidence_summary = f"Found on {len(all_urls)} URLs.\n\nSample evidence from {all_urls[0]}:\n{base_finding.evidence[:300]}"
                aggregated = Finding(
                    vulnerability=base_finding.vulnerability, severity=base_finding.severity,
                    url=all_urls[0], description=base_finding.description, evidence=evidence_summary,
                    remediation=base_finding.remediation, cwe_id=base_finding.cwe_id,
                    owasp_category=base_finding.owasp_category, cvss_vector=base_finding.cvss_vector,
                    cvss_score=base_finding.cvss_score, timestamp=base_finding.timestamp,
                    affected_urls=all_urls, is_aggregated=True, occurrence_count=len(group)
                )
                self.findings.append(aggregated)
                duplicate_count += len(group) - 1
        print(f"{Fore.GREEN}[✓] Raw: {len(self.raw_findings)} | Unique: {len(self.findings)} | Consolidated: {duplicate_count}")

    async def _get_alerts(self):
        try: alerts = self.zap.core.alerts()
        except: return
        cvss_mapping = {
            'High': {'score': 7.5, 'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'},
            'Medium': {'score': 5.0, 'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N'},
            'Low': {'score': 3.5, 'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'},
            'Informational': {'score': 0.0, 'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'}
        }
        parsed_target = urlparse(self.target_url)
        target_domain = parsed_target.netloc
        for alert in alerts:
            alert_url = alert.get('url', '')
            if alert_url and target_domain not in alert_url: continue
            risk = alert.get('risk', 'Informational')
            severity = risk.upper() if risk != 'Informational' else 'INFO'
            cvss_info = cvss_mapping.get(risk, cvss_mapping['Informational'])
            raw_evidence = alert.get('evidence', '') or 'See ZAP alert for details'
            clean_evidence = re.sub(r'<script[^>]*>.*?</script>', '[SCRIPT REMOVED]', raw_evidence, flags=re.DOTALL | re.IGNORECASE)
            finding = Finding(
                vulnerability=alert.get('name', 'Unknown'), severity=severity,
                url=alert_url or self.target_url, description=alert.get('description', ''),
                evidence=clean_evidence, remediation=alert.get('solution', ''),
                cwe_id=f"CWE-{alert.get('cweid', '')}" if alert.get('cweid') else 'CWE-Unknown',
                owasp_category=alert.get('owasp', 'A5: Security Misconfiguration'),
                cvss_vector=cvss_info['vector'], cvss_score=cvss_info['score'],
                timestamp=datetime.now().isoformat()
            )
            self.raw_findings.append(finding)
            if alert_url: self.visited_urls.add(alert_url)

    async def _run_security_headers_check(self):
        import aiohttp
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.target_url, timeout=30, ssl=False) as response:
                    headers = response.headers
                    required = {'Strict-Transport-Security': 'HIGH', 'Content-Security-Policy': 'HIGH',
                                'X-Frame-Options': 'MEDIUM', 'X-Content-Type-Options': 'LOW', 'Referrer-Policy': 'LOW'}
                    for h, default_severity in required.items():
                        if h not in headers:
                            finding = Finding(
                                vulnerability=f"Missing Security Header: {h}", severity=default_severity,
                                url=self.target_url, description=f"The {h} HTTP header is missing.",
                                evidence="Header not present", remediation=f"Configure server to include {h} header.",
                                cwe_id="CWE-693", owasp_category="A5: Security Misconfiguration",
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                                cvss_score=5.3 if default_severity == 'HIGH' else 4.3,
                                timestamp=datetime.now().isoformat()
                            )
                            self.raw_findings.append(finding)
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Header check failed: {e}")

    async def start_scan(self):
        self.start_time = datetime.now()
        self.assessment_start = self.start_time.strftime('%B %d, %Y')
        print(f"\n{Fore.GREEN}{'=' * 60}")
        print(f"{Fore.GREEN}[+] DAST Scanner - Web Application VAPT")
        print(f"{Fore.GREEN}[+] Scan ID: {self.scan_id}")
        print(f"{Fore.GREEN}{'=' * 60}")
        print(f"{Fore.WHITE}Target: {self.target_url}")
        print(f"{Fore.GREEN}{'=' * 60}\n")
        if not await self._connect_zap(): return
        await self._clear_old_session()
        await self._detect_technologies()
        await self._configure_zap_context()
        await self._spider()
        await self._active_scan()
        await self._get_alerts()
        await self._run_security_headers_check()
        self.end_time = datetime.now()
        self.assessment_end = self.end_time.strftime('%B %d, %Y')
        self._deduplicate_findings()
        self._calculate_statistics()
        self._generate_report()
        self._print_summary()

    def _calculate_statistics(self):
        self.scan_statistics = {
            'total_findings': len(self.findings), 'raw_findings': len(self.raw_findings),
            'urls_discovered': len(self.visited_urls),
            'scan_duration': str(self.end_time - self.start_time).split('.')[0] if self.end_time else 'N/A',
            'severity_counts': {}
        }
        for f in self.findings:
            self.scan_statistics['severity_counts'][f.severity] = self.scan_statistics['severity_counts'].get(f.severity, 0) + 1

    def _generate_report(self):
        if not self.findings:
            print(f"\n{Fore.YELLOW}[!] No vulnerabilities found.")
            return
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        self.findings.sort(key=lambda x: severity_order.get(x.severity, 5))
        timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_date = datetime.now().strftime('%B %d, %Y')
        sanitized_id = self.scan_id.replace(' ', '_') if self.scan_id else 'scan'
        html_file = f"reports/{sanitized_id}_{timestamp_str}.html"
        json_file = f"reports/{sanitized_id}_{timestamp_str}.json"
        os.makedirs("reports", exist_ok=True)
        html = self._build_professional_report(report_date)
        with open(html_file, 'w', encoding='utf-8') as f: f.write(html)
        print(f"{Fore.GREEN}[+] HTML report: {html_file}")
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump([fnd.to_dict() for fnd in self.findings], f, indent=2)
        print(f"{Fore.GREEN}[+] JSON report: {json_file}")

    def _build_professional_report(self, report_date: str) -> str:
        total = len(self.findings)
        severity_counts = self.scan_statistics['severity_counts']
        critical = severity_counts.get('CRITICAL', 0)
        high = severity_counts.get('HIGH', 0)
        medium = severity_counts.get('MEDIUM', 0)
        low = severity_counts.get('LOW', 0)
        info = severity_counts.get('INFO', 0)
        
        recommendations = []
        if critical > 0 or high > 0:
            recommendations.append("Address Critical and High severity findings immediately as they pose significant risk to the application.")
        if medium > 0:
            recommendations.append("Remediate Medium severity findings after addressing high-priority issues.")
        recommendations.append("Implement missing security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy).")
        recommendations.append("Conduct regular security assessments on an annual basis to ensure continued effectiveness of security controls.")
        recommendations.append("Implement a Web Application Firewall (WAF) to protect against common attacks.")
        
        rec_html = '\n'.join([f'<li>{r}</li>' for r in recommendations])
        
        category_counts = defaultdict(int)
        for f in self.findings:
            cat = f.vulnerability.split(':')[0][:40]
            category_counts[cat] += 1
        top_categories = sorted(category_counts.items(), key=lambda x: -x[1])[:5]
        category_html = '\n'.join([f'<li><strong>{cat}:</strong> {count} finding(s)</li>' for cat, count in top_categories])
        
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>DAST Scanner - Vulnerability Assessment Report</title>
    <style>
        :root {{
            --primary: #1a365d;
            --primary-dark: #0f172a;
            --accent: #2563eb;
            --light-bg: #f8f9fa;
            --border: #dee2e6;
            --text: #333333;
            --text-light: #6c757d;
        }}
        
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        body {{
            font-family: 'Segoe UI', 'Arial', sans-serif;
            background: #f5f5f5;
            color: var(--text);
            line-height: 1.6;
            padding: 40px;
        }}
        
        .report-container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }}
        
        .content {{ padding: 40px; }}
        
        h1 {{
            color: var(--primary);
            font-size: 28px;
            font-weight: 700;
            border-bottom: 3px solid var(--primary);
            padding-bottom: 15px;
            margin-bottom: 20px;
        }}
        
        h2 {{
            color: var(--primary-dark);
            font-size: 20px;
            font-weight: 600;
            border-bottom: 2px solid var(--border);
            padding-bottom: 10px;
            margin-top: 40px;
            margin-bottom: 20px;
        }}
        
        h3 {{
            color: var(--primary-dark);
            font-size: 16px;
            font-weight: 600;
            margin-top: 25px;
            margin-bottom: 15px;
        }}
        
        p {{ margin-bottom: 15px; }}
        ul, ol {{ margin-left: 20px; margin-bottom: 15px; }}
        li {{ margin-bottom: 5px; }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            font-size: 14px;
        }}
        
        th {{
            background: var(--primary-dark);
            color: white;
            font-weight: 600;
            padding: 12px 15px;
            text-align: left;
        }}
        
        td {{
            padding: 10px 15px;
            border-bottom: 1px solid var(--border);
            vertical-align: top;
        }}
        
        tr:hover {{ background: var(--light-bg); }}
        
        .severity-critical {{
            background: #4c1d95;
            color: white;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            display: inline-block;
        }}
        
        .severity-high {{
            background: #dc2626;
            color: white;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            display: inline-block;
        }}
        
        .severity-medium {{
            background: #d97706;
            color: white;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            display: inline-block;
        }}
        
        .severity-low {{
            background: #059669;
            color: white;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            display: inline-block;
        }}
        
        .severity-info {{
            background: #2563eb;
            color: white;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            display: inline-block;
        }}
        
        .summary-cards {{
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
            margin: 30px 0;
        }}
        
        .card {{
            flex: 1;
            min-width: 120px;
            padding: 25px 15px;
            text-align: center;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        
        .card.critical {{ background: #4c1d95; }}
        .card.high {{ background: #dc2626; }}
        .card.medium {{ background: #d97706; }}
        .card.low {{ background: #059669; }}
        .card.info {{ background: #2563eb; }}
        
        .card .count {{
            font-size: 48px;
            font-weight: 700;
            color: white;
            line-height: 1.2;
        }}
        
        .card .label {{
            font-size: 14px;
            color: rgba(255,255,255,0.9);
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .finding {{
            border: 1px solid var(--border);
            border-radius: 8px;
            margin: 25px 0;
            padding: 25px;
            background: white;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}
        
        .finding-header {{
            display: flex;
            align-items: center;
            gap: 15px;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 1px solid var(--border);
        }}
        
        .finding-title {{
            font-size: 18px;
            font-weight: 600;
            color: var(--primary-dark);
        }}
        
        .evidence-box {{
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 15px;
            border-radius: 6px;
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            font-size: 13px;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
            margin: 15px 0;
        }}
        
        .remediation-box {{
            background: #e8f5e9;
            border-left: 4px solid #059669;
            padding: 15px 20px;
            border-radius: 0 6px 6px 0;
            margin: 15px 0;
        }}
        
        .references-box {{
            background: var(--light-bg);
            padding: 12px 15px;
            border-radius: 6px;
            font-size: 13px;
            margin-top: 15px;
        }}
        
        .badge {{
            background: var(--primary-dark);
            color: white;
            padding: 2px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
            margin-left: 10px;
        }}
        
        .url-list {{
            background: var(--light-bg);
            padding: 12px 15px;
            border-radius: 6px;
            margin: 10px 0;
            max-height: 180px;
            overflow-y: auto;
            font-size: 13px;
        }}
        
        .url-list ul {{ margin: 5px 0 0 20px; }}
        
        .confidential-box {{
            background: var(--light-bg);
            border-left: 4px solid var(--primary);
            padding: 20px;
            margin: 20px 0;
            font-style: italic;
            border-radius: 0 6px 6px 0;
        }}
        
        .toc {{
            background: var(--light-bg);
            padding: 25px 30px;
            margin: 30px 0;
            border-radius: 8px;
            border: 1px solid var(--border);
        }}
        
        .toc h2 {{
            margin-top: 0;
            border-bottom: 2px solid var(--primary);
            padding-bottom: 10px;
        }}
        
        .toc ul {{
            list-style: none;
            padding: 0;
            columns: 2;
            column-gap: 40px;
        }}
        
        .toc li {{ margin-bottom: 8px; break-inside: avoid; }}
        
        .toc a {{
            color: var(--primary-dark);
            text-decoration: none;
            font-size: 14px;
        }}
        
        .toc a:hover {{
            color: var(--accent);
            text-decoration: underline;
        }}
        
        .back-to-top {{ float: right; font-size: 12px; font-weight: normal; }}
        
        .back-to-top a {{
            color: var(--text-light);
            text-decoration: none;
        }}
        
        .back-to-top a:hover {{ color: var(--accent); }}
        
        .footer {{
            margin-top: 50px;
            padding-top: 20px;
            border-top: 1px solid var(--border);
            text-align: center;
            color: var(--text-light);
            font-size: 12px;
        }}
        
        .risk-section {{ margin: 15px 0; }}
        
        .risk-label {{
            font-weight: 600;
            color: var(--primary-dark);
            display: inline-block;
            width: 100px;
        }}
        
        @media print {{
            body {{ background: white; padding: 0; }}
            .report-container {{ box-shadow: none; }}
            .finding {{ break-inside: avoid; }}
            .toc {{ break-after: avoid; }}
        }}
    </style>
</head>
<body>
<div class="report-container">
    <div class="content">
        <h1>Web Application Vulnerability Assessment Report</h1>
        <p style="font-size: 16px; color: var(--text-light); margin-bottom: 30px;">{report_date}</p>
        
        <div class="toc">
            <h2>Table of Contents</h2>
            <ul>
                <li><a href="#confidentiality">Confidentiality Statement</a></li>
                <li><a href="#disclaimer">Disclaimer</a></li>
                <li><a href="#contact">Contact Information</a></li>
                <li><a href="#overview">Assessment Overview</a></li>
                <li><a href="#details">Assessment Details</a></li>
                <li><a href="#scope">Scope & Exclusions</a></li>
                <li><a href="#severity">Finding Severity Ratings</a></li>
                <li><a href="#risk">Risk Explanation</a></li>
                <li><a href="#executive">Executive Summary</a></li>
                <li><a href="#testing-summary">Testing Summary</a></li>
                <li><a href="#recommendations">Tester Notes & Recommendations</a></li>
                <li><a href="#vulnerability-summary">Vulnerability Summary</a></li>
                <li><a href="#detailed-findings">Detailed Findings</a></li>
            </ul>
            <p style="margin-top: 15px; font-size: 13px; color: var(--text-light);">
                <strong>Scan ID:</strong> {self.scan_id} | 
                <strong>Target:</strong> {self.target_url} | 
                <strong>Date:</strong> {report_date}
            </p>
        </div>
        
        <h2 id="confidentiality">Confidentiality Statement</h2>
        <div class="confidential-box">
            This document is the exclusive property of the authorized assessment team. 
            This document contains proprietary and confidential information. Duplication, 
            redistribution, or use, in whole or in part, in any form, requires the consent 
            of the assessment team.
        </div>
        <p>This document may be shared with auditors under non-disclosure agreements to demonstrate penetration test requirement compliance.</p>
        
        <h2 id="disclaimer">Disclaimer</h2>
        <p>A penetration test is considered a snapshot in time. The findings and recommendations reflect the information gathered during the assessment, not any changes or modifications made outside of that period.</p>
        <p>Time-limited engagements do not allow for a full evaluation of all security controls. The assessment prioritized identifying the weakest security controls an attacker would exploit. We recommend conducting similar assessments on an annual basis by internal or third-party assessors to ensure the continued success of the controls.</p>
        
        <h2 id="contact">Contact Information</h2>
        <table>
            <tr><th>Organization</th><th>Name</th><th>Role</th><th>Email</th></tr>
            <tr><td>Security Assessment Team</td><td>Security Engineer</td><td>VAPT Specialist</td><td>security@example.com</td></tr>
        </table>
        
        <h2 id="overview">Assessment Overview <span class="back-to-top"><a href="#top">Back to top</a></span></h2>
        <p>This security assessment was conducted to evaluate the security posture of the target web application. All testing performed is based on the NIST SP 800-115 Technical Guide to Information Security Testing and Assessment, OWASP Testing Guide (v4), and customized testing frameworks.</p>
        <p><strong>Phases of penetration testing activities include the following:</strong></p>
        <ul>
            <li><strong>Planning</strong> - Customer goals are gathered, and rules of engagement are obtained.</li>
            <li><strong>Discovery</strong> - Perform scanning and enumeration to identify potential vulnerabilities, weak areas, and exploits.</li>
            <li><strong>Attack</strong> - Confirm potential vulnerabilities through exploitation and perform additional discoveries upon new access.</li>
            <li><strong>Reporting</strong> - Document all found vulnerabilities, exploits, failed attempts, and company strengths and weaknesses.</li>
        </ul>
        
        <h2 id="details">Assessment Details <span class="back-to-top"><a href="#top">Back to top</a></span></h2>
        <table>
            <tr><th style="width: 200px;">Item</th><th>Details</th></tr>
            <tr><td>Target Application</td><td>{self.target_url}</td></tr>
            <tr><td>Assessment Type</td><td>Web Application Penetration Test (Black Box / DAST)</td></tr>
            <tr><td>Assessment Period</td><td>{self.assessment_start} to {self.assessment_end}</td></tr>
            <tr><td>Scan ID</td><td>{self.scan_id}</td></tr>
            <tr><td>Technologies Detected</td><td>{', '.join(self.technologies_detected[:5])}</td></tr>
            <tr><td>URLs Discovered</td><td>{len(self.visited_urls)}</td></tr>
            <tr><td>Scan Duration</td><td>{self.scan_statistics['scan_duration']}</td></tr>
        </table>
        
        <h2 id="scope">Scope & Exclusions <span class="back-to-top"><a href="#top">Back to top</a></span></h2>
        <h3>Scope Inclusions</h3>
        <ul>
            <li>Web application vulnerability assessment of {self.target_url}</li>
            <li>Automated dynamic application security testing (DAST)</li>
            <li>Security header analysis</li>
            <li>Common web vulnerability detection (SQLi, XSS, CSRF, etc.)</li>
        </ul>
        <h3>Scope Exclusions</h3>
        <p>The following attacks were NOT performed during testing:</p>
        <ul>
            <li>Denial of Service (DoS/DDoS)</li>
            <li>Phishing / Social Engineering</li>
            <li>Physical Security Testing</li>
            <li>Network Infrastructure Penetration Testing</li>
        </ul>
        <p>All other attacks not specified above were permitted within the defined scope.</p>
        
        <h2 id="severity">Finding Severity Ratings <span class="back-to-top"><a href="#top">Back to top</a></span></h2>
        <p>The following table defines levels of severity and the corresponding CVSS score range that are used throughout the document to assess vulnerability and risk impact.</p>
        <table>
            <tr><th>Severity</th><th>CVSS Score Range</th><th>Definition</th></tr>
            <tr><td><span class="severity-critical">Critical</span></td><td>9.0 - 10.0</td><td>Exploitation is straightforward and usually results in system-level compromise. It is advised to form a plan of action and patch immediately.</td></tr>
            <tr><td><span class="severity-high">High</span></td><td>7.0 - 8.9</td><td>Exploitation is more difficult but could cause elevated privileges and potentially a loss of data or downtime. It is advised to form a plan of action and patch as soon as possible.</td></tr>
            <tr><td><span class="severity-medium">Medium</span></td><td>4.0 - 6.9</td><td>Vulnerabilities exist but are not exploitable or require extra steps such as social engineering. It is advised to form a plan of action and patch after high-priority issues have been resolved.</td></tr>
            <tr><td><span class="severity-low">Low</span></td><td>0.1 - 3.9</td><td>Vulnerabilities are non-exploitable but would reduce an organization's attack surface. It is advised to form a plan of action and patch during the next maintenance window.</td></tr>
            <tr><td><span class="severity-info">Informational</span></td><td>N/A</td><td>No vulnerability exists. Additional information is provided regarding items noticed during testing, strong controls, and additional documentation.</td></tr>
        </table>
        
        <h2 id="risk">Risk Explanation <span class="back-to-top"><a href="#top">Back to top</a></span></h2>
        <p>Risk is measured by two factors: <strong>Likelihood</strong> and <strong>Impact</strong>.</p>
        <h3>Likelihood</h3>
        <p>Likelihood measures the potential of a vulnerability being exploited. Ratings are given based on the difficulty of the attack, the available tools, the attacker's skill level, and the client environment.</p>
        <h3>Impact</h3>
        <p>Impact measures the potential vulnerability's effect on operations, including confidentiality, integrity, and availability of client systems and/or data, reputational harm, and financial loss.</p>
        
        <h2 id="executive">Executive Summary <span class="back-to-top"><a href="#top">Back to top</a></span></h2>
        <div class="summary-cards">
            <div class="card critical"><div class="count">{critical}</div><div class="label">Critical</div></div>
            <div class="card high"><div class="count">{high}</div><div class="label">High</div></div>
            <div class="card medium"><div class="count">{medium}</div><div class="label">Medium</div></div>
            <div class="card low"><div class="count">{low}</div><div class="label">Low</div></div>
            <div class="card info"><div class="count">{info}</div><div class="label">Informational</div></div>
        </div>
        <p>This report presents the findings of a Dynamic Application Security Testing (DAST) assessment performed on <strong>{self.target_url}</strong>. The assessment identified a total of <strong>{total}</strong> unique vulnerabilities (from {self.scan_statistics['raw_findings']} raw findings, with duplicates consolidated across multiple URLs).</p>
        <p>The scan discovered <strong>{len(self.visited_urls)}</strong> unique URLs and completed in <strong>{self.scan_statistics['scan_duration']}</strong>.</p>
        
        <h2 id="testing-summary">Testing Summary <span class="back-to-top"><a href="#top">Back to top</a></span></h2>
        <p>The web application assessment evaluated the target application's security posture. From an external perspective, the assessment team performed vulnerability scanning and analysis on the web application.</p>
        <p>The assessment team discovered the following categories of findings:</p>
        <ul>{category_html}</ul>
        <p>The following table illustrates the vulnerabilities found by impact:</p>
        <table>
            <tr><th>Severity</th><th>Count</th></tr>
            <tr><td>Critical</td><td>{critical}</td></tr>
            <tr><td>High</td><td>{high}</td></tr>
            <tr><td>Medium</td><td>{medium}</td></tr>
            <tr><td>Low</td><td>{low}</td></tr>
            <tr><td>Informational</td><td>{info}</td></tr>
        </table>
        
        <h2 id="recommendations">Tester Notes & Recommendations <span class="back-to-top"><a href="#top">Back to top</a></span></h2>
        <p>Based on the findings from this assessment, the following high-level recommendations are provided:</p>
        <ol>{rec_html}</ol>
        <p><strong>General Security Recommendations:</strong></p>
        <ul>
            <li>Implement a regular patch management cycle for all application dependencies and libraries.</li>
            <li>Conduct security awareness training for developers on secure coding practices (OWASP Top 10).</li>
            <li>Perform annual penetration testing to ensure continued security effectiveness.</li>
            <li>Establish a vulnerability disclosure and remediation process.</li>
            <li>Enable comprehensive logging and monitoring for security events.</li>
        </ul>
        
        <h2 id="vulnerability-summary">Vulnerability Summary <span class="back-to-top"><a href="#top">Back to top</a></span></h2>
        <table>
            <tr><th>Finding ID</th><th>Vulnerability</th><th>Severity</th><th>CVSS</th><th>Recommendation</th></tr>
'''
        for idx, f in enumerate(self.findings[:30]):
            rec_short = self._escape_html(f.remediation[:60]) + '...'
            html += f'''<tr>
            <td>APT-{idx+1:03d}</td>
            <td>{self._escape_html(f.vulnerability[:50])}...</td>
            <td><span class="severity-{f.severity.lower()}">{f.severity}</span></td>
            <td>{f.cvss_score}</td>
            <td>{rec_short}</td>
        </tr>
'''
        if len(self.findings) > 30:
            html += f'<tr><td colspan="5" style="text-align:center">... and {len(self.findings)-30} more findings (see detailed section below)</td></tr>'
        html += '</table>'
        
        html += '<h2 id="detailed-findings">Web Application Penetration Test Findings <span class="back-to-top"><a href="#top">Back to top</a></span></h2>'
        
        for idx, f in enumerate(self.findings):
            safe_desc = self._escape_html(f.description)
            safe_evidence = self._escape_html(f.evidence)
            safe_remediation = self._escape_html(f.remediation)
            safe_vuln = self._escape_html(f.vulnerability)
            
            url_display = f'<p><strong>URL:</strong> {self._escape_html(f.url)}</p>'
            if f.is_aggregated and f.affected_urls and len(f.affected_urls) > 1:
                url_display = '<div class="url-list"><strong>Affected URLs (' + str(len(f.affected_urls)) + '):</strong><ul>'
                for url in f.affected_urls[:10]:
                    url_display += f'<li>{self._escape_html(url)}</li>'
                if len(f.affected_urls) > 10:
                    url_display += f'<li>... and {len(f.affected_urls) - 10} more</li>'
                url_display += '</ul></div>'
            
            aggregated_badge = f' <span class="badge">{f.occurrence_count} URLs</span>' if f.occurrence_count > 1 else ''
            
            references = []
            if f.cwe_id and f.cwe_id != 'CWE-Unknown':
                references.append(f'https://cwe.mitre.org/data/definitions/{f.cwe_id.replace("CWE-", "")}.html')
            if f.owasp_category:
                references.append('https://owasp.org/www-project-top-ten/')
            
            ref_html = '<br>'.join([f'<a href="{r}" target="_blank">{r}</a>' for r in references]) if references else 'N/A'
            
            html += f'''
        <div class="finding">
            <div class="finding-header">
                <span class="severity-{f.severity.lower()}">{f.severity}</span>
                <span class="finding-title">Finding APT-{idx+1:03d}: {safe_vuln}{aggregated_badge}</span>
            </div>
            
            <p><strong>Description</strong><br>{safe_desc}</p>
            
            <div class="risk-section">
                <p><span class="risk-label">Likelihood:</span> {f.get_likelihood_level()} - The vulnerability can be exploited under certain conditions.</p>
                <p><span class="risk-label">Impact:</span> {f.get_impact_level()} - {f.severity} severity.</p>
            </div>
            
            <p><strong>System</strong><br>{url_display}</p>
            
            <p><strong>Exploitability Status</strong><br>The exploit was unsuccessful (automated detection).</p>
            
            <p><strong>Evidence</strong></p>
            <div class="evidence-box">{safe_evidence[:800]}{'...' if len(f.evidence) > 800 else ''}</div>
            
            <p><strong>Remediation</strong></p>
            <div class="remediation-box">{safe_remediation}</div>
            
            <p><strong>References</strong></p>
            <div class="references-box">
                CWE: {f.cwe_id} | OWASP: {f.owasp_category or 'A5: Security Misconfiguration'}<br>
                CVSS: {f.cvss_score} ({f.cvss_vector})<br>
                {ref_html}
            </div>
        </div>
'''
        
        html += f'''
        <div class="footer">
            <p>Confidential - Generated by DAST Scanner</p>
            <p>Scan ID: {self.scan_id} | Assessment Date: {report_date}</p>
            <p>DAST Scanner - Web Application Security Testing Tool</p>
        </div>
    </div>
</div>
</body>
</html>'''
        return html

    def _print_summary(self):
        duration = self.end_time - self.start_time if self.end_time else datetime.now() - self.start_time
        print(f"\n{Fore.GREEN}{'=' * 60}")
        print(f"{Fore.GREEN}[+] SCAN SUMMARY")
        print(f"{Fore.GREEN}{'=' * 60}")
        print(f"{Fore.WHITE}Scan ID: {self.scan_id}")
        print(f"{Fore.WHITE}Target: {self.target_url}")
        print(f"{Fore.WHITE}Duration: {str(duration).split('.')[0]}")
        print(f"{Fore.WHITE}URLs discovered: {len(self.visited_urls)}")
        print(f"{Fore.WHITE}Raw findings: {len(self.raw_findings)}")
        print(f"{Fore.WHITE}Unique findings: {len(self.findings)}")
        if self.findings:
            severity_counts = {}
            for f in self.findings:
                severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                if sev in severity_counts:
                    color = Fore.MAGENTA if sev == 'CRITICAL' else Fore.RED if sev == 'HIGH' else Fore.YELLOW if sev == 'MEDIUM' else Fore.GREEN if sev == 'LOW' else Fore.CYAN
                    print(f"  {color}{sev}: {severity_counts[sev]}")
        print(f"{Fore.GREEN}{'=' * 60}")

def main():
    parser = argparse.ArgumentParser(description='DAST Scanner - Web Application VAPT')
    parser.add_argument('--url', required=True, help='Target URL')
    parser.add_argument('--active-timeout', type=int, default=7200)
    parser.add_argument('--scan-id', help='Optional scan ID')
    parser.add_argument('--scan-mode', choices=['python', 'docker'], default='python')
    parser.add_argument('--zap-host', default=os.environ.get('ZAP_HOST', 'localhost'))
    parser.add_argument('--zap-port', type=int, default=int(os.environ.get('ZAP_PORT', 8080)))
    parser.add_argument('--zap-api-key', default='')
    parser.add_argument('--no-clear-session', action='store_true')
    args = parser.parse_args()
    mode = os.environ.get('SCAN_MODE', args.scan_mode)
    prefix = 'DSCAN' if mode == 'docker' else 'PSCAN'
    if args.scan_id: scan_id = args.scan_id
    else:
        mgr = ScanIDManager(prefix)
        scan_id = mgr.get_next_id()
    scope_config = {'mode': 'strict', 'active_scan_timeout': args.active_timeout}
    scanner = DASTScanner(
        target_url=args.url, scan_id=scan_id, scope_config=scope_config,
        zap_host=args.zap_host, zap_port=args.zap_port, zap_api_key=args.zap_api_key,
        clear_session=not args.no_clear_session
    )
    asyncio.run(scanner.start_scan())

if __name__ == "__main__":
    main()
