import io
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

class PDFGenerator:
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.title_style = self.styles['Heading1']
        self.heading_style = self.styles['Heading2']
        self.normal_style = self.styles['Normal']
        
        self.custom_normal = ParagraphStyle(
            'CustomNormal',
            parent=self.styles['Normal'],
            spaceAfter=10
        )
        self.success_style = ParagraphStyle(
            'SuccessStyle',
            parent=self.styles['Normal'],
            textColor=colors.green,
            spaceAfter=5
        )
        self.error_style = ParagraphStyle(
            'ErrorStyle',
            parent=self.styles['Normal'],
            textColor=colors.red,
            spaceAfter=5
        )

    def generate_website_report(self, data: dict) -> bytes:
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        elements = []
        
        # Title
        elements.append(Paragraph("CyberOptimus - Website Security Report", self.title_style))
        elements.append(Spacer(1, 12))
        
        # Summary
        orig_url = data.get('original_url') or data.get('url')
        orig_host = data.get('original_host') or data.get('resolved_hostname') or data.get('domain')
        orig_ip = data.get('original_ip') or data.get('ip_address', 'N/A')
        fin_url = data.get('final_url') or data.get('url')
        fin_host = data.get('final_host') or data.get('final_domain') or orig_host
        fin_ip = data.get('final_ip') or orig_ip
        
        elements.append(Paragraph(f"Reconnaissance Target: {orig_host}", self.heading_style))
        elements.append(Paragraph(f"<b>Original Target:</b> {orig_url} (Host: {orig_host} | IP: {orig_ip})", self.custom_normal))
        elements.append(Paragraph(f"<b>Final Endpoint:</b> {fin_url} (Host: {fin_host} | IP: {fin_ip})", self.custom_normal))
        
        # Redirect Intelligence Block in PDF
        intel = data.get('redirect_intel', {})
        if intel:
            elements.append(Paragraph(f"<b>Redirect Classification:</b> {intel.get('classification', 'N/A')} [{intel.get('status', 'N/A')}]", self.heading_style))
            elements.append(Paragraph(f"<b>Risk Rationale:</b> {intel.get('rationale', 'N/A')}", self.custom_normal))
            
        # Hop Chain in PDF
        chain = data.get('response_chain', [])
        if chain:
            chain_str = " ➔ ".join([f"[{hop.get('status_code')}] {hop.get('url')} ({hop.get('ip', 'N/A')})" for hop in chain])
            elements.append(Paragraph(f"<b>Redirect Hop Chain:</b> {chain_str}", self.custom_normal))
            
        elements.append(Spacer(1, 12))
        elements.append(Paragraph(f"<b>Overall Grade:</b> {data.get('grade')} (Score: {data.get('risk_score')})", self.custom_normal))
        if data.get('score_explanation'):
            elements.append(Paragraph(f"Score Explanation: {data.get('score_explanation')}", self.custom_normal))
        
        # Severity Summary in PDF
        sev_sum = data.get('severity_summary', {})
        if sev_sum:
            elements.append(Paragraph(f"<b>Findings Severity Summary:</b> Critical: {sev_sum.get('Critical', 0)} | High: {sev_sum.get('High', 0)} | Medium: {sev_sum.get('Medium', 0)} | Low: {sev_sum.get('Low', 0)} | Info: {sev_sum.get('Info', 0)}", self.custom_normal))
            
        # Scoring Breakdown in PDF
        breakdown = data.get('scoring_breakdown', [])
        if breakdown:
            elements.append(Paragraph("<b>Scoring Calculation Breakdown:</b>", self.normal_style))
            for step in breakdown:
                elements.append(Paragraph(f"• {step}", self.custom_normal))
                
        # Header Summary in PDF
        h_sum = data.get('header_summary', {})
        if h_sum:
            elements.append(Paragraph(f"<b>Security Headers Summary:</b> Checked: {h_sum.get('checked', 0)} | Present: {h_sum.get('present', 0)} | Report Only: {h_sum.get('report_only', 0)} | Missing: {h_sum.get('missing', 0)} | Not Evaluated: {h_sum.get('not_tested', 0)}", self.custom_normal))
                
        elements.append(Spacer(1, 12))
        
        # Performance Observations (Decoupled)
        perf_obs = data.get('performance_observations', {})
        if perf_obs:
            elements.append(Paragraph("<b>Performance Observations (Telemetry Only - Excluded from Security Score):</b>", self.normal_style))
            elements.append(Paragraph(f"HTTP Response Time: {perf_obs.get('response_time_ms')} ms | DNS Lookup: {perf_obs.get('dns_lookup')} ms | TCP Connect: {perf_obs.get('tcp_connect')} ms | TLS Handshake: {perf_obs.get('tls_handshake')} ms | Total Duration: {perf_obs.get('total_scan_duration')} ms", self.custom_normal))

        elements.append(Spacer(1, 12))
        
        # Security Categories
        categories = data.get('categories', {})
        for cat_key, cat_name in [("headers", "HTTP Security Headers (25%)"),
                                  ("ssl", "SSL/TLS Security (25%)"), 
                                  ("redirects", "Redirect Intelligence (20%)"),
                                  ("dns", "DNS Health (15%)"), 
                                  ("cookies", "Cookie Security (10%)"),
                                  ("server", "Server Configuration (5%)")]:
            cat_data = categories.get(cat_key)
            if not cat_data:
                continue
                
            score_text = "N/A" if cat_data['score'] == "N/A" else f"{cat_data['score']}/100"
            status_text = f" [{cat_data.get('status', 'Not Evaluated')}]"
            elements.append(Paragraph(f"{cat_name} - Score: {score_text}{status_text}", self.heading_style))
            
            # Findings
            elements.append(Paragraph("Findings & Evidence:", self.normal_style))
            findings = cat_data.get('findings', [])
            if findings:
                for f in findings:
                    deduct_str = f" (-{f['deduction']} pts)" if f.get('deduction', 0) > 0 else ""
                    conf_str = f" [{f.get('confidence', 'Verified')}]"
                    msg = f"• [{f['severity']}]{conf_str} {f['message']}{deduct_str}"
                    if f['severity'] in ['Critical', 'High']:
                        elements.append(Paragraph(msg, self.error_style))
                    else:
                        elements.append(Paragraph(msg, self.custom_normal))
                    if f.get('evidence'):
                        elements.append(Paragraph(f"  <i>Evidence:</i> {f['evidence']}", self.custom_normal))
            else:
                elements.append(Paragraph("No findings reported.", self.custom_normal))
                
            elements.append(Spacer(1, 6))
            recs = cat_data.get('recommendations', [])
            if recs:
                elements.append(Paragraph("Recommendations:", self.normal_style))
                for rec in recs:
                    if isinstance(rec, dict):
                        rec_text = f"<b>{rec.get('title', 'Recommendation')}</b><br/>" \
                                   f"• <b>Why it matters:</b> {rec.get('why_it_matters', 'N/A')}<br/>" \
                                   f"• <b>Risk:</b> {rec.get('risk', 'N/A')}<br/>" \
                                   f"• <b>OWASP Reference:</b> {rec.get('owasp_ref', 'N/A')}<br/>" \
                                   f"• <b>Example:</b> {rec.get('example', 'N/A')}<br/>" \
                                   f"• <b>Expected Impact:</b> {rec.get('impact', 'N/A')}"
                        elements.append(Paragraph(rec_text, self.custom_normal))
                    else:
                        elements.append(Paragraph(f"• {rec}", self.custom_normal))
                
            elements.append(Spacer(1, 12))
            
        # SSL/TLS Certificate Details Section in PDF
        ssl_info = data.get('ssl', {})
        if ssl_info:
            elements.append(Paragraph("SSL/TLS Certificate Details", self.heading_style))
            elements.append(Paragraph(f"<b>Valid:</b> {'Yes' if ssl_info.get('valid') else 'No'}", self.custom_normal))
            elements.append(Paragraph(f"<b>TLS Version:</b> {ssl_info.get('tls_version', 'N/A')}", self.custom_normal))
            elements.append(Paragraph(f"<b>Subject:</b> {ssl_info.get('subject', 'N/A')}", self.custom_normal))
            elements.append(Paragraph(f"<b>Issuer:</b> {ssl_info.get('issuer', 'N/A')}", self.custom_normal))
            elements.append(Paragraph(f"<b>Expiration Date:</b> {ssl_info.get('expiration', 'N/A')}", self.custom_normal))
            days_rem = ssl_info.get('days_remaining', 'N/A')
            elements.append(Paragraph(f"<b>Days Remaining:</b> {days_rem if days_rem == 'N/A' else str(days_rem) + ' days'}", self.custom_normal))
            san_list = ssl_info.get('san', [])
            elements.append(Paragraph(f"<b>SAN Domains:</b> {', '.join(san_list) if san_list else 'None'}", self.custom_normal))
            if ssl_info.get('error'):
                elements.append(Paragraph(f"<b>SSL/TLS Error:</b> {ssl_info.get('error')}", self.error_style))
            elements.append(Spacer(1, 12))

        # Performance timing metrics section
        timings = data.get('timings', {})
        if timings:
            elements.append(Paragraph("Performance Timing Metrics", self.heading_style))
            elements.append(Paragraph(f"<b>DNS Lookup:</b> {timings.get('dns_lookup', 0.0)} ms", self.custom_normal))
            elements.append(Paragraph(f"<b>TCP Connection:</b> {timings.get('tcp_connect', 0.0)} ms", self.custom_normal))
            elements.append(Paragraph(f"<b>TLS Handshake:</b> {timings.get('tls_handshake', 0.0)} ms", self.custom_normal))
            elements.append(Paragraph(f"<b>Time to First Byte (TTFB):</b> {timings.get('ttfb', 0.0)} ms", self.custom_normal))
            elements.append(Paragraph(f"<b>Download Time:</b> {timings.get('download_time', 0.0)} ms", self.custom_normal))
            elements.append(Paragraph(f"<b>Total Response Time:</b> {timings.get('total_time', 0.0)} ms", self.custom_normal))
            elements.append(Spacer(1, 12))

        # Edge Intelligence Section
        elements.append(Paragraph("Edge Infrastructure & Security Intelligence", self.heading_style))
        elements.append(Paragraph(f"<b>CDN / Proxy / WAF Provider:</b> {data.get('cdn_provider', 'Direct / Unknown')}", self.custom_normal))
        elements.append(Paragraph(f"<b>HTTP Protocol Version:</b> {data.get('http_protocol', 'HTTP/1.1')}", self.custom_normal))
        elements.append(Paragraph(f"<b>IPv6 Support:</b> {'Available' if data.get('ipv6_supported') else 'IPv4 Only'}", self.custom_normal))
        elements.append(Paragraph(f"<b>OCSP Stapling Status:</b> {'Stapled' if ssl_info.get('ocsp_stapled') else 'Not Stapled'}", self.custom_normal))
        elements.append(Paragraph(f"<b>TLS Cipher Suite:</b> {ssl_info.get('cipher_suite', 'N/A')}", self.custom_normal))
        elements.append(Paragraph(f"<b>Certificate Transparency (CT):</b> {'Present (SCT list verified)' if ssl_info.get('sct_present') else 'Not Verified'}", self.custom_normal))
        elements.append(Spacer(1, 12))

        # Cookies Section in PDF
        cookies = data.get('cookies', [])
        if cookies:
            elements.append(Paragraph("Verified Cookies", self.heading_style))
            for c in cookies:
                h_only_str = "HttpOnly" if c.get('http_only') else "No HttpOnly"
                sec_str = "Secure" if c.get('secure') else "No Secure"
                expires_val = c.get('expires') or "Session"
                elements.append(Paragraph(f"• <b>{c.get('name')}</b> ({h_only_str} | {sec_str} | SameSite: {c.get('same_site')} | Domain: {c.get('domain', 'N/A')} | Expires: {expires_val})", self.custom_normal))
            elements.append(Spacer(1, 12))

        # Raw Technical & Network Data Section in PDF
        elements.append(Paragraph("Raw Technical & Network Data", self.heading_style))
        elements.append(Paragraph(f"<b>IP Address:</b> {data.get('ip_address', 'N/A')}", self.custom_normal))
        elements.append(Paragraph(f"<b>Status Code:</b> {data.get('status_code', 'N/A')}", self.custom_normal))
        elements.append(Paragraph(f"<b>Response Time:</b> {data.get('response_time_ms', '0')} ms", self.custom_normal))
        elements.append(Paragraph(f"<b>Server Software:</b> {data.get('server', 'N/A')}", self.custom_normal))
        
        # Redirect path
        chain = data.get('response_chain', [])
        if chain:
            chain_str = " → ".join([f"{hop['url']} ({hop['status_code']})" for hop in chain])
            elements.append(Paragraph(f"<b>Redirect Path:</b> {chain_str}", self.custom_normal))
        elements.append(Spacer(1, 12))
        
        # Raw Response Headers
        raw_headers = data.get('raw_headers', {})
        if raw_headers:
            elements.append(Paragraph("Raw Response Headers", self.heading_style))
            for k, v in raw_headers.items():
                elements.append(Paragraph(f"<b>{k}:</b> {v}", self.custom_normal))
            elements.append(Spacer(1, 12))

        doc.build(elements)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_bytes
