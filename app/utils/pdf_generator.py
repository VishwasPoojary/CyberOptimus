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
        elements.append(Paragraph(f"Target URL: {data.get('url')}", self.heading_style))
        elements.append(Paragraph(f"Overall Grade: {data.get('grade')} (Score: {data.get('risk_score')})", self.custom_normal))
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
        
        # Categories
        categories = data.get('categories', {})
        for cat_key, cat_name in [("dns", "DNS Health"), ("ssl", "SSL/TLS Security"), 
                                  ("headers", "HTTP Security Headers"), 
                                  ("server", "Server Configuration"), 
                                  ("performance", "Performance")]:
            cat_data = categories.get(cat_key)
            if not cat_data:
                continue
                
            score_text = "N/A" if cat_data['score'] == "N/A" else f"{cat_data['score']}/100"
            status_text = f" [{cat_data.get('status', 'Not Evaluated')}]"
            elements.append(Paragraph(f"{cat_name} - Score: {score_text}{status_text}", self.heading_style))
            
            # Findings
            elements.append(Paragraph("Findings:", self.normal_style))
            findings = cat_data.get('findings', [])
            if findings:
                for f in findings:
                    deduct_str = f" (-{f['deduction']})" if f['deduction'] > 0 else ""
                    msg = f"• [{f['severity']}] {f['message']}{deduct_str}"
                    if f['severity'] in ['Critical', 'High']:
                        elements.append(Paragraph(msg, self.error_style))
                    else:
                        elements.append(Paragraph(msg, self.custom_normal))
            else:
                elements.append(Paragraph("• [Info] No security issues detected.", self.success_style))
                    
            # Recommendations
            elements.append(Paragraph("Recommendations:", self.normal_style))
            for rec in cat_data['recommendations']:
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
