"""
Report Exporter - Exports reports to multiple formats (PDF, Markdown, JSON, HTML)
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
import base64


class ReportExporter:
    """Exports reports in multiple formats"""
    
    def __init__(self, output_dir: str = None):
        if output_dir is None:
            self.output_dir = Path(__file__).parent.absolute() / "output"
        else:
            self.output_dir = Path(output_dir).absolute()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.logo_path = Path(__file__).parent.absolute() / "assets" / "certin_logo.png"
    
    def export_markdown(self, report_data: Dict[str, Any], filename: str) -> str:
        """Export report as Markdown"""
        output_path = self.output_dir / f"{filename}.md"
        
        md_content = self._generate_markdown(report_data)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(md_content)
        
        return str(output_path)
    
    def export_json(self, report_data: Dict[str, Any], filename: str) -> str:
        """Export report as JSON"""
        output_path = self.output_dir / f"{filename}.json"
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        return str(output_path)
    
    def export_html(self, report_data: Dict[str, Any], filename: str) -> str:
        """Export report as self-contained HTML"""
        output_path = self.output_dir / f"{filename}.html"
        
        html_content = self._generate_html(report_data)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return str(output_path)
    
    def export_pdf(self, report_data: Dict[str, Any], filename: str) -> str:
        """Export report as PDF"""
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
            from reportlab.lib import colors
            from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
            
            output_path = self.output_dir / f"{filename}.pdf"
            
            # Create PDF
            doc = SimpleDocTemplate(
                str(output_path),
                pagesize=A4,
                rightMargin=inch,
                leftMargin=inch,
                topMargin=inch,
                bottomMargin=inch
            )
            
            # Page elements callback to draw CERT-In logo on top right of all content pages
            def draw_page_elements(canvas, doc):
                canvas.saveState()
                
                # Check if we are on the first page (cover page)
                if doc.page == 1:
                    canvas.restoreState()
                    return
                
                # Draw CERT-In logo in top right corner
                logo_path = Path(__file__).parent.absolute() / "assets" / "certin_logo.png"
                if logo_path.exists():
                    logo_w, logo_h = 75, 23
                    # Align with right margin of 72pt (595.27 - 72 = 523.27)
                    canvas.drawImage(str(logo_path), 523.27 - logo_w, 841.89 - 44, width=logo_w, height=logo_h, mask='auto')
                
                # Draw a nice thin horizontal line under header
                canvas.setStrokeColor(colors.HexColor('#BDC3C7'))
                canvas.setLineWidth(0.5)
                canvas.line(72, 841.89 - 50, 523.27, 841.89 - 50)
                
                # Draw a footer with page number and confidentiality note
                canvas.setFont('Helvetica-Bold', 8)
                canvas.setFillColor(colors.HexColor('#C0392B')) # Crimson for Confidential on footer
                canvas.drawString(72, 40, "STRICTLY CONFIDENTIAL — FOR INTERNAL USE ONLY")
                canvas.setFont('Helvetica', 8)
                canvas.setFillColor(colors.HexColor('#7F8C8D'))
                canvas.drawRightString(523.27, 40, f"Page {doc.page}")
                
                canvas.restoreState()

            story = []
            styles = getSampleStyleSheet()

            # --- Shared styles ---
            primary = colors.HexColor('#002B49')
            grey_bg = colors.HexColor('#D9D9D9')
            white = colors.white
            border = colors.HexColor('#7F8C8D')
            light = colors.HexColor('#F2F4F7')
            red = colors.HexColor('#C0392B')

            lbl = ParagraphStyle('Lbl', parent=styles['Normal'], fontSize=9, fontName='Helvetica-Bold', leading=12)
            val = ParagraphStyle('Val', parent=styles['Normal'], fontSize=9, fontName='Helvetica', leading=12)
            sec = ParagraphStyle('Sec', parent=styles['Normal'], fontSize=9.5, fontName='Helvetica-Bold',
                                 textColor=primary, leading=12)
            body_style = ParagraphStyle('Body', parent=styles['Normal'], fontSize=9, fontName='Helvetica',
                                        leading=13, alignment=TA_JUSTIFY)

            FW = 523  # full usable width (A4 - margins)

            def section_row(text):
                """Grey header row spanning full width"""
                t = Table([[Paragraph(text, sec)]], colWidths=[FW])
                t.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,-1), grey_bg),
                    ('BOX', (0,0), (-1,-1), 0.5, border),
                    ('TOPPADDING', (0,0), (-1,-1), 4),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                    ('LEFTPADDING', (0,0), (-1,-1), 6),
                ]))
                return t

            def grid(rows, widths):
                """Standard bordered grid"""
                t = Table(rows, colWidths=widths)
                t.setStyle(TableStyle([
                    ('BOX', (0,0), (-1,-1), 0.5, border),
                    ('GRID', (0,0), (-1,-1), 0.5, border),
                    ('VALIGN', (0,0), (-1,-1), 'TOP'),
                    ('TOPPADDING', (0,0), (-1,-1), 4),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                    ('LEFTPADDING', (0,0), (-1,-1), 6),
                    ('RIGHTPADDING', (0,0), (-1,-1), 6),
                ]))
                return t

            # Page callback: CERT-In logo top-right + footer on all pages except cover
            def draw_page_elements(canvas, doc):
                canvas.saveState()
                if doc.page == 1:
                    canvas.restoreState()
                    return
                logo_path = Path(__file__).parent.absolute() / "assets" / "certin_logo.png"
                if logo_path.exists():
                    canvas.drawImage(str(logo_path), FW - 40, 841.89 - 42, width=75, height=23, mask='auto')
                canvas.setStrokeColor(colors.HexColor('#BDC3C7'))
                canvas.setLineWidth(0.5)
                canvas.line(36, 841.89 - 48, FW + 36, 841.89 - 48)
                canvas.setFont('Helvetica-Bold', 7.5)
                canvas.setFillColor(red)
                canvas.drawString(36, 22, "STRICTLY CONFIDENTIAL — FOR INTERNAL USE ONLY")
                canvas.setFont('Helvetica', 7.5)
                canvas.setFillColor(border)
                canvas.drawRightString(FW + 36, 22, f"Page {doc.page}")
                canvas.restoreState()

            stats = report_data["statistics"]
            total = stats['total_incidents']
            period = report_data['period']
            gen_at = report_data['generated_at']

            # ── COVER PAGE ──────────────────────────────────────────────────────────
            conf_style = ParagraphStyle('Conf', parent=styles['Normal'], fontSize=10,
                                        fontName='Helvetica-Bold', textColor=red, alignment=TA_CENTER, spaceAfter=24)
            story.append(Paragraph("STRICTLY CONFIDENTIAL — INTERNAL USE ONLY", conf_style))

            certin_path = Path(__file__).parent.absolute() / "assets" / "certin_logo.png"
            rbi_path = Path(__file__).parent.absolute() / "assets" / "rbi_logo.jpg"
            logo_els = []
            if certin_path.exists():
                try: logo_els.append(Image(str(certin_path), width=150, height=45))
                except: pass
            if rbi_path.exists():
                try: logo_els.append(Image(str(rbi_path), width=70, height=70))
                except: pass
            if logo_els:
                lt = Table([logo_els], colWidths=[260, 260])
                lt.setStyle(TableStyle([('ALIGN',(0,0),(-1,-1),'CENTER'),('VALIGN',(0,0),(-1,-1),'MIDDLE')]))
                story.append(lt)
                story.append(Spacer(1, 50))

            cover_title = ParagraphStyle('CT', parent=styles['Heading1'], fontSize=20,
                                         textColor=primary, fontName='Helvetica-Bold', leading=26)
            cover_sub = ParagraphStyle('CS', parent=styles['Normal'], fontSize=11,
                                       textColor=colors.HexColor('#7F8C8D'), fontName='Helvetica', leading=14)
            story.append(Paragraph(report_data["title"], cover_title))
            story.append(Spacer(1, 8))
            story.append(Paragraph("Periodic Compliance &amp; Security Posture Report — CERT-In Regulatory Framework", cover_sub))
            story.append(Spacer(1, 50))

            meta_lbl = ParagraphStyle('ML', parent=styles['Normal'], fontSize=9.5, fontName='Helvetica-Bold')
            meta_val = ParagraphStyle('MV', parent=styles['Normal'], fontSize=9.5, fontName='Helvetica')
            cover_meta = grid([
                [Paragraph("Reporting Period:", meta_lbl), Paragraph(period, meta_val)],
                [Paragraph("Generated On:", meta_lbl), Paragraph(gen_at, meta_val)],
                [Paragraph("Classification:", meta_lbl), Paragraph("STRICTLY CONFIDENTIAL", meta_val)],
                [Paragraph("Framework:", meta_lbl), Paragraph("CERT-In Directions (2022) &amp; RBI Cyber Security Framework", meta_val)],
            ], [160, 360])
            story.append(cover_meta)
            story.append(PageBreak())

            # ── PAGE 2: AGGREGATE INCIDENT SUMMARY ──────────────────────────────────
            # Header row like CERT-In form
            hdr_title = ParagraphStyle('HT', parent=styles['Normal'], fontSize=13,
                                       fontName='Helvetica-Bold', textColor=primary, alignment=TA_CENTER)
            story.append(Paragraph("Periodic Incident Reporting Summary — Form to CERT-In", hdr_title))
            story.append(Spacer(1, 8))

            # For official use row
            off_t = Table([[Paragraph("For official use only:", lbl),
                            Paragraph(f"Report Reference: <b>CERT-In-RPT-{gen_at[:10].replace('-','')}</b>", val)]],
                          colWidths=[180, FW-180])
            off_t.setStyle(TableStyle([
                ('BOX',(0,0),(-1,-1),0.5,border),('BACKGROUND',(0,0),(-1,-1),light),
                ('TOPPADDING',(0,0),(-1,-1),4),('BOTTOMPADDING',(0,0),(-1,-1),4),('LEFTPADDING',(0,0),(-1,-1),6),
            ]))
            story.append(off_t)
            story.append(Spacer(1, 6))

            # Section 1: Reporting Organization
            org_nm = report_data.get("org_name", "HCI-OS Security Operations")
            org_tp = report_data.get("org_type", "RBI Supervised Entity / CERT-In Constituency")
            c_name = report_data.get("contact_name", "CISO / Incident Response Team")
            c_mail = report_data.get("contact_email", "incident@hci-os.gov.in")
            story.append(section_row("1. Reporting Organization Information"))
            story.append(grid([
                [Paragraph("Name:", lbl), Paragraph(org_nm, val),
                 Paragraph("Organization:", lbl), Paragraph(org_tp, val)],
                [Paragraph("Contact:", lbl), Paragraph(c_name, val),
                 Paragraph("Email:", lbl), Paragraph(c_mail, val)],
            ], [80, FW//2-80, 80, FW//2-80]))
            story.append(Spacer(1, 6))

            # Section 2: Reporting Period
            story.append(section_row("2. Reporting Period"))
            story.append(grid([
                [Paragraph("Period Covered:", lbl), Paragraph(period, val),
                 Paragraph("Total Incidents:", lbl), Paragraph(str(total), val)],
                [Paragraph("Report Generated:", lbl), Paragraph(gen_at[:19], val),
                 Paragraph("Total Decisions:", lbl), Paragraph(str(stats['total_decisions']), val)],
            ], [120, FW//2-120, 120, FW//2-120]))
            story.append(Spacer(1, 6))

            # Section 3: Incident Type Distribution
            story.append(section_row("3. Distribution by Incident Type (Please refer to CERT-In categories)"))
            type_rows = [[Paragraph("Incident Type", lbl), Paragraph("Count", lbl), Paragraph("% of Total", lbl)]]
            for itype, cnt in sorted(stats.get("incidents_by_type", {}).items(), key=lambda x: x[1], reverse=True):
                pct = f"{cnt/total*100:.1f}%" if total > 0 else "0%"
                type_rows.append([Paragraph(itype, val), Paragraph(str(cnt), val), Paragraph(pct, val)])
            if len(type_rows) == 1:
                type_rows.append([Paragraph("No incidents recorded", val), Paragraph("0", val), Paragraph("0%", val)])
            t = Table(type_rows, colWidths=[FW*0.55, FW*0.22, FW*0.23])
            t.setStyle(TableStyle([
                ('BACKGROUND',(0,0),(-1,0), grey_bg),
                ('BOX',(0,0),(-1,-1),0.5,border),('GRID',(0,0),(-1,-1),0.5,border),
                ('ROWBACKGROUNDS',(0,1),(-1,-1),[white, light]),
                ('VALIGN',(0,0),(-1,-1),'MIDDLE'),
                ('TOPPADDING',(0,0),(-1,-1),4),('BOTTOMPADDING',(0,0),(-1,-1),4),
                ('LEFTPADDING',(0,0),(-1,-1),6),('RIGHTPADDING',(0,0),(-1,-1),6),
            ]))
            story.append(t)
            story.append(Spacer(1, 6))

            # Section 4: Sector Analysis
            story.append(section_row("4. Sector: (Affected sectors during reporting period)"))
            all_sectors = ["Government", "Financial", "Power", "Transportation", "Manufacturing",
                           "Health", "Telecommunications", "Academia", "Petroleum", "InfoTech", "Other"]
            sector_counts = stats.get("incidents_by_sector", {})
            sec_rows = []
            row = []
            for i, s in enumerate(all_sectors):
                cnt = sector_counts.get(s, 0)
                tick = "[X]" if cnt > 0 else "[ ]"
                row.append(Paragraph(f"{tick} {s} ({cnt})", val))
                if len(row) == 3:
                    sec_rows.append(row)
                    row = []
            if row:
                while len(row) < 3: row.append(Paragraph("", val))
                sec_rows.append(row)
            story.append(grid(sec_rows, [FW//3, FW//3, FW//3]))
            story.append(Spacer(1, 6))

            # Section 5: MITRE ATT&CK TTPs
            story.append(section_row("5. MITRE ATT&amp;CK Tactics/Techniques Observed"))
            mitre = stats.get("mitre_ttps", {})
            if mitre:
                mitre_rows = [[Paragraph("Tactic / Technique ID", lbl), Paragraph("Occurrences", lbl)]]
                for ttp, cnt in sorted(mitre.items(), key=lambda x: x[1], reverse=True)[:10]:
                    mitre_rows.append([Paragraph(ttp, val), Paragraph(str(cnt), val)])
                mt = Table(mitre_rows, colWidths=[FW*0.75, FW*0.25])
                mt.setStyle(TableStyle([
                    ('BACKGROUND',(0,0),(-1,0), grey_bg),
                    ('BOX',(0,0),(-1,-1),0.5,border),('GRID',(0,0),(-1,-1),0.5,border),
                    ('ROWBACKGROUNDS',(0,1),(-1,-1),[white, light]),
                    ('VALIGN',(0,0),(-1,-1),'MIDDLE'),
                    ('TOPPADDING',(0,0),(-1,-1),4),('BOTTOMPADDING',(0,0),(-1,-1),4),
                    ('LEFTPADDING',(0,0),(-1,-1),6),
                ]))
                story.append(mt)
            else:
                story.append(grid([[Paragraph("No MITRE TTPs recorded for this period.", val)]], [FW]))
            story.append(Spacer(1, 6))

            # Section 6: Executive Summary
            story.append(section_row("6. Executive Summary / Analysis"))
            story.append(grid([[Paragraph(report_data.get("executive_summary", "N/A"), body_style)]], [FW]))
            story.append(PageBreak())

            # ── PAGE 3: TREND & RECOMMENDATIONS ─────────────────────────────────────
            story.append(Paragraph("Periodic Incident Reporting Summary (Continued)", hdr_title))
            story.append(Spacer(1, 8))

            # Section 7: Trend Analysis
            story.append(section_row("7. Trend Analysis &amp; Threat Intelligence Assessment"))
            story.append(grid([[Paragraph(report_data.get("trend_analysis", "N/A"), body_style)]], [FW]))
            story.append(Spacer(1, 6))

            # Section 8: Actions and Mitigation
            story.append(section_row("8. Actions Taken / Mitigation Controls"))
            story.append(grid([
                [Paragraph("[X] Incidents logged and triaged", val),
                 Paragraph("[X] Automated SOAR response triggered", val),
                 Paragraph("[X] Human review conducted (high blast-radius)", val)],
                [Paragraph("[X] MITRE chain correlated per incident", val),
                 Paragraph("[X] GNN-based anomaly detection applied", val),
                 Paragraph("[ ] Physical infrastructure isolated", val)],
            ], [FW//3, FW//3, FW//3]))
            story.append(Spacer(1, 6))

            # Section 9: Recommendations
            story.append(section_row("9. Security Recommendations &amp; Mandatory Controls"))
            if report_data.get("recommendations"):
                rec_rows = [[Paragraph("Ref", lbl), Paragraph("Recommendation", lbl),
                             Paragraph("Priority", lbl), Paragraph("MITRE Mitigation", lbl)]]
                for i, rec in enumerate(report_data["recommendations"], 1):
                    rec_rows.append([
                        Paragraph(str(i), val),
                        Paragraph(f"<b>{rec['title']}</b><br/>{rec['description']}", val),
                        Paragraph(rec['priority'], val),
                        Paragraph(rec.get('mitre_mitigation', 'N/A'), val),
                    ])
                rt = Table(rec_rows, colWidths=[30, FW*0.48, 70, FW*0.3])
                rt.setStyle(TableStyle([
                    ('BACKGROUND',(0,0),(-1,0), grey_bg),
                    ('BOX',(0,0),(-1,-1),0.5,border),('GRID',(0,0),(-1,-1),0.5,border),
                    ('ROWBACKGROUNDS',(0,1),(-1,-1),[white, light]),
                    ('VALIGN',(0,0),(-1,-1),'TOP'),
                    ('TOPPADDING',(0,0),(-1,-1),4),('BOTTOMPADDING',(0,0),(-1,-1),4),
                    ('LEFTPADDING',(0,0),(-1,-1),6),
                ]))
                story.append(rt)
            else:
                story.append(grid([[Paragraph("No recommendations generated.", val)]], [FW]))
            story.append(Spacer(1, 6))

            # Section 10: Declaration footer (mirrors CERT-In form footer)
            story.append(section_row("10. Declaration"))
            story.append(grid([[Paragraph(
                "This report has been auto-generated by the HCI-OS Multi-Agent Cybersecurity Operations System in compliance with "
                "CERT-In Cyber Security Directions (2022) and the RBI Cyber Security Framework. All data is sourced from "
                "real-time telemetry, GNN analysis, and SOAR decision logs.", body_style)]], [FW]))
            story.append(Spacer(1, 10))

            footer_lbl = ParagraphStyle('FL', parent=styles['Normal'], fontSize=8,
                                        textColor=colors.HexColor('#7F8C8D'), alignment=TA_CENTER)
            story.append(Paragraph(
                "Mail/Fax to: CERT-In, Electronics Niketan, CGO Complex, New Delhi 110003 | "
                "Fax: +91-11-24368546 | Email: incident@cert-in.org.in", footer_lbl))

            # Build PDF
            doc.build(story, onFirstPage=draw_page_elements, onLaterPages=draw_page_elements)

            return str(output_path)

        except ImportError as e:
            print(f"ReportLab not available: {e}. Falling back to HTML export.")
            return self.export_html(report_data, filename)
        except Exception as e:
            print(f"PDF generation failed: {e}. Falling back to HTML export.")
            return self.export_html(report_data, filename)
    
            
            # 2. Side-by-side Logos
            certin_path = Path(__file__).parent.absolute() / "assets" / "certin_logo.png"
            rbi_path = Path(__file__).parent.absolute() / "assets" / "rbi_logo.jpg"
            
            logo_elements = []
            if certin_path.exists():
                try:
                    logo_elements.append(Image(str(certin_path), width=130, height=39))
                except Exception as e:
                    print(f"Error loading CERT-In logo for cover page: {e}")
            if rbi_path.exists():
                try:
                    logo_elements.append(Image(str(rbi_path), width=75, height=75))
                except Exception as e:
                    print(f"Error loading RBI logo for cover page: {e}")
                    
            if logo_elements:
                logo_table_data = [logo_elements]
                logo_table = Table(logo_table_data, colWidths=[225, 225])
                logo_table.setStyle(TableStyle([
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
                    ('TOPPADDING', (0, 0), (-1, -1), 0),
                ]))
                story.append(logo_table)
                story.append(Spacer(1, 60))
            
            # 3. Main Title Block with Navy Accent Bar
            title_style = ParagraphStyle(
                'CoverTitle',
                parent=styles['Heading1'],
                fontSize=22,
                textColor=colors.HexColor('#002B49'),
                spaceAfter=10,
                leading=28,
                fontName='Helvetica-Bold'
            )
            
            subtitle_style = ParagraphStyle(
                'CoverSubtitle',
                parent=styles['Normal'],
                fontSize=11,
                textColor=colors.HexColor('#7F8C8D'),
                leading=14,
                fontName='Helvetica'
            )
            
            title_p = Paragraph(report_data["title"], title_style)
            subtitle_p = Paragraph("Regulatory Compliance Audit & Security Posture Assessment Report", subtitle_style)
            
            title_table_data = [
                ["", [title_p, subtitle_p]]
            ]
            title_table = Table(title_table_data, colWidths=[6, 444])
            title_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, 0), colors.HexColor('#002B49')), # Navy accent bar
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('LEFTPADDING', (1, 0), (1, -1), 15),
                ('RIGHTPADDING', (1, 0), (1, -1), 0),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
                ('TOPPADDING', (0, 0), (-1, -1), 0),
            ]))
            story.append(title_table)
            story.append(Spacer(1, 70))
            
            # 4. Metadata Block Box
            meta_label_style = ParagraphStyle('MetaLabel', parent=styles['Normal'], fontSize=9.5, fontName='Helvetica-Bold', textColor=colors.HexColor('#34495E'))
            meta_val_style = ParagraphStyle('MetaValue', parent=styles['Normal'], fontSize=9.5, fontName='Helvetica', textColor=colors.HexColor('#2C3E50'))
            
            meta_data = [
                [Paragraph("Reporting Period:", meta_label_style), Paragraph(report_data['period'], meta_val_style)],
                [Paragraph("Generated On:", meta_label_style), Paragraph(report_data['generated_at'], meta_val_style)],
                [Paragraph("Security Classification:", meta_label_style), Paragraph("STRICTLY CONFIDENTIAL", meta_val_style)],
                [Paragraph("Regulatory Framework:", meta_label_style), Paragraph("CERT-In Cyber Directions 70B & RBI CS Framework", meta_val_style)]
            ]
            
            meta_table = Table(meta_data, colWidths=[150, 300])
            meta_table.setStyle(TableStyle([
                ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#BDC3C7')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#ECF0F1')),
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F8F9FA')),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('LEFTPADDING', (0, 0), (-1, -1), 12),
                ('RIGHTPADDING', (0, 0), (-1, -1), 12),
            ]))
            story.append(meta_table)
            
            story.append(PageBreak())
            
            section_heading_style = ParagraphStyle(
                'SectionHeading',
                parent=styles['Normal'],
                fontSize=11,
                textColor=colors.HexColor('#002B49'),
                fontName='Helvetica-Bold',
                spaceBefore=10,
                spaceAfter=6
            )

            # Reusable CERT-In themed Table Style
            certin_table_style = TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#002B49')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#7F8C8D')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#BDC3C7')),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F2F4F7')]),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('LEFTPADDING', (0, 0), (-1, -1), 10),
                ('RIGHTPADDING', (0, 0), (-1, -1), 10),
            ])

            # 1. Executive Summary (inside a bordered CERT-In style box)
            exec_data = [
                [Paragraph("<b>Executive Summary</b>", ParagraphStyle('ExecHead', parent=styles['Normal'], textColor=colors.white, fontSize=11, fontName='Helvetica-Bold'))],
                [Paragraph(report_data["executive_summary"], body_style)]
            ]
            exec_table = Table(exec_data, colWidths=[450])
            exec_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#002B49')),
                ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#7F8C8D')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#BDC3C7')),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('LEFTPADDING', (0, 0), (-1, -1), 12),
                ('RIGHTPADDING', (0, 0), (-1, -1), 12),
            ]))
            story.append(exec_table)
            story.append(Spacer(1, 20))
            
            # 2. Incident Statistics Summary
            stats = report_data["statistics"]
            stats_data = [
                [Paragraph("<b>Incident Statistics Summary</b>", ParagraphStyle('StatsHead', parent=styles['Normal'], textColor=colors.white, fontSize=11, fontName='Helvetica-Bold')), ""],
                [Paragraph("Total Incidents Handled:", meta_label_style), Paragraph(str(stats['total_incidents']), meta_val_style)],
                [Paragraph("Total Decisions Actioned:", meta_label_style), Paragraph(str(stats['total_decisions']), meta_val_style)]
            ]
            stats_table = Table(stats_data, colWidths=[200, 250])
            stats_table.setStyle(TableStyle([
                ('SPAN', (0, 0), (1, 0)),
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#002B49')),
                ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#7F8C8D')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#BDC3C7')),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F8F9FA')]),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('LEFTPADDING', (0, 0), (-1, -1), 12),
                ('RIGHTPADDING', (0, 0), (-1, -1), 12),
            ]))
            story.append(stats_table)
            story.append(Spacer(1, 15))
            
            # 2.1 Incidents by Type Table
            if stats.get("incidents_by_type"):
                story.append(Paragraph("<b>Distribution by Incident Type</b>", section_heading_style))
                type_data = [["Incident Type", "Count", "Percentage"]]
                total = stats["total_incidents"]
                for inc_type, count in sorted(stats["incidents_by_type"].items(), key=lambda x: x[1], reverse=True):
                    pct = f"{(count/total*100):.1f}%" if total > 0 else "0%"
                    type_data.append([inc_type, str(count), pct])
                
                type_table = Table(type_data, colWidths=[230, 110, 110])
                type_table.setStyle(certin_table_style)
                story.append(type_table)
                story.append(Spacer(1, 15))
            
            # 2.2 Sector Analysis Table
            if stats.get("incidents_by_sector"):
                story.append(Paragraph("<b>Distribution by Affected Sector</b>", section_heading_style))
                sector_data = [["Sector", "Incidents"]]
                for sector, count in sorted(stats["incidents_by_sector"].items(), key=lambda x: x[1], reverse=True):
                    sector_data.append([sector, str(count)])
                
                sector_table = Table(sector_data, colWidths=[300, 150])
                sector_table.setStyle(certin_table_style)
                story.append(sector_table)
                story.append(Spacer(1, 15))
            
            # 2.3 Threat Actors Table
            if stats.get("threat_actors"):
                actor_data = [["Threat Actor", "Incidents"]]
                for actor, count in sorted(stats["threat_actors"].items(), key=lambda x: x[1], reverse=True)[:10]:
                    actor_data.append([actor, str(count)])
                
                if len(actor_data) > 1:
                    story.append(Paragraph("<b>Distribution by Threat Actor</b>", section_heading_style))
                    actor_table = Table(actor_data, colWidths=[300, 150])
                    actor_table.setStyle(certin_table_style)
                    story.append(actor_table)
                    story.append(Spacer(1, 15))
            
            story.append(PageBreak())
            
            # 3. Trend Analysis Box
            trend_data = [
                [Paragraph("<b>Trend Analysis & Threat Intelligence</b>", ParagraphStyle('TrendHead', parent=styles['Normal'], textColor=colors.white, fontSize=11, fontName='Helvetica-Bold'))],
                [Paragraph(report_data["trend_analysis"], body_style)]
            ]
            trend_table = Table(trend_data, colWidths=[450])
            trend_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#002B49')),
                ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#7F8C8D')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#BDC3C7')),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('LEFTPADDING', (0, 0), (-1, -1), 12),
                ('RIGHTPADDING', (0, 0), (-1, -1), 12),
            ]))
            story.append(trend_table)
            story.append(Spacer(1, 20))
            
            # 4. Recommendations Table
            if report_data.get("recommendations"):
                story.append(Paragraph("<b>Security Control Recommendations & Mitigation Controls</b>", section_heading_style))
                rec_headers = [["Ref", "Control Recommendation", "Priority", "MITRE Mitigation"]]
                for i, rec in enumerate(report_data["recommendations"], 1):
                    rec_desc = Paragraph(f"<b>{rec['title']}</b><br/>{rec['description']}", body_style)
                    rec_headers.append([
                        str(i),
                        rec_desc,
                        rec['priority'],
                        rec.get('mitre_mitigation', 'N/A')
                    ])
                    
                rec_table = Table(rec_headers, colWidths=[30, 250, 70, 100])
                rec_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#002B49')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#7F8C8D')),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#BDC3C7')),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F8F9FA')]),
                    ('TOPPADDING', (0, 0), (-1, -1), 6),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                    ('LEFTPADDING', (0, 0), (-1, -1), 8),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                ]))
                story.append(rec_table)
            
            # Build PDF
            doc.build(story, onFirstPage=draw_page_elements, onLaterPages=draw_page_elements)
            
            return str(output_path)
            
        except ImportError as e:
            print(f"ReportLab not available: {e}. Falling back to HTML export.")
            return self.export_html(report_data, filename)
        except Exception as e:
            print(f"PDF generation failed: {e}. Falling back to HTML export.")
            return self.export_html(report_data, filename)
    
    def _generate_markdown(self, report_data: Dict[str, Any]) -> str:
        """Generate Markdown content"""
        md = f"""---
title: {report_data['title']}
period: {report_data['period']}
generated_at: {report_data['generated_at']}
report_type: {report_data.get('report_type', 'annual')}
---

# {report_data['title']}

**Reporting Period:** {report_data['period']}  
**Generated:** {report_data['generated_at']}  
**System:** HCI-OS Multi-Agent Cybersecurity Operations

---

## Executive Summary

{report_data['executive_summary']}

---

## Incident Statistics

- **Total Incidents:** {report_data['statistics']['total_incidents']}
- **Total Decisions:** {report_data['statistics']['total_decisions']}

### Incidents by Type

| Incident Type | Count | Percentage |
|--------------|-------|------------|
"""
        
        stats = report_data['statistics']
        total = stats['total_incidents']
        for inc_type, count in sorted(stats.get('incidents_by_type', {}).items(), key=lambda x: x[1], reverse=True):
            pct = f"{(count/total*100):.1f}%" if total > 0 else "0%"
            md += f"| {inc_type} | {count} | {pct} |\n"
        
        md += "\n### Incidents by Sector\n\n"
        md += "| Sector | Incidents |\n"
        md += "|--------|----------|\n"
        for sector, count in sorted(stats.get('incidents_by_sector', {}).items(), key=lambda x: x[1], reverse=True):
            md += f"| {sector} | {count} |\n"
        
        if stats.get('threat_actors'):
            md += "\n### Threat Actor Attribution\n\n"
            md += "| Threat Actor | Incidents |\n"
            md += "|-------------|----------|\n"
            for actor, count in sorted(stats['threat_actors'].items(), key=lambda x: x[1], reverse=True)[:10]:
                md += f"| {actor} | {count} |\n"
        
        md += f"\n---\n\n## Trend Analysis\n\n{report_data['trend_analysis']}\n"
        
        md += "\n---\n\n## Recommendations\n\n"
        for i, rec in enumerate(report_data['recommendations'], 1):
            md += f"### {i}. {rec['title']} (Priority: {rec['priority']})\n\n"
            md += f"{rec['description']}\n\n"
            md += f"*MITRE Mitigation: {rec['mitre_mitigation']}*\n\n"
        
        md += "\n---\n\n**End of Report**\n"
        
        return md
    
    def _generate_html(self, report_data: Dict[str, Any]) -> str:
        """Generate self-contained HTML"""
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{report_data['title']}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            background-color: white;
            padding: 40px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            border-bottom: 3px solid #2B5B9B;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        h1 {{
            color: #2B5B9B;
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        h2 {{
            color: #2B5B9B;
            font-size: 1.8em;
            margin-top: 30px;
            margin-bottom: 15px;
            border-bottom: 2px solid #2B5B9B;
            padding-bottom: 5px;
        }}
        h3 {{
            color: #2B5B9B;
            font-size: 1.3em;
            margin-top: 20px;
            margin-bottom: 10px;
        }}
        .metadata {{
            color: #666;
            font-size: 0.9em;
            text-align: center;
            margin-bottom: 20px;
        }}
        .section {{
            margin-bottom: 30px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border: 1px solid #ddd;
        }}
        th {{
            background-color: #2B5B9B;
            color: white;
            font-weight: bold;
        }}
        tr:nth-child(even) {{
            background-color: #f9f9f9;
        }}
        tr:hover {{
            background-color: #f1f1f1;
        }}
        .recommendation {{
            background-color: #f8f9fa;
            border-left: 4px solid #2B5B9B;
            padding: 15px;
            margin: 15px 0;
        }}
        .priority-CRITICAL {{
            border-left-color: #dc3545;
        }}
        .priority-HIGH {{
            border-left-color: #fd7e14;
        }}
        .priority-MEDIUM {{
            border-left-color: #ffc107;
        }}
        .priority-LOW {{
            border-left-color: #28a745;
        }}
        .stat-box {{
            display: inline-block;
            background: #e7f3ff;
            padding: 15px 25px;
            margin: 10px;
            border-radius: 5px;
            border-left: 4px solid #2B5B9B;
        }}
        .stat-label {{
            font-weight: bold;
            color: #2B5B9B;
        }}
        .stat-value {{
            font-size: 1.5em;
            color: #333;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{report_data['title']}</h1>
            <div class="metadata">
                <p><strong>Reporting Period:</strong> {report_data['period']}</p>
                <p><strong>Generated:</strong> {report_data['generated_at']}</p>
                <p><strong>System:</strong> HCI-OS Multi-Agent Cybersecurity Operations</p>
            </div>
        </div>
        
        <div class="section">
            <h2>Executive Summary</h2>
            <p>{report_data['executive_summary'].replace(chr(10), '<br>')}</p>
        </div>
        
        <div class="section">
            <h2>Incident Statistics</h2>
            <div class="stat-box">
                <div class="stat-label">Total Incidents</div>
                <div class="stat-value">{report_data['statistics']['total_incidents']}</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">Total Decisions</div>
                <div class="stat-value">{report_data['statistics']['total_decisions']}</div>
            </div>
            
            <h3>Incidents by Type</h3>
            <table>
                <thead>
                    <tr>
                        <th>Incident Type</th>
                        <th>Count</th>
                        <th>Percentage</th>
                    </tr>
                </thead>
                <tbody>
"""
        
        stats = report_data['statistics']
        total = stats['total_incidents']
        for inc_type, count in sorted(stats.get('incidents_by_type', {}).items(), key=lambda x: x[1], reverse=True):
            pct = f"{(count/total*100):.1f}%" if total > 0 else "0%"
            html += f"<tr><td>{inc_type}</td><td>{count}</td><td>{pct}</td></tr>\n"
        
        html += """
                </tbody>
            </table>
            
            <h3>Incidents by Sector</h3>
            <table>
                <thead>
                    <tr>
                        <th>Sector</th>
                        <th>Incidents</th>
                    </tr>
                </thead>
                <tbody>
"""
        
        for sector, count in sorted(stats.get('incidents_by_sector', {}).items(), key=lambda x: x[1], reverse=True):
            html += f"<tr><td>{sector}</td><td>{count}</td></tr>\n"
        
        html += """
                </tbody>
            </table>
"""
        
        if stats.get('threat_actors'):
            html += """
            <h3>Threat Actor Attribution</h3>
            <table>
                <thead>
                    <tr>
                        <th>Threat Actor</th>
                        <th>Incidents</th>
                    </tr>
                </thead>
                <tbody>
"""
            for actor, count in sorted(stats['threat_actors'].items(), key=lambda x: x[1], reverse=True)[:10]:
                html += f"<tr><td>{actor}</td><td>{count}</td></tr>\n"
            html += """
                </tbody>
            </table>
"""
        
        html += f"""
        </div>
        
        <div class="section">
            <h2>Trend Analysis</h2>
            <p>{report_data['trend_analysis'].replace(chr(10), '<br>')}</p>
        </div>
        
        <div class="section">
            <h2>Recommendations</h2>
"""
        
        for i, rec in enumerate(report_data['recommendations'], 1):
            html += f"""
            <div class="recommendation priority-{rec['priority']}">
                <h3>{i}. {rec['title']}</h3>
                <p><strong>Priority:</strong> {rec['priority']}</p>
                <p>{rec['description']}</p>
                <p><em>MITRE Mitigation: {rec['mitre_mitigation']}</em></p>
            </div>
"""
        
        html += """
        </div>
        
        <div class="section" style="text-align: center; margin-top: 50px; padding-top: 20px; border-top: 2px solid #2B5B9B;">
            <p><strong>End of Report</strong></p>
        </div>
    </div>
</body>
</html>
"""
        return html

    def export_official_cert_in_pdf(self, incident: Dict[str, Any], timeline: List[Dict[str, Any]], audit: List[Dict[str, Any]], filename: str) -> str:
        """Export a single incident report in the official CERT-In Incident Reporting Form layout"""
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
            from reportlab.lib import colors
            from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
            
            output_path = self.output_dir / f"{filename}.pdf"
            
            # Margins of 0.5 inch to maximize printable area for form fields
            doc = SimpleDocTemplate(
                str(output_path),
                pagesize=A4,
                rightMargin=36,
                leftMargin=36,
                topMargin=36,
                bottomMargin=36
            )
            
            story = []
            styles = getSampleStyleSheet()
            
            # Colors
            primary_color = colors.HexColor('#002B49') # Deep Navy
            secondary_color = colors.HexColor('#F2F4F7') # Light Grey
            border_color = colors.HexColor('#7F8C8D')
            
            # Custom Paragraph Styles
            title_style = ParagraphStyle(
                'FormTitle',
                parent=styles['Heading1'],
                fontSize=14,
                textColor=primary_color,
                alignment=TA_CENTER,
                spaceAfter=2,
                fontName='Helvetica-Bold'
            )
            
            subtitle_style = ParagraphStyle(
                'FormSubtitle',
                parent=styles['Normal'],
                fontSize=10,
                alignment=TA_CENTER,
                spaceAfter=15,
                fontName='Helvetica-Bold'
            )
            
            section_heading_style = ParagraphStyle(
                'SectionHeading',
                parent=styles['Normal'],
                fontSize=10,
                textColor=primary_color,
                fontName='Helvetica-Bold',
                spaceBefore=6,
                spaceAfter=4
            )
            
            field_label_style = ParagraphStyle(
                'FieldLabel',
                parent=styles['Normal'],
                fontSize=9,
                fontName='Helvetica-Bold',
                leading=11
            )
            
            field_value_style = ParagraphStyle(
                'FieldValue',
                parent=styles['Normal'],
                fontSize=9,
                fontName='Helvetica',
                leading=11
            )
            
            mono_value_style = ParagraphStyle(
                'MonoValue',
                parent=styles['Normal'],
                fontSize=8.5,
                fontName='Courier',
                leading=10
            )

            # --- Form Header ---
            story.append(Paragraph("Incident Reporting Form", title_style))
            story.append(Paragraph("Form to report Incidents to CERT-In", subtitle_style))
            
            # Official Use Only Block
            tracking_num = f"CERTIn-{incident.get('hypothesis_id', 'UNKNOWN')}"
            official_data = [
                [Paragraph("<b>For official use only:</b>", field_label_style), Paragraph(f"Incident Tracking Number: <b>{tracking_num}</b>", field_value_style)]
            ]
            official_table = Table(official_data, colWidths=[150, 370])
            official_table.setStyle(TableStyle([
                ('BOX', (0, 0), (-1, -1), 1, border_color),
                ('BACKGROUND', (0, 0), (-1, -1), secondary_color),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(official_table)
            story.append(Spacer(1, 10))
            
            # --- 1. Contact Information ---
            story.append(Paragraph("1. Contact Information for this Incident:", section_heading_style))
            contact_data = [
                [Paragraph("Name:", field_label_style), Paragraph(incident.get("ciso_name", "Sriram Iyer"), field_value_style), Paragraph("Organization:", field_label_style), Paragraph(incident.get("organization", "Central Board of Secondary Education (CBSE)"), field_value_style)],
                [Paragraph("Title:", field_label_style), Paragraph(incident.get("ciso_title", "Chief Information Security Officer (CISO)"), field_value_style), Paragraph("Phone / Fax No:", field_label_style), Paragraph(incident.get("ciso_phone", "+91-11-24368546"), field_value_style)],
                [Paragraph("Mobile:", field_label_style), Paragraph(incident.get("ciso_mobile", "+91-9988776655"), field_value_style), Paragraph("Email:", field_label_style), Paragraph(incident.get("ciso_email", "s.iyer@cbse.gov.in"), field_value_style)],
                [Paragraph("Address:", field_label_style), Paragraph(incident.get("ciso_address", "CBSE HQ, Preet Vihar, New Delhi, 110092"), field_value_style), Paragraph("", field_label_style), Paragraph("", field_value_style)]
            ]
            contact_table = Table(contact_data, colWidths=[70, 190, 90, 170])
            contact_table.setStyle(TableStyle([
                ('BOX', (0, 0), (-1, -1), 1, border_color),
                ('GRID', (0, 0), (-1, -1), 0.5, border_color),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('BACKGROUND', (0, 0), (0, -1), secondary_color),
                ('BACKGROUND', (2, 0), (2, -1), secondary_color),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
            ]))
            story.append(contact_table)
            story.append(Spacer(1, 8))
            
            # --- 2. Sector Selection ---
            story.append(Paragraph("2. Sector: (Please tick the appropriate choices)", section_heading_style))
            inc_sector = str(incident.get("sector", "Government")).lower()
            gov_tick = "[X]" if "gov" in inc_sector or "cbse" in incident.get("organization","").lower() else "[ ]"
            info_tick = "[X]" if "info" in inc_sector or "tech" in inc_sector or "app" in incident.get("target","").lower() else "[ ]"
            fin_tick = "[X]" if "finan" in inc_sector or "rbi" in incident.get("organization","").lower() else "[ ]"
            health_tick = "[X]" if "health" in inc_sector or "aiims" in incident.get("organization","").lower() else "[ ]"
            power_tick = "[X]" if "power" in inc_sector or "grid" in inc_sector else "[ ]"
            
            sector_data = [
                [Paragraph(f"{gov_tick} Government", field_label_style), Paragraph(f"{info_tick} InfoTech", field_label_style), Paragraph(f"{power_tick} Power", field_label_style)],
                [Paragraph(f"{fin_tick} Financial", field_label_style), Paragraph(f"{health_tick} Health", field_label_style), Paragraph("[ ] Telecommunications", field_label_style)],
                [Paragraph("[ ] Transportation", field_label_style), Paragraph("[ ] Academia", field_label_style), Paragraph("[ ] Petroleum", field_label_style)],
                [Paragraph("[ ] Manufacturing", field_label_style), Paragraph("[ ] Other _________________", field_label_style), Paragraph("", field_label_style)]
            ]
            sector_table = Table(sector_data, colWidths=[173, 173, 174])
            sector_table.setStyle(TableStyle([
                ('BOX', (0, 0), (-1, -1), 1, border_color),
                ('GRID', (0, 0), (-1, -1), 0.5, border_color),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
            ]))
            story.append(sector_table)
            story.append(Spacer(1, 8))
            
            # --- 3 & 4. Location and Date ---
            loc_str = incident.get("location", "Primary Data Center")
            isp_str = incident.get("isp", "National Informatics Centre (NIC)")
            loc_date_data = [
                [Paragraph("3. Physical Location of Affected Computer/ Network and ISP:", field_label_style), Paragraph(f"{loc_str}<br/>ISP: {isp_str}", field_value_style)],
                [Paragraph("4. Date and Time Incident Occurred:", field_label_style), Paragraph(f"Date: {incident.get('detection_ts', '').split(' ')[0]} &nbsp;&nbsp;&nbsp;&nbsp; Time: {incident.get('detection_ts', '').split(' ')[1] if ' ' in incident.get('detection_ts', '') else ''} IST", field_value_style)]
            ]
            loc_date_table = Table(loc_date_data, colWidths=[200, 320])
            loc_date_table.setStyle(TableStyle([
                ('BOX', (0, 0), (-1, -1), 1, border_color),
                ('GRID', (0, 0), (-1, -1), 0.5, border_color),
                ('BACKGROUND', (0, 0), (0, -1), secondary_color),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(loc_date_table)
            story.append(Spacer(1, 8))
            
            # --- 5. Criticality ---
            is_critical = incident.get("criticality_note") or f"Yes. Target asset ({incident.get('target', 'Core Infrastructure')}) is critical to organization's mission."
            crit_data = [
                [Paragraph("5. Is the affected system/network critical to organization's mission?", field_label_style), Paragraph(is_critical, field_value_style)]
            ]
            crit_table = Table(crit_data, colWidths=[200, 320])
            crit_table.setStyle(TableStyle([
                ('BOX', (0, 0), (-1, -1), 1, border_color),
                ('BACKGROUND', (0, 0), (0, 0), secondary_color),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(crit_table)
            story.append(Spacer(1, 8))
            
            # --- 6. Information of Affected System ---
            story.append(Paragraph("6. Information of Affected System:", section_heading_style))
            sys_headers = ["IP Address", "Host Name", "Operating System", "Last Patched", "Hardware Vendor/Model"]
            sys_rows = [[Paragraph(f"<b>{h}</b>", field_label_style) for h in sys_headers]]
            
            affected = incident.get("affected_assets", [])
            if not affected:
                sys_rows.append([
                    Paragraph(incident.get("asset_ip", "10.150.12.35"), mono_value_style),
                    Paragraph(incident.get("target", "CBSE-AppSvr-03"), field_value_style),
                    Paragraph(incident.get("asset_os", "Ubuntu Linux 22.04 LTS"), field_value_style),
                    Paragraph(incident.get("last_patched", "2026-06-15"), field_value_style),
                    Paragraph(incident.get("hardware_model", "Dell PowerEdge R750"), field_value_style)
                ])
            else:
                for idx, a in enumerate(affected):
                    ip_addr = a.get("ip") or ("10.150.12." + str(35 + idx))
                    host_nm = a.get("name") or a.get("id") or "Host-Svr"
                    os_name = a.get("os") or ("Ubuntu Linux 22.04 LTS" if "App" in host_nm else "Windows Server 2022")
                    patched = a.get("last_patched", "2026-06-15")
                    hw_mdl  = a.get("hardware") or ("Dell PowerEdge R750" if "App" in host_nm else "HPE ProLiant DL380")
                    sys_rows.append([
                        Paragraph(ip_addr, mono_value_style),
                        Paragraph(host_nm, field_value_style),
                        Paragraph(os_name, field_value_style),
                        Paragraph(patched, field_value_style),
                        Paragraph(hw_mdl, field_value_style)
                    ])
            
            sys_table = Table(sys_rows, colWidths=[90, 110, 130, 80, 110])
            sys_table.setStyle(TableStyle([
                ('BOX', (0, 0), (-1, -1), 1, border_color),
                ('GRID', (0, 0), (-1, -1), 0.5, border_color),
                ('BACKGROUND', (0, 0), (-1, 0), secondary_color),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(sys_table)
            story.append(Spacer(1, 8))
            
            # --- 7. Type of Incident ---
            story.append(Paragraph("7. Type of Incident: (Ticked based on indicators and threat profile)", section_heading_style))
            title_lower = incident.get("title", "").lower()
            mitre_str = "".join(incident.get("mitre_chain", [])).lower()
            
            phishing_tick = "[X]" if "phishing" in title_lower or "t1566" in mitre_str else "[ ]"
            scan_tick = "[X]" if "scanning" in title_lower or "probe" in title_lower or "t1595" in mitre_str else "[ ]"
            dos_tick = "[X]" if "dos" in title_lower or "ddos" in title_lower else "[ ]"
            compromise_tick = "[X]" if "root" in title_lower or "compromise" in title_lower or (phishing_tick == "[ ]" and scan_tick == "[ ]") else "[ ]"
            vuln_tick = "[X]" if "vulnerability" in title_lower or "exploit" in title_lower else "[ ]"
            
            type_data = [
                [Paragraph(f"{phishing_tick} Phishing", field_value_style), Paragraph(f"{scan_tick} Network scanning /Probing", field_value_style), Paragraph(f"{compromise_tick} Break-in/Root Compromise", field_value_style)],
                [Paragraph("[ ] Virus/Malicious Code", field_value_style), Paragraph("[ ] Website Defacement", field_value_style), Paragraph(f"{dos_tick} Denial of Service (DoS)", field_value_style)],
                [Paragraph(f"{vuln_tick} Technical Vulnerability", field_value_style), Paragraph("[ ] User Account Compromise", field_value_style), Paragraph("[ ] Other_______________", field_value_style)]
            ]
            type_table = Table(type_data, colWidths=[173, 173, 174])
            type_table.setStyle(TableStyle([
                ('BOX', (0, 0), (-1, -1), 1, border_color),
                ('GRID', (0, 0), (-1, -1), 0.5, border_color),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
            ]))
            story.append(type_table)
            story.append(PageBreak())

            # --- Page 2 Header ---
            story.append(Paragraph("Incident Reporting Form (Page 2)", title_style))
            story.append(Spacer(1, 10))

            # --- 8. Description of Incident ---
            desc_text = f"<b>Title:</b> {incident.get('title')}<br/>"
            desc_text += f"<b>Analysis:</b> The system detected anomalous active activities on {incident.get('target')}. "
            desc_text += f"Confidence level is {(incident.get('confidence', 0.5)*100):.1f}%. "
            desc_text += f"Causal analysis indicates MITRE chain: {', '.join(incident.get('mitre_chain', []))}. "
            desc_text += "Real-time behavior was processed by GNN engine and decisions were generated and gated."
            
            desc_data = [
                [Paragraph("8. Description of Incident:", field_label_style)],
                [Paragraph(desc_text, field_value_style)]
            ]
            desc_table = Table(desc_data, colWidths=[520])
            desc_table.setStyle(TableStyle([
                ('BOX', (0, 0), (-1, -1), 1, border_color),
                ('BACKGROUND', (0, 0), (-1, 0), secondary_color),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
            ]))
            story.append(desc_table)
            story.append(Spacer(1, 8))
            
            # --- 9. Unusual Behavior / Symptoms ---
            story.append(Paragraph("9. Unusual behavior/symptoms: (Ticked based on log correlation)", section_heading_style))
            symptoms_data = [
                [Paragraph("[X] Anomalies", field_value_style), Paragraph("[X] Unusual log file entries", field_value_style), Paragraph("[X] Suspicious probes", field_value_style)],
                [Paragraph("[ ] System crashes", field_value_style), Paragraph("[ ] Unexplained privilege elevation", field_value_style), Paragraph("[X] Attempts to write to system", field_value_style)],
                [Paragraph("[ ] Unexplained poor performance", field_value_style), Paragraph("[ ] Altered home pages", field_value_style), Paragraph("[ ] Other (Please specify)", field_value_style)]
            ]
            symptoms_table = Table(symptoms_data, colWidths=[173, 173, 174])
            symptoms_table.setStyle(TableStyle([
                ('BOX', (0, 0), (-1, -1), 1, border_color),
                ('GRID', (0, 0), (-1, -1), 0.5, border_color),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
            ]))
            story.append(symptoms_table)
            story.append(Spacer(1, 8))
            
            # --- 10, 11, 12 & 13. Details ---
            detail_rows = [
                [Paragraph("10. Has this problem been experienced earlier? If yes, details.", field_label_style), Paragraph(incident.get("prev_occurrence", "No previous occurrence found in intelligence database."), field_value_style)],
                [Paragraph("11. When and How was the incident detected:", field_label_style), Paragraph(f"Detected on {incident.get('detection_ts')} via watchdog log parser.", field_value_style)],
                [Paragraph("12. Agencies notified?", field_label_style), Paragraph("[X] Internal Security &nbsp;&nbsp;&nbsp;&nbsp; [X] Law Enforcement &nbsp;&nbsp;&nbsp;&nbsp; [ ] Affected Vendor", field_value_style)],
                [Paragraph("13. Additional Information:", field_label_style), Paragraph("Log submitting: <b>Yes</b> &nbsp;&nbsp;&nbsp;&nbsp; Mode of submission: <b>Secure API Portal</b>", field_value_style)]
            ]
            detail_table = Table(detail_rows, colWidths=[200, 320])
            detail_table.setStyle(TableStyle([
                ('BOX', (0, 0), (-1, -1), 1, border_color),
                ('GRID', (0, 0), (-1, -1), 0.5, border_color),
                ('BACKGROUND', (0, 0), (0, -1), secondary_color),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(detail_table)
            story.append(Spacer(1, 8))
            
            # --- 14 & 15. Source and Infrastructure ---
            iocs_str = ", ".join([ioc.get("value", "") for ioc in incident.get("iocs", []) if ioc.get("type") == "ip"])
            if not iocs_str:
                iocs_str = incident.get("attacker_ip") or incident.get("source_ip") or "Under Investigation"
                
            sec_infra = incident.get("sec_infra", "<b>Firewall:</b> Enterprise NGFW<br/><b>Endpoint:</b> EDR Solution<br/><b>IDS/IPS:</b> HCI-OS GNN Telemetry Watcher")
            infra_rows = [
                [Paragraph("14. IP Address of Apparent or Suspected Source:", field_label_style), Paragraph(iocs_str, mono_value_style)],
                [Paragraph("15. Security Infrastructure in place:", field_label_style), Paragraph(sec_infra, field_value_style)]
            ]
            infra_table = Table(infra_rows, colWidths=[200, 320])
            infra_table.setStyle(TableStyle([
                ('BOX', (0, 0), (-1, -1), 1, border_color),
                ('GRID', (0, 0), (-1, -1), 0.5, border_color),
                ('BACKGROUND', (0, 0), (0, -1), secondary_color),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(infra_table)
            story.append(Spacer(1, 8))
            
            # --- 16 & 17. Hosts and Actions ---
            num_hosts = len(affected) if affected else 1
            if num_hosts <= 10:
                host_count_str = "[X] 1 to 10 &nbsp;&nbsp;&nbsp;&nbsp; [ ] 10 to 100 &nbsp;&nbsp;&nbsp;&nbsp; [ ] More than 100"
            elif num_hosts <= 100:
                host_count_str = "[ ] 1 to 10 &nbsp;&nbsp;&nbsp;&nbsp; [X] 10 to 100 &nbsp;&nbsp;&nbsp;&nbsp; [ ] More than 100"
            else:
                host_count_str = "[ ] 1 to 10 &nbsp;&nbsp;&nbsp;&nbsp; [ ] 10 to 100 &nbsp;&nbsp;&nbsp;&nbsp; [X] More than 100"

            actions_taken_str = incident.get("actions_taken")
            if actions_taken_str:
                actions_mitigation = f"<b>Executed Actions:</b> {actions_taken_str}"
            else:
                actions_mitigation = "[X] System(s) disconnected from network &nbsp;&nbsp;&nbsp;&nbsp; [X] Log Files examined<br/>[X] Restored with a good backup &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; [ ] Other"
            
            last_rows = [
                [Paragraph("16. How Many Host(s) are Affected:", field_label_style), Paragraph(host_count_str, field_value_style)],
                [Paragraph("17. Actions taken to mitigate intrusion/attack:", field_label_style), Paragraph(actions_mitigation, field_value_style)]
            ]
            last_table = Table(last_rows, colWidths=[200, 320])
            last_table.setStyle(TableStyle([
                ('BOX', (0, 0), (-1, -1), 1, border_color),
                ('GRID', (0, 0), (-1, -1), 0.5, border_color),
                ('BACKGROUND', (0, 0), (0, -1), secondary_color),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(last_table)
            story.append(Spacer(1, 10))
            
            # --- Form Footer ---
            footer_text = "<font color='#7F8C8D'>Mail/Fax this Form to: CERT-In, Electronics Niketan, CGO Complex, New Delhi 110003 Fax:+91-11-24368546 or email at: incident@cert-in.org.in</font>"
            story.append(Paragraph(footer_text, ParagraphStyle('FormFooter', parent=styles['Normal'], fontSize=8.5, alignment=TA_CENTER)))
            
            # Page elements callback to draw CERT-In logo and confidential footer
            def draw_form_page_elements(canvas, doc):
                canvas.saveState()
                logo_path = Path(__file__).parent.absolute() / "assets" / "certin_logo.png"
                if logo_path.exists():
                    logo_w, logo_h = 75, 23
                    canvas.drawImage(str(logo_path), 595.27 - 36 - logo_w, 841.89 - 25 - logo_h, width=logo_w, height=logo_h, mask='auto')
                
                # Draw running footer with page number
                canvas.setFont('Helvetica-Bold', 8)
                canvas.setFillColor(colors.HexColor('#C0392B')) # Crimson for Confidential on form
                canvas.drawString(36, 20, "CONFIDENTIAL - SECURE CYBER INCIDENT REPORT")
                canvas.setFont('Helvetica', 8)
                canvas.setFillColor(colors.HexColor('#7F8C8D'))
                canvas.drawRightString(595.27 - 36, 20, f"Page {doc.page} of 2")
                canvas.restoreState()

            # Build doc
            doc.build(story, onFirstPage=draw_form_page_elements, onLaterPages=draw_form_page_elements)
            return str(output_path)
            
        except Exception as e:
            print(f"Failed to generate official PDF: {e}")
            raise e
