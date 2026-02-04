import os
import html as html_lib
from datetime import datetime

class ReportGenerator:
    def generate_html(self, vulnerabilities):
        """Generates an Elite Cyber Obsidian HTML report."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Calculate Stats for Charts
        critical = sevs.count("critical")
        high = sevs.count("high")
        medium = sevs.count("medium")
        low = sevs.count("low")
        total = len(vulnerabilities) or 1
        
        grade = "A+"
        color = "#50fa7b"
        if critical > 0: grade, color = "F", "#ff5555"
        elif high > 0: grade, color = "D", "#ff5555"
        elif medium > 0: grade, color = "C", "#ffb900"
        elif sevs: grade, color = "B", "#bd93f9"

        # Categorize Findings for Executive Summary
        vuln_types = {}
        for v in vulnerabilities:
            vuln_types[v.type] = vuln_types.get(v.type, 0) + 1
        top_vuln = max(vuln_types, key=vuln_types.get) if vuln_types else "None"

        html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>BurpKiller Pro v1.0.0 - Security Assessment</title>
            <style>
                :root {{
                    --bg-app: #0b0b0d;
                    --bg-card: rgba(30, 30, 35, 0.8);
                    --accent: #60cdff;
                    --accent-pink: #ff79c6;
                    --text: #e0e0e0;
                    --border: rgba(96, 205, 255, 0.15);
                }}
                body {{ 
                    font-family: 'Segoe UI Variable Display', 'Segoe UI', sans-serif; 
                    margin: 0; 
                    padding: 40px; 
                    background-color: var(--bg-app); 
                    color: var(--text);
                    line-height: 1.6;
                }}
                .header-card {{
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 rgba(30, 30, 35, 0.9), stop:1 rgba(20, 20, 25, 1));
                    border: 1px solid var(--border);
                    border-radius: 16px;
                    padding: 30px;
                    margin-bottom: 30px;
                    box-shadow: 0 10px 40px rgba(0,0,0,0.5);
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }}
                .grade-box {{
                    text-align: center;
                    border-left: 2px solid rgba(255,255,255,0.1);
                    padding-left: 40px;
                }}
                .grade-letter {{
                    font-size: 72px;
                    font-weight: 900;
                    margin: 0;
                    line-height: 1;
                    color: {color};
                    text-shadow: 0 0 20px {color}44;
                }}
                h1 {{ 
                    margin: 0; 
                    font-size: 12px; 
                    text-transform: uppercase; 
                    letter-spacing: 4px; 
                    color: var(--accent);
                    font-weight: 900;
                }}
                h2 {{ font-size: 24px; margin: 10px 0; color: #fff; }}
                
                table {{ width: 100%; border-collapse: separate; border-spacing: 0 10px; margin-top: 20px; }}
                th {{ 
                    padding: 15px; 
                    text-align: left; 
                    text-transform: uppercase; 
                    font-size: 11px; 
                    letter-spacing: 2px; 
                    color: #888;
                    border-bottom: 2px solid var(--border);
                }}
                td {{ 
                    padding: 20px; 
                    background: var(--bg-card);
                    border-top: 1px solid var(--border);
                    border-bottom: 1px solid var(--border);
                }}
                td:first-child {{ border-left: 1px solid var(--border); border-top-left-radius: 12px; border-bottom-left-radius: 12px; }}
                td:last-child {{ border-right: 1px solid var(--border); border-top-right-radius: 12px; border-bottom-right-radius: 12px; }}
                
                .sev-critical {{ color: #ff5555; font-weight: 900; }}
                .sev-high {{ color: #ff5555; font-weight: bold; }}
                .sev-medium {{ color: #ffb900; font-weight: bold; }}
                .sev-low {{ color: #bd93f9; font-weight: bold; }}
                .sev-info {{ color: var(--accent); }}
                
                pre {{ 
                    background: rgba(0,0,0,0.4); 
                    padding: 15px; 
                    border-radius: 8px; 
                    font-family: 'Cascadia Code', 'Consolas', monospace; 
                    font-size: 12px; 
                    max-height: 300px; 
                    overflow: auto; 
                    border: 1px solid rgba(255,255,255,0.05);
                    white-space: pre-wrap;
                    word-break: break-all;
                }}
                .tag {{
                    font-size: 10px;
                    text-transform: uppercase;
                    padding: 4px 8px;
                    border-radius: 4px;
                    background: rgba(255,255,255,0.05);
                    margin-right: 5px;
                    font-weight: 800;
                }}
            </style>
        </head>
        <body>
            <div class="header-card">
                <div>
                    <h1>BurpKiller Pro v1.2.0</h1>
                    <h2>Executive Security Intelligence Report</h2>
                    <p style="color: #666; font-size: 13px;">GEN_TIME: {timestamp} &nbsp;|&nbsp; OBJECTS_SCANNED: {len(vulnerabilities)}</p>
                </div>
                <div class="grade-box">
                    <div style="font-size: 10px; font-weight: 900; color: #888; margin-bottom: 5px;">SECURITY GRADE</div>
                    <div class="grade-letter">{grade}</div>
                </div>
            </div>

            <!-- EXECUTIVE SUMMARY GRID -->
            <div style="display: grid; grid-template-columns: 2fr 1fr; gap: 20px; margin-bottom: 30px;">
                <div style="background: var(--bg-card); border: 1px solid var(--border); border-radius: 16px; padding: 25px;">
                    <h3 style="color: var(--accent); font-size: 12px; text-transform: uppercase; margin-top: 0;">STRATEGIC BOTTOM LINE</h3>
                    <p style="font-size: 14px; color: #ccc;">
                        Analysis reveals a <b>{grade}</b> grade security posture. The primary concern is <b>{top_vuln}</b>, 
                        which appeared in {vuln_types.get(top_vuln, 0)} instances. 
                        Immediate remediation of {critical} critical issues is required to prevent data exfiltration.
                    </p>
                    <div style="display: flex; gap: 15px; margin-top: 20px;">
                        <div style="flex: 1; background: #ff555522; padding: 10px; border-radius: 8px; border-left: 3px solid #ff5555;">
                            <div style="font-size: 10px; color: #ff5555; font-weight: 900;">CRITICAL</div>
                            <div style="font-size: 20px; font-weight: 900;">{critical}</div>
                        </div>
                        <div style="flex: 1; background: #ffb90022; padding: 10px; border-radius: 8px; border-left: 3px solid #ffb900;">
                            <div style="font-size: 10px; color: #ffb900; font-weight: 900;">HIGH</div>
                            <div style="font-size: 20px; font-weight: 900;">{high}</div>
                        </div>
                        <div style="flex: 1; background: #50fa7b22; padding: 10px; border-radius: 8px; border-left: 3px solid #50fa7b;">
                            <div style="font-size: 10px; color: #50fa7b; font-weight: 900;">PATCHED/OK</div>
                            <div style="font-size: 20px; font-weight: 900;">{len(vulnerabilities) - critical - high}</div>
                        </div>
                    </div>
                </div>

                <div style="background: var(--bg-card); border: 1px solid var(--border); border-radius: 16px; padding: 25px;">
                    <h3 style="color: var(--accent); font-size: 12px; text-transform: uppercase; margin-top: 0;">RISK EXPOSURE</h3>
                    <div style="height: 100px; display: flex; align-items: flex-end; gap: 10px; padding-bottom: 10px;">
                        <div style="flex: 1; height: {(critical/total)*100}%; background: #ff5555; border-radius: 4px 4px 0 0;"></div>
                        <div style="flex: 1; height: {(high/total)*100}%; background: #ffb900; border-radius: 4px 4px 0 0;"></div>
                        <div style="flex: 1; height: {(medium/total)*100}%; background: #bd93f9; border-radius: 4px 4px 0 0;"></div>
                        <div style="flex: 1; height: {(low/total)*100}%; background: #50fa7b; border-radius: 4px 4px 0 0;"></div>
                    </div>
                    <div style="display: flex; justify-content: space-between; font-size: 9px; color: #666; font-weight: bold;">
                        <span>CRIT</span><span>HIGH</span><span>MED</span><span>LOW</span>
                    </div>
                </div>
            </div>
            
            <table>
                <thead>
                    <tr>
                        <th style="width: 120px;">Severity</th>
                        <th>Vulnerability & Location</th>
                        <th>Evidence / Artifacts</th>
                    </tr>
                </thead>
                <tbody>
        """
        
        for v in vulnerabilities:
            sev_class = f"sev-{v.severity.lower()}"
            safe_details = html_lib.escape(v.details)
            safe_evidence = html_lib.escape(v.evidence or "No evidence captured.")
            
            html += f"""
                <tr>
                    <td class="{sev_class}">
                        <span class="tag">{v.severity}</span>
                        {f'<div style="margin-top:5px;"><span class="tag" style="background:#222; color:#aaa; font-size:9px;">ASVS {v.asvs}</span></div>' if v.asvs else ''}
                    </td>
                    <td>
                        <div style="font-weight: bold; color: #fff; font-size: 16px; margin-bottom: 5px;">{v.type}</div>
                        <div style="color: var(--accent); font-size: 12px; margin-bottom: 10px; word-break: break-all;">{v.url}</div>
                        <div style="font-size: 13px; color: #aaa;">{safe_details}</div>
                    </td>
                    <td><pre>{safe_evidence}</pre></td>
                </tr>
            """
            
        html += """
                </tbody>
            </table>
            
            <div style="margin-top: 50px; padding: 30px; border: 1px dashed var(--border); border-radius: 12px; text-align: center;">
                <div style="color: var(--accent); font-weight: 800; font-size: 11px; letter-spacing: 2px;">STRATEGIC ACTION PLAN</div>
                <p style="color: #888; font-size: 13px; max-width: 600px; margin: 15px auto;">
                    This report contains automated security intelligence. Focus remediation efforts on <b>Critical</b> and <b>High</b> findings immediately. 
                    Use the <b>BurpKiller Pro Attack Station</b> to verify BOLA and SQLi vectors manually before patching.
                </p>
            </div>
        </body>
        </html>
        """
        
        filename = f"BurpKiller_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html)
        return os.path.abspath(filename)
