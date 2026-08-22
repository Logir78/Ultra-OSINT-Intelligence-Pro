"""PDF export of the full scan report with intel summary cover page."""
import io
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether,
)


LEVEL_COLORS = {
    "red":    colors.HexColor("#FF3366"),
    "orange": colors.HexColor("#FFB000"),
    "green":  colors.HexColor("#00CC66"),
}

BG      = colors.HexColor("#0A0A0C")
FG      = colors.HexColor("#FFFFFF")
MUTED   = colors.HexColor("#8A8A92")
ACCENT  = colors.HexColor("#00E5FF")
DIVIDER = colors.HexColor("#242428")


def _base_styles():
    ss = getSampleStyleSheet()
    styles = {
        "title": ParagraphStyle("title", parent=ss["Title"], fontName="Helvetica-Bold",
                                fontSize=32, leading=36, textColor=FG, spaceAfter=6),
        "subtitle": ParagraphStyle("subtitle", parent=ss["Normal"], fontName="Helvetica",
                                   fontSize=10, textColor=ACCENT, spaceAfter=24,
                                   letterSpacing=2),
        "h1": ParagraphStyle("h1", parent=ss["Heading1"], fontName="Helvetica-Bold",
                             fontSize=18, textColor=FG, spaceBefore=18, spaceAfter=8),
        "h2": ParagraphStyle("h2", parent=ss["Heading2"], fontName="Helvetica-Bold",
                             fontSize=13, textColor=ACCENT, spaceBefore=12, spaceAfter=6),
        "body": ParagraphStyle("body", parent=ss["Normal"], fontName="Helvetica",
                               fontSize=10, leading=14, textColor=FG),
        "muted": ParagraphStyle("muted", parent=ss["Normal"], fontName="Helvetica",
                                fontSize=9, textColor=MUTED),
        "risk_label": ParagraphStyle("risk_label", parent=ss["Normal"], fontName="Helvetica-Bold",
                                     fontSize=11, textColor=FG),
        "risk_big": ParagraphStyle("risk_big", parent=ss["Normal"], fontName="Helvetica-Bold",
                                   fontSize=28, textColor=FG, alignment=1),
        "mono": ParagraphStyle("mono", parent=ss["Normal"], fontName="Courier",
                               fontSize=9, textColor=FG, leading=12),
        "mono_muted": ParagraphStyle("mono_muted", parent=ss["Normal"], fontName="Courier",
                                     fontSize=8, textColor=MUTED, leading=11),
    }
    return styles


def _draw_page_bg(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(BG)
    canvas.rect(0, 0, A4[0], A4[1], stroke=0, fill=1)
    # footer
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(MUTED)
    canvas.drawString(2 * cm, 1.2 * cm, "NOCTUA.osint · Confidential · Escaneo defensivo")
    canvas.drawRightString(A4[0] - 2 * cm, 1.2 * cm, f"Página {doc.page}")
    canvas.restoreState()


def _kv_table(rows: list[tuple[str, str]], col_widths=(4.5 * cm, 12 * cm)) -> Table:
    data = [[k, str(v) if v is not None else "—"] for k, v in rows]
    t = Table(data, colWidths=list(col_widths))
    t.setStyle(TableStyle([
        ("FONT", (0, 0), (0, -1), "Helvetica", 9),
        ("FONT", (1, 0), (1, -1), "Courier", 9),
        ("TEXTCOLOR", (0, 0), (0, -1), MUTED),
        ("TEXTCOLOR", (1, 0), (1, -1), FG),
        ("LINEBELOW", (0, 0), (-1, -1), 0.25, DIVIDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t


def build_pdf(scan_doc: dict, intel: dict) -> bytes:
    result = scan_doc["result"]
    domain = result["domain"]
    level = intel.get("risk_level", "orange")
    level_color = LEVEL_COLORS.get(level, LEVEL_COLORS["orange"])
    styles = _base_styles()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=2 * cm, bottomMargin=2 * cm,
    )

    flow = []

    # ── COVER: brand + intel summary ─────────────────────────────
    brand = Table([["NOCTUA", ".osint"]],
                  colWidths=[3 * cm, 3 * cm])
    brand.setStyle(TableStyle([
        ("FONT", (0, 0), (0, 0), "Helvetica-Bold", 20),
        ("FONT", (1, 0), (1, 0), "Helvetica", 20),
        ("TEXTCOLOR", (0, 0), (0, 0), FG),
        ("TEXTCOLOR", (1, 0), (1, 0), ACCENT),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
    ]))
    flow.append(brand)
    flow.append(Spacer(1, 20))

    flow.append(Paragraph("INFORME OSINT · " + datetime.now().strftime("%Y-%m-%d %H:%M"), styles["subtitle"]))
    flow.append(Paragraph(domain, styles["title"]))
    flow.append(Spacer(1, 12))

    # Risk indicator strip
    risk_strip = Table(
        [[
            Paragraph(f"<font color='#FFFFFF'><b>NIVEL DE CONFIANZA</b></font>", styles["risk_label"]),
            Paragraph(f"<font color='#FFFFFF'><b>{intel.get('confidence', 'Media').upper()}</b></font>", styles["risk_big"]),
        ]],
        colWidths=[6 * cm, 10.5 * cm],
    )
    risk_strip.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), level_color),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 18),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 18),
        ("LEFTPADDING", (0, 0), (-1, -1), 20),
        ("RIGHTPADDING", (0, 0), (-1, -1), 20),
    ]))
    flow.append(risk_strip)
    flow.append(Spacer(1, 24))

    # Intel summary: 3-point briefing
    flow.append(Paragraph("RESUMEN DE INTELIGENCIA", styles["h2"]))

    flow.append(Paragraph("Perfil del sitio", ParagraphStyle(
        "profile_label", fontName="Helvetica-Bold", fontSize=10,
        textColor=ACCENT, spaceBefore=8, spaceAfter=4)))
    flow.append(Paragraph(intel.get("profile", "—"), styles["body"]))

    flow.append(Paragraph("Puntos críticos", ParagraphStyle(
        "risks_label", fontName="Helvetica-Bold", fontSize=10,
        textColor=ACCENT, spaceBefore=14, spaceAfter=4)))
    for i, risk in enumerate(intel.get("critical_risks", []), 1):
        flow.append(Paragraph(f"<font color='{level_color.hexval()}'><b>{i}.</b></font>  {risk}", styles["body"]))
        flow.append(Spacer(1, 4))

    # Meta stats
    rm = intel.get("risk_meta", {})
    flow.append(Spacer(1, 14))
    stats_rows = [
        ("Antigüedad (años)", rm.get("age_years") if rm.get("age_years") is not None else "N/D"),
        ("Score seguridad promedio", f"{rm.get('score_average', 0)}%"),
        ("Protección WAF/CDN", "Sí" if rm.get("protected") else "No"),
        ("Puertos sensibles expuestos", ", ".join(str(p) for p in rm.get("exposed_risky_ports", [])) or "Ninguno"),
    ]
    flow.append(_kv_table(stats_rows))

    flow.append(PageBreak())

    # ── EXECUTIVE SUMMARY PAGE (Attack Path Narrative) ─────────────────────────────
    attack_path = (scan_doc.get("attack_paths") or {}).get("attack_path_none")
    oracle = scan_doc.get("risk_oracle")
    if attack_path or oracle:
        flow.append(Paragraph("RESUMEN EJECUTIVO DE RIESGO", styles["h1"]))
        flow.append(Paragraph("Análisis narrativo del peligro real para el negocio",
                              ParagraphStyle("exec_sub", fontName="Helvetica", fontSize=9,
                                             textColor=MUTED, spaceAfter=12, letterSpacing=1.5)))

        # Big risk verdict box
        if oracle:
            prob = oracle.get("probability_percent", 0)
            verdict_color = colors.HexColor("#FF3366") if prob >= 60 else (
                colors.HexColor("#FFB000") if prob >= 30 else colors.HexColor("#00CC66"))
            oracle_box = Table(
                [[
                    Paragraph(f"<font color='#FFFFFF'><b>PROBABILIDAD DE BRECHA</b><br/>"
                              f"<font size='9'>Predicción a 90 días</font></font>",
                              styles["risk_label"]),
                    Paragraph(f"<font color='#FFFFFF' size='34'><b>{prob:.0f}%</b></font>",
                              styles["risk_big"]),
                ]],
                colWidths=[8 * cm, 8.5 * cm],
            )
            oracle_box.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), verdict_color),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 22),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 22),
                ("LEFTPADDING", (0, 0), (-1, -1), 20),
                ("RIGHTPADDING", (0, 0), (-1, -1), 20),
            ]))
            flow.append(oracle_box)
            flow.append(Spacer(1, 8))
            verdict_text = oracle.get("verdict") or ""
            if verdict_text:
                flow.append(Paragraph(f"<i>“{verdict_text}”</i>",
                                       ParagraphStyle("verdict_q", fontName="Helvetica-Oblique",
                                                      fontSize=12, textColor=FG, leading=16,
                                                      leftIndent=10, rightIndent=10, spaceAfter=12)))

        # Attack Path Narrative
        if attack_path:
            exec_summary = attack_path.get("executive_summary") or ""
            if exec_summary:
                flow.append(Paragraph("El peligro explicado en lenguaje sencillo", styles["h2"]))
                flow.append(Paragraph(exec_summary, styles["body"]))
                flow.append(Spacer(1, 10))

            # Attack chain as a diagram (vertical steps)
            chain = attack_path.get("attack_chain") or []
            if chain:
                flow.append(Paragraph("El camino del ataque paso a paso", styles["h2"]))
                for step in chain:
                    step_num = step.get("step", "?")
                    step_num_cell = Paragraph(
                        f"<font color='#00E5FF' size='20'><b>{step_num}</b></font>",
                        ParagraphStyle("step_num", fontName="Helvetica-Bold", fontSize=20,
                                       textColor=ACCENT, alignment=1),
                    )
                    plain = step.get("action_plain") or step.get("action_technical") or ""
                    technical = step.get("action_technical") or ""
                    asset = step.get("asset_used") or ""
                    outcome = step.get("outcome") or ""
                    content = f"<b>{plain}</b><br/>"
                    if technical and technical != plain:
                        content += f"<font size='8' color='#8A8A92'>{technical}</font><br/>"
                    if asset:
                        content += f"<font size='9' color='#00E5FF'>Utiliza: {asset}</font><br/>"
                    if outcome:
                        content += f"<font size='9'>→ {outcome}</font>"
                    step_cell = Paragraph(content, styles["body"])
                    step_row = Table([[step_num_cell, step_cell]],
                                     colWidths=[1.5 * cm, 15 * cm])
                    step_row.setStyle(TableStyle([
                        ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#141418")),
                        ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#0F0F13")),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ("LEFTPADDING", (1, 0), (1, 0), 12),
                        ("RIGHTPADDING", (1, 0), (1, 0), 12),
                        ("TOPPADDING", (0, 0), (-1, -1), 10),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                        ("BOX", (0, 0), (-1, -1), 0.5, DIVIDER),
                    ]))
                    flow.append(step_row)
                    flow.append(Spacer(1, 4))

            # Final impact
            impact = attack_path.get("final_impact")
            if impact:
                flow.append(Spacer(1, 8))
                urg = (attack_path.get("urgency") or "medium").lower()
                urg_color = {"critical": colors.HexColor("#FF3366"),
                             "high": colors.HexColor("#FFB000"),
                             "medium": colors.HexColor("#00E5FF"),
                             "low": colors.HexColor("#8A8A92")}.get(urg, colors.HexColor("#8A8A92"))
                impact_row = Table(
                    [[Paragraph(f"<font color='#FFFFFF'><b>CONSECUENCIA FINAL PARA EL NEGOCIO</b></font>",
                                styles["risk_label"]),
                      Paragraph(f"<font color='#FFFFFF' size='9'>Urgencia: {urg.upper()}</font>",
                                styles["muted"])],
                     [Paragraph(f"<font color='#FFFFFF'>{impact}</font>", styles["body"]), ""]],
                    colWidths=[13 * cm, 3.5 * cm],
                )
                impact_row.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), urg_color),
                    ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#141418")),
                    ("SPAN", (0, 1), (-1, 1)),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 12),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                    ("TOPPADDING", (0, 0), (-1, -1), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ]))
                flow.append(impact_row)

            # Mitigation priorities
            mitigations = attack_path.get("mitigation_priorities") or []
            if mitigations:
                flow.append(Spacer(1, 12))
                flow.append(Paragraph("Acciones que rompen la cadena (por prioridad)", styles["h2"]))
                for i, m in enumerate(mitigations, 1):
                    flow.append(Paragraph(f"<font color='{ACCENT.hexval()}'><b>{i}.</b></font>  {m}",
                                           styles["body"]))
                    flow.append(Spacer(1, 4))

        flow.append(PageBreak())

    # ── SECTION: WHOIS + IP ─────────────────────────────
    flow.append(Paragraph("IDENTIDAD Y REGISTRO", styles["h1"]))
    ip = result.get("ip") or {}
    whois_data = (result.get("whois") or {}).get("data") or {}
    ident_rows = [
        ("Dominio", domain),
        ("IP", ip.get("ip")),
        ("Reverse DNS", ip.get("reverse_dns")),
        ("Registrar", whois_data.get("registrar")),
        ("Creado", whois_data.get("creation_date") or whois_data.get("created")),
        ("Expira", whois_data.get("expiration_date") or whois_data.get("expires")),
        ("Servidores DNS", ", ".join(whois_data.get("name_servers", []) if isinstance(whois_data.get("name_servers"), list) else [str(whois_data.get("name_servers", ""))])[:180]),
    ]
    flow.append(_kv_table(ident_rows))

    # ── SECTION: TECH STACK ─────────────────────────────
    tech = result.get("tech_analysis") or []
    if tech:
        flow.append(Paragraph("STACK TECNOLÓGICO", styles["h1"]))
        rows = [["Host", "Servidor", "Proxy/WAF", "CSP", "HSTS", "Estado"]]
        for t in tech[:20]:
            missing = t.get("missing_critical", []) or []
            rows.append([
                t.get("hostname", "")[:38],
                (t.get("server") or "—")[:20],
                ", ".join(p["name"] for p in (t.get("proxies") or []))[:22] or "—",
                "✗" if "content-security-policy" in missing else "✓",
                "✗" if "strict-transport-security" in missing else "✓",
                "Protegido" if t.get("is_protected") else "Directo",
            ])
        table = Table(rows, colWidths=[6.4*cm, 3*cm, 3.4*cm, 1*cm, 1*cm, 2.2*cm])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#141418")),
            ("TEXTCOLOR", (0, 0), (-1, 0), ACCENT),
            ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 9),
            ("FONT", (0, 1), (-1, -1), "Courier", 8),
            ("TEXTCOLOR", (0, 1), (-1, -1), FG),
            ("LINEBELOW", (0, 0), (-1, -1), 0.25, DIVIDER),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        flow.append(table)

    # ── SECTION: SUBDOMAINS ─────────────────────────────
    subs = (result.get("subdomains") or {}).get("found", [])
    if subs:
        flow.append(Paragraph("SUBDOMINIOS ENCONTRADOS", styles["h1"]))
        rows = [[s["subdomain"][:50], ", ".join(s.get("ips", []))[:40]] for s in subs[:40]]
        table = Table([["Subdominio", "IPs"]] + rows, colWidths=[9 * cm, 8 * cm])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#141418")),
            ("TEXTCOLOR", (0, 0), (-1, 0), ACCENT),
            ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 9),
            ("FONT", (0, 1), (-1, -1), "Courier", 8),
            ("TEXTCOLOR", (0, 1), (-1, -1), FG),
            ("LINEBELOW", (0, 0), (-1, -1), 0.25, DIVIDER),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        flow.append(table)

    # ── SECTION: PORTS + SECURITY ─────────────────────────────
    flow.append(PageBreak())
    flow.append(Paragraph("PUERTOS ABIERTOS", styles["h1"]))
    ports = (result.get("ports") or {}).get("open_ports", [])
    if ports:
        rows = [["Puerto", "Servicio"]] + [[str(p["port"]), p.get("service", "")] for p in ports]
        table = Table(rows, colWidths=[3 * cm, 14 * cm])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#141418")),
            ("TEXTCOLOR", (0, 0), (-1, 0), ACCENT),
            ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 9),
            ("FONT", (0, 1), (-1, -1), "Courier", 9),
            ("TEXTCOLOR", (0, 1), (0, -1), colors.HexColor("#00CC66")),
            ("TEXTCOLOR", (1, 1), (1, -1), FG),
            ("LINEBELOW", (0, 0), (-1, -1), 0.25, DIVIDER),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ]))
        flow.append(table)
    else:
        flow.append(Paragraph("Ningún puerto abierto detectado.", styles["muted"]))

    # Security checklists
    sec = result.get("security") or {}
    for key, label in [("basic", "SEGURIDAD BÁSICA"), ("medium", "SEGURIDAD MEDIA"), ("advanced", "SEGURIDAD AVANZADA")]:
        block = sec.get(key) or {}
        items = block.get("items", [])
        if not items:
            continue
        flow.append(Paragraph(f"{label} — {block.get('score', 0)}%", styles["h2"]))
        for it in items:
            status = it["status"]
            symbol = "✓" if status == "pass" else ("!" if status == "warn" else "✗")
            color = "#00CC66" if status == "pass" else ("#FFB000" if status == "warn" else "#FF3366")
            flow.append(Paragraph(
                f"<font color='{color}'><b>{symbol}</b></font>  <b>{it['check']}</b> "
                f"<font color='#8A8A92'>— {it.get('detail', '')[:150]}</font>",
                styles["body"]))
            flow.append(Spacer(1, 2))

    # Subdomain Takeover
    takeover = scan_doc.get("takeover")
    if takeover:
        flow.append(Paragraph("SUBDOMAIN TAKEOVER · DANGLING DNS", styles["h1"]))
        vuln_count = takeover.get("vulnerable_count", 0)
        if vuln_count > 0:
            banner = Table([[Paragraph(
                f"<font color='#FFFFFF'><b>⚠ RIESGO CRÍTICO · {vuln_count} subdominio(s) vulnerables</b></font>",
                styles["risk_label"])]], colWidths=[16.5 * cm])
            banner.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), LEVEL_COLORS["red"]),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ("LEFTPADDING", (0, 0), (-1, -1), 16),
            ]))
            flow.append(banner)
            flow.append(Spacer(1, 10))
            rows = [["Subdominio", "Servicio", "Riesgo", "Evidencia"]]
            for r_ in takeover.get("results", []):
                if not r_.get("vulnerable"):
                    continue
                rows.append([
                    r_["subdomain"][:36],
                    r_.get("service") or "—",
                    (r_.get("risk") or "").upper(),
                    (r_.get("evidence") or "")[:80],
                ])
            if len(rows) > 1:
                t = Table(rows, colWidths=[5.5 * cm, 3.5 * cm, 2.2 * cm, 5.3 * cm])
                t.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#141418")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), ACCENT),
                    ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 9),
                    ("FONT", (0, 1), (-1, -1), "Courier", 8),
                    ("TEXTCOLOR", (0, 1), (-1, -1), FG),
                    ("TEXTCOLOR", (2, 1), (2, -1), LEVEL_COLORS["red"]),
                    ("LINEBELOW", (0, 0), (-1, -1), 0.25, DIVIDER),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]))
                flow.append(t)
        else:
            flow.append(Paragraph(
                f"<font color='#00CC66'>✓</font>  Sin subdominios vulnerables detectados "
                f"(revisados {takeover.get('checked', 0)}, con CNAME: {takeover.get('with_cname', 0)}).",
                styles["body"]))

        flow.append(Spacer(1, 12))
        note = Table([[Paragraph(
            "<b>Nota técnica.</b> " + takeover.get("explanation", ""),
            ParagraphStyle("note", fontName="Helvetica", fontSize=9,
                           textColor=colors.HexColor("#E8E8EC"), leading=13))]],
            colWidths=[16.5 * cm])
        note.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#141418")),
            ("BOX", (0, 0), (-1, -1), 0.5, LEVEL_COLORS["orange"]),
            ("LEFTPADDING", (0, 0), (-1, -1), 12),
            ("RIGHTPADDING", (0, 0), (-1, -1), 12),
            ("TOPPADDING", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ]))
        flow.append(note)

    # Paste / dark-web mentions
    pastes = scan_doc.get("pastes")
    if pastes and pastes.get("total_mentions", 0) > 0:
        flow.append(Paragraph("MENCIONES EN PASTE SITES", styles["h1"]))
        for m in pastes["mentions"][:15]:
            flow.append(Paragraph(
                f"<font color='{ACCENT.hexval()}'>[{m['source_label']}]</font> "
                f"<link href='{m['url']}'><font color='#FFFFFF'>{m['title'][:100]}</font></link>",
                styles["mono"]))
            if m.get("snippet"):
                flow.append(Paragraph(
                    f"<font color='#8A8A92'>{m['snippet'][:200]}</font>", styles["mono_muted"]))
            flow.append(Spacer(1, 4))

    # Wayback
    wb = scan_doc.get("wayback") or result.get("wayback")
    if wb and (wb.get("oldest") or wb.get("newest")):
        flow.append(Paragraph("CRONOLOGÍA (WAYBACK MACHINE)", styles["h1"]))
        for label, key in [("Más antiguas", "oldest"), ("Más recientes", "newest")]:
            snaps = wb.get(key) or []
            if not snaps:
                continue
            flow.append(Paragraph(label, styles["h2"]))
            for s in snaps:
                flow.append(Paragraph(
                    f"<font color='{ACCENT.hexval()}'>{s['date'][:10]}</font>  "
                    f"<link href='{s['snapshot_url']}'><font color='#FFFFFF'>{s['snapshot_url'][:110]}</font></link>",
                    styles["mono"]))
                flow.append(Spacer(1, 2))

    doc.build(flow, onFirstPage=_draw_page_bg, onLaterPages=_draw_page_bg)
    return buf.getvalue()
