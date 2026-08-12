"""Reportes y tendencias.

Antes este módulo devolvía cuatro reportes inventados con fechas y número de páginas
fijos, y una serie de tendencia escrita a mano. Ahora describe los reportes que la
plataforma puede componer con los datos que tiene, y calcula la tendencia real a
partir de las fechas de descubrimiento y remediación.
"""

import csv
import io
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response, StreamingResponse
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.asset import Asset
from app.models.compliance import ComplianceControl
from app.models.incident import Incident
from app.models.vulnerability import Severity, Vulnerability, VulnStatus
from app.services import ai_report

router = APIRouter()

MONTHS_ES = ["Ene", "Feb", "Mar", "Abr", "May", "Jun",
             "Jul", "Ago", "Sep", "Oct", "Nov", "Dic"]


@router.get("/")
def get_reports(db: Session = Depends(get_db)):
    """Reportes disponibles y el volumen de datos que respalda a cada uno."""
    vulns = db.query(Vulnerability).count()
    open_vulns = db.query(Vulnerability).filter(Vulnerability.status == VulnStatus.OPEN).count()
    assets = db.query(Asset).count()
    incidents = db.query(Incident).count()
    controls = db.query(ComplianceControl).count()

    reports = [
        {
            "id": "vulnerabilities",
            "name": "Inventario de vulnerabilidades",
            "description": "Hallazgos abiertos ordenados por CVSS, con activo afectado y remediación.",
            "records": vulns,
            "available": vulns > 0,
            "format": "CSV",
        },
        {
            "id": "assets",
            "name": "Inventario de activos",
            "description": "Activos registrados con tipo, criticidad y última fecha de escaneo.",
            "records": assets,
            "available": assets > 0,
            "format": "CSV",
        },
        {
            "id": "incidents",
            "name": "Bitácora de incidentes",
            "description": "Incidentes con severidad, estado y tiempos de contención y resolución.",
            "records": incidents,
            "available": incidents > 0,
            "format": "CSV",
        },
        {
            "id": "compliance",
            "name": "Estado de cumplimiento",
            "description": "Controles por estándar con su puntuación y hallazgos asociados.",
            "records": controls,
            "available": controls > 0,
            "format": "CSV",
        },
    ]

    return {
        "reports": reports,
        "summary": {
            "open_vulnerabilities": open_vulns,
            "total_assets": assets,
            "total_incidents": incidents,
        },
        "note": (
            "La exportación a PDF con redacción asistida todavía no está implementada. "
            "Estos reportes se componen con los datos actuales de la plataforma."
        ),
    }


@router.get("/trends")
def get_trends(months: int = 6, db: Session = Depends(get_db)):
    """Hallazgos descubiertos y remediados por mes, calculados sobre datos reales."""
    months = max(1, min(months, 24))
    now = datetime.now(timezone.utc)

    buckets: "OrderedDict[tuple, dict]" = OrderedDict()
    cursor = (now.replace(day=1) - timedelta(days=1)).replace(day=1)
    keys: List[tuple] = []
    for _ in range(months):
        keys.append((cursor.year, cursor.month))
        cursor = (cursor.replace(day=1) - timedelta(days=1)).replace(day=1)
    for key in reversed(keys):
        buckets[key] = {"discovered": 0, "remediated": 0, "risk": 0}
    # Incluye el mes en curso.
    buckets[(now.year, now.month)] = {"discovered": 0, "remediated": 0, "risk": 0}

    weights = {Severity.CRITICAL: 10, Severity.HIGH: 6, Severity.MEDIUM: 3,
               Severity.LOW: 1, Severity.INFO: 0}

    for vuln in db.query(Vulnerability).all():
        if vuln.discovered_at:
            key = (vuln.discovered_at.year, vuln.discovered_at.month)
            if key in buckets:
                buckets[key]["discovered"] += 1
                buckets[key]["risk"] += weights.get(vuln.severity, 0)
        if vuln.remediated_at:
            key = (vuln.remediated_at.year, vuln.remediated_at.month)
            if key in buckets:
                buckets[key]["remediated"] += 1

    ordered = list(buckets.items())[-months:]
    return {
        "months": [MONTHS_ES[month - 1] for (_, month) in ordered],
        "vulnerabilities": [data["discovered"] for _, data in ordered],
        "remediated": [data["remediated"] for _, data in ordered],
        "risk_scores": [min(100, data["risk"]) for _, data in ordered],
        "note": (
            "Calculado sobre las fechas de descubrimiento y remediación registradas. "
            "Los meses sin diagnósticos aparecen en cero."
        ),
    }


# ---------------------------------------------------------------- exportación

_SEVERITY_RANK = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
                  Severity.LOW: 3, Severity.INFO: 4}
_ACTIONABLE = {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW}


def _csv_response(filename: str, header: List[str], rows: List[list]) -> StreamingResponse:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(header)
    writer.writerows(rows)
    buffer.seek(0)
    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/export/{report_type}")
def export_csv(report_type: str, organization: Optional[str] = None, db: Session = Depends(get_db)):
    """Exporta un inventario a CSV. report_type: vulnerabilities|assets|incidents|compliance."""
    if report_type == "vulnerabilities":
        query = db.query(Vulnerability)
        if organization:
            query = query.join(Asset, Vulnerability.asset_id == Asset.id).filter(
                Asset.organization == organization)
        rows = [
            [v.cve_id, v.title, v.severity.value, v.cvss_score, v.finding_type or "",
             v.status.value, v.affected_component or "", v.solution or ""]
            for v in query.order_by(Vulnerability.cvss_score.desc()).all()
        ]
        return _csv_response(
            "vulnerabilidades.csv",
            ["ID", "Titulo", "Severidad", "CVSS", "Tipo", "Estado", "Componente", "Solucion"], rows)

    if report_type == "assets":
        query = db.query(Asset)
        if organization:
            query = query.filter(Asset.organization == organization)
        rows = [
            [a.name, a.organization or "", a.asset_type.value, a.ip_address or "",
             a.operating_system or "", a.criticality.value, a.status.value]
            for a in query.order_by(Asset.id).all()
        ]
        return _csv_response(
            "activos.csv",
            ["Nombre", "Organizacion", "Tipo", "IP", "SO", "Criticidad", "Estado"], rows)

    if report_type == "incidents":
        query = db.query(Incident)
        if organization:
            query = query.filter(Incident.organization == organization)
        rows = [
            [i.title, i.organization or "", i.severity.value, i.status.value,
             i.affected_asset or "", i.detected_at.isoformat() if i.detected_at else "",
             i.resolved_at.isoformat() if i.resolved_at else ""]
            for i in query.order_by(Incident.detected_at.desc()).all()
        ]
        return _csv_response(
            "incidentes.csv",
            ["Titulo", "Organizacion", "Severidad", "Estado", "Activo", "Detectado", "Resuelto"], rows)

    if report_type == "compliance":
        rows = [
            [c.standard.value, c.control_id, c.control_name, c.status.value, c.score, c.findings or ""]
            for c in db.query(ComplianceControl).all()
        ]
        return _csv_response(
            "cumplimiento.csv",
            ["Estandar", "Control", "Nombre", "Estado", "Puntuacion", "Hallazgos"], rows)

    raise HTTPException(status_code=400, detail=f"Tipo de reporte desconocido: {report_type}")


@router.get("/pdf")
def export_pdf(organization: str, db: Session = Depends(get_db)):
    """Genera un informe ejecutivo en PDF para una organización, con datos reales."""
    assets = db.query(Asset).filter(Asset.organization == organization).all()
    if not assets:
        raise HTTPException(status_code=404,
                            detail=f"No hay datos para «{organization}». Ejecuta primero un diagnóstico.")

    asset_ids = [a.id for a in assets]
    vulns = (db.query(Vulnerability).filter(Vulnerability.asset_id.in_(asset_ids))
             .order_by(Vulnerability.cvss_score.desc()).all())
    actionable = [v for v in vulns if v.severity in _ACTIONABLE]

    findings = [{
        "cve_id": v.cve_id, "title": v.title, "severity": v.severity.value,
        "cvss_score": v.cvss_score, "finding_type": v.finding_type,
        "affected_component": v.affected_component, "solution": v.solution,
    } for v in vulns]

    critical = sum(1 for v in actionable if v.severity == Severity.CRITICAL)
    high = sum(1 for v in actionable if v.severity == Severity.HIGH)
    risk = "crítico" if critical >= 3 else "alto" if (critical or high >= 3) else \
           "medio" if high else "bajo"

    report = ai_report.generate_report(
        organization=organization, risk_level=risk, findings=findings,
        assets_scanned=sum(1 for a in assets if a.ip_address), assets_total=len(assets),
    )

    pdf_bytes = _build_pdf(organization, risk, report, actionable,
                           scanned=sum(1 for a in assets if a.ip_address), total=len(assets))
    return Response(
        content=pdf_bytes, media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="informe_{_slug(organization)}.pdf"'},
    )


def _slug(text: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in text.lower())[:40]


# Paleta compartida con la interfaz web, para que el PDF se vea de la misma familia.
_PDF_ACCENT = "#0e6a72"
_PDF_INK = "#1a2230"
_PDF_MUTED = "#5a6474"
_RISK_HEX = {"crítico": "#b5271f", "alto": "#c2680a", "medio": "#a07c08", "bajo": "#15803d"}
_SEV_HEX = {"critical": "#b5271f", "high": "#c2680a", "medium": "#a07c08", "low": "#15803d", "info": "#5a6474"}
_SEV_LABEL = {"critical": "Crítico", "high": "Alto", "medium": "Medio", "low": "Bajo", "info": "Info"}


def _esc(text) -> str:
    """Escapa el texto dinámico para los Paragraph de reportlab."""
    from xml.sax.saxutils import escape
    return escape(str(text if text is not None else ""))


def _build_pdf(organization, risk, report, actionable, scanned=0, total=0) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm, mm
    from reportlab.platypus import (HRFlowable, KeepTogether, Paragraph,
                                    SimpleDocTemplate, Spacer, Table, TableStyle)

    accent = colors.HexColor(_PDF_ACCENT)
    ink = colors.HexColor(_PDF_INK)
    muted = colors.HexColor(_PDF_MUTED)
    risk_hex = colors.HexColor(_RISK_HEX.get(risk, "#333333"))

    styles = getSampleStyleSheet()
    st_summary = ParagraphStyle("gsum", parent=styles["BodyText"], fontSize=10.5, leading=16,
                                textColor=ink, alignment=TA_LEFT, spaceAfter=2)
    st_body = ParagraphStyle("gbody", parent=styles["BodyText"], fontSize=10, leading=15,
                             textColor=ink, alignment=TA_LEFT)
    st_bullet = ParagraphStyle("gbul", parent=st_body, leftIndent=14, spaceAfter=4,
                               bulletIndent=2)
    st_step = ParagraphStyle("gstep", parent=st_body, leftIndent=20, spaceAfter=5)
    st_small = ParagraphStyle("gsmall", parent=st_body, fontSize=8, textColor=muted)

    def section(title: str):
        return [
            Spacer(1, 5 * mm),
            Paragraph(f'<b>{_esc(title)}</b>',
                      ParagraphStyle("gh", parent=styles["Heading2"], fontSize=12.5,
                                     textColor=accent, spaceAfter=3)),
            HRFlowable(width="100%", thickness=1.2, color=accent, spaceAfter=7),
        ]

    # ---- banda de marca ----
    brand = Table([[
        Paragraph('<font size="17"><b>GuardIA GT</b></font><br/>'
                  '<font size="10">Informe Ejecutivo de Seguridad</font>',
                  ParagraphStyle("gbrand", parent=styles["Normal"], textColor=colors.white, leading=20)),
        Paragraph('<font size="9">Ciberseguridad<br/>con IA</font>',
                  ParagraphStyle("gshield", parent=styles["Normal"], textColor=colors.HexColor("#8fd6d0"),
                                 alignment=2, leading=12)),
    ]], colWidths=[13 * cm, 4 * cm])
    brand.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), accent),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (0, 0), 14), ("TOPPADDING", (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12), ("RIGHTPADDING", (-1, 0), (-1, 0), 14),
    ]))

    # ---- tira de KPIs ----
    def kpi(value, label, value_color=ink):
        return Paragraph(
            f'<font size="18" color="{value_color.hexval() if hasattr(value_color, "hexval") else value_color}">'
            f'<b>{_esc(value)}</b></font><br/>'
            f'<font size="8" color="{_PDF_MUTED}">{_esc(label)}</font>',
            ParagraphStyle("gkpi", parent=styles["Normal"], alignment=TA_CENTER, leading=22))

    n_crit = sum(1 for v in actionable if v.severity.value == "critical")
    n_high = sum(1 for v in actionable if v.severity.value == "high")
    kpis = Table([[
        kpi(risk.upper(), "Nivel de riesgo", risk_hex),
        kpi(f"{scanned}/{total}", "Activos escaneados"),
        kpi(str(len(actionable)), "Hallazgos accionables", colors.HexColor("#c2680a") if actionable else ink),
        kpi(f"{n_crit}·{n_high}", "Críticos · Altos"),
    ]], colWidths=[4.25 * cm] * 4)
    kpis.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f4f6f8")),
        ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#dde2e8")),
        ("LINEAFTER", (0, 0), (-2, -1), 0.6, colors.HexColor("#dde2e8")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 10), ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))

    modo = f"Redacción con IA · {report.model}" if report.generated_by == "ia" \
        else "Redacción con plantilla determinista"
    meta = Paragraph(
        f'Organización: <b>{_esc(organization)}</b>  ·  '
        f'Generado el {datetime.now(timezone.utc).strftime("%d/%m/%Y")}  ·  {_esc(modo)}',
        st_small)

    elements = [brand, Spacer(1, 4 * mm), meta, Spacer(1, 5 * mm), kpis]

    # ---- resumen ----
    elements += section("Resumen ejecutivo")
    summary_box = Table([[Paragraph(_esc(report.executive_summary), st_summary)]], colWidths=[17 * cm])
    summary_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#eef5f5")),
        ("LINEBEFORE", (0, 0), (0, -1), 3, accent),
        ("LEFTPADDING", (0, 0), (-1, -1), 12), ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 10), ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    elements.append(summary_box)

    # ---- riesgos ----
    if report.key_risks:
        block = section("Riesgos principales")
        for r in report.key_risks:
            block.append(Paragraph(f'<font color="{_PDF_ACCENT}">▪</font>&nbsp; {_esc(r)}', st_bullet))
        elements.append(KeepTogether(block))

    # ---- plan ----
    if report.remediation_plan:
        block = section("Plan de remediación priorizado")
        for i, step in enumerate(report.remediation_plan, 1):
            block.append(Paragraph(
                f'<font color="{_PDF_ACCENT}"><b>{i}.</b></font>&nbsp; {_esc(step)}', st_step))
        elements.append(KeepTogether(block))

    # ---- hallazgos ----
    elements += section("Hallazgos accionables")
    if actionable:
        data = [["Severidad", "CVSS", "Hallazgo", "Componente"]]
        for v in actionable[:30]:
            sev = v.severity.value
            data.append([
                Paragraph(f'<font color="{_SEV_HEX.get(sev, "#333")}"><b>{_SEV_LABEL.get(sev, sev)}</b></font>',
                          st_small),
                Paragraph(f"{v.cvss_score}", st_small),
                Paragraph(_esc(v.title), st_small),
                Paragraph(_esc(v.affected_component or "—"), st_small),
            ])
        table = Table(data, colWidths=[2.2 * cm, 1.4 * cm, 8.4 * cm, 5 * cm], repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), accent),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8.5),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f6f8")]),
            ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#e2e6ec")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ]))
        elements.append(table)
        if len(actionable) > 30:
            elements.append(Spacer(1, 2 * mm))
            elements.append(Paragraph(f"… y {len(actionable) - 30} hallazgos más.", st_small))
    else:
        ok = Table([[Paragraph(
            '<font color="#15803d"><b>✓ Sin hallazgos accionables.</b></font>&nbsp; '
            'El diagnóstico no identificó exposiciones que requieran acción inmediata.',
            st_body)]], colWidths=[17 * cm])
        ok.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#e9f5ee")),
            ("LINEBEFORE", (0, 0), (0, -1), 3, colors.HexColor("#15803d")),
            ("LEFTPADDING", (0, 0), (-1, -1), 12), ("RIGHTPADDING", (0, 0), (-1, -1), 12),
            ("TOPPADDING", (0, 0), (-1, -1), 10), ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ]))
        elements.append(ok)

    def _decorate(canvas, doc_):
        canvas.saveState()
        # Barra de acento superior.
        canvas.setFillColor(accent)
        canvas.rect(0, A4[1] - 4 * mm, A4[0], 4 * mm, stroke=0, fill=1)
        # Pie con línea, confidencialidad y número de página.
        canvas.setStrokeColor(colors.HexColor("#dde2e8"))
        canvas.setLineWidth(0.5)
        canvas.line(2 * cm, 1.5 * cm, A4[0] - 2 * cm, 1.5 * cm)
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(muted)
        canvas.drawString(2 * cm, 1.05 * cm,
                          "GuardIA GT · Documento confidencial · Universidad Mariano Gálvez de Guatemala")
        canvas.drawRightString(A4[0] - 2 * cm, 1.05 * cm, f"Página {doc_.page}")
        canvas.restoreState()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=1.6 * cm, bottomMargin=2.2 * cm,
                            leftMargin=2 * cm, rightMargin=2 * cm, title=f"Informe {organization}")
    doc.build(elements, onFirstPage=_decorate, onLaterPages=_decorate)
    return buffer.getvalue()
