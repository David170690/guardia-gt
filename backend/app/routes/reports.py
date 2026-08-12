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

    pdf_bytes = _build_pdf(organization, risk, report, actionable)
    return Response(
        content=pdf_bytes, media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="informe_{_slug(organization)}.pdf"'},
    )


def _slug(text: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in text.lower())[:40]


def _build_pdf(organization, risk, report, actionable) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import (Paragraph, SimpleDocTemplate, Spacer, Table,
                                    TableStyle)

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=2 * cm, bottomMargin=2 * cm,
                            leftMargin=2 * cm, rightMargin=2 * cm, title=f"Informe {organization}")
    styles = getSampleStyleSheet()
    accent = colors.HexColor("#0e6a72")
    h1 = ParagraphStyle("gh1", parent=styles["Title"], textColor=accent, fontSize=20, spaceAfter=6)
    h2 = ParagraphStyle("gh2", parent=styles["Heading2"], textColor=accent, fontSize=13,
                        spaceBefore=14, spaceAfter=6)
    body = ParagraphStyle("gbody", parent=styles["BodyText"], fontSize=10, leading=15, alignment=TA_LEFT)
    small = ParagraphStyle("gsmall", parent=body, fontSize=8, textColor=colors.grey)

    risk_color = {"crítico": "#b5271f", "alto": "#9a5b06", "medio": "#7d6209", "bajo": "#15803d"}
    elements = []
    elements.append(Paragraph("GuardIA GT — Informe Ejecutivo de Seguridad", h1))
    elements.append(Paragraph(f"Organización: <b>{organization}</b>", body))
    modo = f"IA ({report.model})" if report.generated_by == "mimo" else "plantilla determinista"
    elements.append(Paragraph(
        f'Nivel de riesgo: <b><font color="{risk_color.get(risk, "#333333")}">{risk.upper()}</font></b> · '
        f'Generado el {datetime.now(timezone.utc).strftime("%d/%m/%Y")} · Redacción: {modo}',
        small))

    elements.append(Paragraph("Resumen ejecutivo", h2))
    elements.append(Paragraph(report.executive_summary, body))

    if report.key_risks:
        elements.append(Paragraph("Riesgos principales", h2))
        for r in report.key_risks:
            elements.append(Paragraph(f"• {r}", body))

    if report.remediation_plan:
        elements.append(Paragraph("Plan de remediación priorizado", h2))
        for i, step in enumerate(report.remediation_plan, 1):
            elements.append(Paragraph(f"{i}. {step}", body))

    elements.append(Paragraph("Hallazgos accionables", h2))
    if actionable:
        data = [["Sev.", "CVSS", "Hallazgo", "Componente"]]
        for v in actionable[:30]:
            data.append([v.severity.value, f"{v.cvss_score}", v.title[:48], (v.affected_component or "")[:28]])
        table = Table(data, colWidths=[1.6 * cm, 1.4 * cm, 8.5 * cm, 5 * cm])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), accent),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f4f7")]),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d0d5dd")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(table)
    else:
        elements.append(Paragraph("No se identificaron hallazgos accionables en este diagnóstico.", body))

    elements.append(Spacer(1, 0.8 * cm))
    elements.append(Paragraph(
        "Documento generado por GuardIA GT a partir de los datos reales del diagnóstico. "
        "Universidad Mariano Gálvez de Guatemala.", small))

    doc.build(elements)
    return buffer.getvalue()
