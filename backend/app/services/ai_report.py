"""Generación del informe ejecutivo.

Toma los hallazgos reales de un diagnóstico y produce un resumen para dirección
más un plan de remediación priorizado.

Dos modos, y en ninguno se inventan datos:

- **Con modelo** (AI_API_KEY definida): se envían los hallazgos reales a un modelo
  abierto vía un proveedor compatible con OpenAI (OpenRouter → MiMo por defecto),
  que redacta la prosa. Si la llamada falla, se cae al modo plantilla.
- **Sin modelo**: una plantilla determinista compone el informe a partir de los
  mismos hallazgos. No es prosa "inteligente", pero es 100 % veraz.

El prompt instruye al modelo a no añadir cifras ni CVEs que no estén en la entrada.
"""

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_ES = {
    "critical": "crítico", "high": "alto", "medium": "medio",
    "low": "bajo", "info": "informativo",
}


@dataclass
class ExecutiveReport:
    organization: str
    risk_level: str
    generated_by: str          # "mimo" | "plantilla"
    executive_summary: str
    key_risks: List[str] = field(default_factory=list)
    remediation_plan: List[str] = field(default_factory=list)
    model: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "organization": self.organization,
            "risk_level": self.risk_level,
            "generated_by": self.generated_by,
            "model": self.model,
            "executive_summary": self.executive_summary,
            "key_risks": self.key_risks,
            "remediation_plan": self.remediation_plan,
        }


def ai_enabled() -> bool:
    return bool(settings.AI_API_KEY)


def configured_model() -> str:
    return settings.AI_MODEL


def _counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {k: 0 for k in SEVERITY_ORDER}
    for finding in findings:
        sev = str(finding.get("severity", "info")).lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _actionable(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    ranked = [f for f in findings if str(f.get("severity")).lower() in ("critical", "high", "medium", "low")]
    ranked.sort(key=lambda f: (SEVERITY_ORDER.get(str(f.get("severity")).lower(), 9),
                               -float(f.get("cvss_score", 0) or 0)))
    return ranked


def generate_report(
    organization: str,
    risk_level: str,
    findings: List[Dict[str, Any]],
    assets_scanned: int,
    assets_total: int,
) -> ExecutiveReport:
    """Punto de entrada. Intenta el modelo y cae a la plantilla ante cualquier fallo."""
    if ai_enabled():
        try:
            return _generate_with_model(organization, risk_level, findings, assets_scanned, assets_total)
        except Exception as exc:  # la caída a plantilla nunca deja al usuario sin informe
            logger.warning("El modelo de IA falló (%s); se usa la plantilla determinista", exc)
    return _generate_with_template(organization, risk_level, findings, assets_scanned, assets_total)


# ---------------------------------------------------------------- modo modelo


def _build_prompt(organization, risk_level, findings, assets_scanned, assets_total) -> str:
    counts = _counts(findings)
    lines = [
        f"Organización evaluada: {organization}",
        f"Activos escaneados: {assets_scanned} de {assets_total}",
        f"Nivel de riesgo calculado: {risk_level}",
        f"Conteo por severidad: crítico={counts['critical']}, alto={counts['high']}, "
        f"medio={counts['medium']}, bajo={counts['low']}, informativo={counts['info']}",
        "",
        "HALLAZGOS (esta es la única evidencia disponible; no agregues otros):",
    ]
    for f in _actionable(findings)[:40]:
        lines.append(
            f"- [{SEVERITY_ES.get(str(f.get('severity')).lower(), '?')}] "
            f"{f.get('title')} — {f.get('affected_component')} "
            f"(CVSS {f.get('cvss_score')}). Remediación sugerida: {f.get('solution')}"
        )
    if not _actionable(findings):
        lines.append("- No se encontraron hallazgos accionables.")
    return "\n".join(lines)


SYSTEM_PROMPT = (
    "Eres un analista de ciberseguridad que redacta informes ejecutivos en español "
    "para directivos sin perfil técnico de instituciones de Guatemala. "
    "Reglas estrictas:\n"
    "1. Usa ÚNICAMENTE los hallazgos que se te entregan. No inventes vulnerabilidades, "
    "CVEs, porcentajes, métricas ni fechas que no estén en los datos.\n"
    "2. Si no hay hallazgos accionables, dilo con claridad y no rellenes.\n"
    "3. Sé conciso, concreto y orientado a la acción.\n"
    "Responde SOLO con un objeto JSON válido con esta forma exacta:\n"
    '{"executive_summary": "texto de 2 a 4 frases", '
    '"key_risks": ["riesgo 1", "riesgo 2"], '
    '"remediation_plan": ["paso priorizado 1", "paso priorizado 2"]}'
)


def _generate_with_model(organization, risk_level, findings, assets_scanned, assets_total) -> ExecutiveReport:
    payload = {
        "model": settings.AI_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": _build_prompt(organization, risk_level, findings, assets_scanned, assets_total)},
        ],
        "temperature": 0.2,
        "max_tokens": settings.AI_MAX_TOKENS,
        "response_format": {"type": "json_object"},
    }
    headers = {
        "Authorization": f"Bearer {settings.AI_API_KEY}",
        "Content-Type": "application/json",
        # OpenRouter recomienda estas cabeceras para identificar la aplicación.
        "HTTP-Referer": "https://guardia-gt-frontend.onrender.com",
        "X-Title": "GuardIA GT",
    }
    with httpx.Client(timeout=settings.AI_TIMEOUT_SECONDS) as client:
        response = client.post(
            f"{settings.AI_BASE_URL.rstrip('/')}/chat/completions",
            json=payload, headers=headers,
        )
        response.raise_for_status()
        content = response.json()["choices"][0]["message"]["content"]

    parsed = _parse_model_json(content)
    return ExecutiveReport(
        organization=organization,
        risk_level=risk_level,
        generated_by="mimo",
        model=settings.AI_MODEL,
        executive_summary=parsed.get("executive_summary", "").strip()
        or _template_summary(organization, risk_level, findings, assets_scanned, assets_total),
        key_risks=[str(x).strip() for x in parsed.get("key_risks", []) if str(x).strip()][:6],
        remediation_plan=[str(x).strip() for x in parsed.get("remediation_plan", []) if str(x).strip()][:8],
    )


def _parse_model_json(content: str) -> Dict[str, Any]:
    content = content.strip()
    # Algunos modelos envuelven el JSON en ```json ... ```.
    if content.startswith("```"):
        content = content.strip("`")
        if content.lower().startswith("json"):
            content = content[4:]
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        start, end = content.find("{"), content.rfind("}")
        if 0 <= start < end:
            try:
                return json.loads(content[start:end + 1])
            except json.JSONDecodeError:
                pass
    # Sin JSON utilizable: se usa el texto como resumen.
    return {"executive_summary": content[:800]}


# ------------------------------------------------------------- modo plantilla


def _template_summary(organization, risk_level, findings, assets_scanned, assets_total) -> str:
    counts = _counts(findings)
    actionable = _actionable(findings)
    if not actionable:
        return (
            f"El diagnóstico de {organization} cubrió {assets_scanned} de {assets_total} activos "
            f"y no identificó hallazgos accionables. El nivel de riesgo resultante es {risk_level}. "
            "Se recomienda mantener el monitoreo periódico."
        )
    partes = []
    if counts["critical"]:
        partes.append(f"{counts['critical']} crítico(s)")
    if counts["high"]:
        partes.append(f"{counts['high']} alto(s)")
    if counts["medium"]:
        partes.append(f"{counts['medium']} medio(s)")
    if counts["low"]:
        partes.append(f"{counts['low']} bajo(s)")
    resumen_sev = ", ".join(partes) if partes else "sin hallazgos accionables"
    return (
        f"El diagnóstico de {organization} evaluó {assets_scanned} de {assets_total} activos y "
        f"determinó un nivel de riesgo {risk_level}. Se identificaron {len(actionable)} hallazgos "
        f"accionables ({resumen_sev}). El más relevante es «{actionable[0].get('title')}» en "
        f"{actionable[0].get('affected_component')}. Se recomienda atender los hallazgos por orden "
        "de severidad según el plan adjunto."
    )


def _generate_with_template(organization, risk_level, findings, assets_scanned, assets_total) -> ExecutiveReport:
    actionable = _actionable(findings)

    key_risks: List[str] = []
    for f in actionable[:5]:
        key_risks.append(
            f"[{SEVERITY_ES.get(str(f.get('severity')).lower(), '?')}] "
            f"{f.get('title')} en {f.get('affected_component')}"
        )

    remediation: List[str] = []
    seen = set()
    for f in actionable:
        solucion = (f.get("solution") or "").strip()
        if solucion and solucion not in seen:
            seen.add(solucion)
            remediation.append(solucion)
    remediation = remediation[:8]

    return ExecutiveReport(
        organization=organization,
        risk_level=risk_level,
        generated_by="plantilla",
        model=None,
        executive_summary=_template_summary(organization, risk_level, findings, assets_scanned, assets_total),
        key_risks=key_risks,
        remediation_plan=remediation,
    )
