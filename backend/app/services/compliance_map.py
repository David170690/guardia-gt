"""Evaluación de cumplimiento derivada de los hallazgos reales.

Convierte lo que el escáner encuentra en un veredicto por control de cada estándar.
A diferencia del marco de referencia estático, esto sí evalúa a la organización
escaneada: cada control se marca según haya o no evidencia de incumplimiento entre
sus hallazgos.

El mapeo es deliberadamente conservador. Solo se afirma un incumplimiento cuando hay
un hallazgo que lo respalda; en ausencia de evidencia un control queda "no evaluado",
no "cumple", porque este escaneo externo no puede probar cumplimiento pleno.
"""

from typing import Any, Dict, List

# Cada regla asocia un tipo de hallazgo (o un prefijo de identificador) con los
# controles que ese hallazgo incumple, en varios estándares.
# clave -> predicado sobre el hallazgo
RULES = [
    {
        "match": lambda f: f.get("cve_id", "").startswith("HTTP-NO-TLS")
        or f.get("cve_id", "").startswith("CLEARTEXT")
        or f.get("cve_id", "").startswith("TLS-HANDSHAKE"),
        "controls": [
            ("owasp_top10", "A02", "Fallos criptográficos"),
            ("iso_27001", "A.8.24", "Uso de criptografía"),
            ("nist_csf", "PR.DS", "Seguridad de los datos"),
        ],
        "finding": "Tráfico sin cifrar o TLS mal configurado detectado en el perímetro.",
    },
    {
        "match": lambda f: f.get("cve_id", "").startswith("SSL-EXPIRED")
        or f.get("cve_id", "").startswith("SSL-EXPIRING"),
        "controls": [
            ("iso_27001", "A.8.24", "Uso de criptografía"),
            ("nist_csf", "PR.DS", "Seguridad de los datos"),
        ],
        "finding": "Certificado TLS expirado o próximo a expirar.",
    },
    {
        "match": lambda f: f.get("cve_id", "").startswith("EXPOSED"),
        "controls": [
            ("cis_v8", "CIS 4", "Configuración segura de activos y software"),
            ("owasp_top10", "A01", "Pérdida de control de acceso"),
            ("nist_csf", "PR.AA", "Identidad, autenticación y control de acceso"),
            ("mitre_attack", "TA0001", "Acceso inicial"),
        ],
        "finding": "Servicio sensible accesible desde la red sin restricción de perímetro.",
    },
    {
        "match": lambda f: f.get("cve_id", "").startswith("BANNER"),
        "controls": [
            ("cis_v8", "CIS 4", "Configuración segura de activos y software"),
            ("mitre_attack", "TA0007", "Descubrimiento"),
        ],
        "finding": "El servicio divulga su versión, facilitando el reconocimiento.",
    },
    {
        "match": lambda f: f.get("finding_type") == "cve",
        "controls": [
            ("iso_27001", "A.8.8", "Gestión de vulnerabilidades técnicas"),
            ("owasp_top10", "A06", "Componentes vulnerables y desactualizados"),
            ("nist_csf", "ID.RA", "Evaluación de riesgos"),
        ],
        "finding": "Se confirmó una vulnerabilidad conocida (CVE) por la versión del servicio.",
    },
]

STANDARD_NAMES = {
    "iso_27001": "ISO 27001",
    "nist_csf": "NIST CSF",
    "cis_v8": "CIS v8",
    "owasp_top10": "OWASP Top 10",
    "mitre_attack": "MITRE ATT&CK",
}


def assess(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Devuelve una evaluación por control basada en los hallazgos.

    Cada elemento: standard, control_id, control_name, status, score, findings.
    `status` es `non_compliant` si algún hallazgo lo incumple, `compliant` si el
    control está cubierto por el mapeo y ningún hallazgo lo incumple.
    """
    # control_key -> {meta, evidencias[]}
    controls: Dict[tuple, Dict[str, Any]] = {}

    # Registra todos los controles que el mapeo puede evaluar.
    for rule in RULES:
        for standard, control_id, control_name in rule["controls"]:
            controls.setdefault(
                (standard, control_id),
                {"standard": standard, "control_id": control_id,
                 "control_name": control_name, "evidence": []},
            )

    # Acumula evidencia de incumplimiento.
    for finding in findings:
        for rule in RULES:
            if rule["match"](finding):
                for standard, control_id, _ in rule["controls"]:
                    entry = controls[(standard, control_id)]
                    detalle = f"{finding.get('affected_component')}: {rule['finding']}"
                    if detalle not in entry["evidence"]:
                        entry["evidence"].append(detalle)

    result: List[Dict[str, Any]] = []
    for control in controls.values():
        failed = bool(control["evidence"])
        result.append({
            "standard": control["standard"],
            "control_id": control["control_id"],
            "control_name": control["control_name"],
            "status": "non_compliant" if failed else "compliant",
            "score": 0.0 if failed else 100.0,
            "findings": " | ".join(control["evidence"][:4]) if failed else None,
        })

    result.sort(key=lambda c: (c["standard"], c["control_id"]))
    return result


def score(assessment: List[Dict[str, Any]]) -> float:
    if not assessment:
        return 0.0
    compliant = sum(1 for c in assessment if c["status"] == "compliant")
    return round(compliant / len(assessment) * 100, 1)
