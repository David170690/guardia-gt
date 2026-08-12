"""Confirmación de CVEs a partir de la versión leída del banner.

El escáner reporta "exposición" cuando ve un puerto abierto, sin afirmar un CVE.
Cuando el banner revela producto y versión, este módulo consulta la API pública
del NVD y, si hay coincidencias reales, añade hallazgos de tipo `cve` con
identificadores verificados.

Diseño defensivo:
- Desactivado por defecto (`CVE_LOOKUP_ENABLED`). El NVD limita fuerte las
  peticiones y podría ralentizar un diagnóstico en vivo.
- Best-effort: cualquier fallo (timeout, límite de tasa, formato inesperado) deja
  el hallazgo de exposición intacto en lugar de romper el diagnóstico.
- Cachea por (producto, versión) durante el proceso para no repetir consultas.
"""

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Extrae "producto versión" de los banners más comunes.
_BANNER_PATTERNS = [
    re.compile(r"OpenSSH[_/ ](?P<version>\d+\.\d+(?:p\d+)?)", re.I),
    re.compile(r"Apache[/ ](?P<version>\d+\.\d+\.\d+)", re.I),
    re.compile(r"nginx[/ ](?P<version>\d+\.\d+\.\d+)", re.I),
    re.compile(r"Microsoft-IIS[/ ](?P<version>\d+\.\d+)", re.I),
    re.compile(r"vsftpd[/ ](?P<version>\d+\.\d+\.\d+)", re.I),
    re.compile(r"ProFTPD[/ ](?P<version>\d+\.\d+\.\d+)", re.I),
    re.compile(r"Exim[/ ](?P<version>\d+\.\d+)", re.I),
    re.compile(r"Postfix", re.I),
]

_PRODUCT_NAMES = {
    "openssh": "OpenSSH",
    "apache": "Apache httpd",
    "nginx": "nginx",
    "microsoft-iis": "Microsoft IIS",
    "vsftpd": "vsftpd",
    "proftpd": "ProFTPD",
    "exim": "Exim",
}

_cache: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}


def enabled() -> bool:
    return settings.CVE_LOOKUP_ENABLED


def parse_banner(banner: str) -> Optional[Tuple[str, str]]:
    """Devuelve (producto, versión) si el banner los revela."""
    if not banner:
        return None
    for pattern in _BANNER_PATTERNS:
        match = pattern.search(banner)
        if match and "version" in match.groupdict() and match.group("version"):
            token = pattern.pattern.split("[")[0].split("(")[0].lower()
            product = _PRODUCT_NAMES.get(token, token.title())
            return product, match.group("version")
    return None


def _severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def lookup(product: str, version: str) -> List[Dict[str, Any]]:
    """Consulta el NVD por 'producto versión'. Devuelve CVEs reales o lista vacía."""
    key = (product.lower(), version)
    if key in _cache:
        return _cache[key]

    results: List[Dict[str, Any]] = []
    try:
        with httpx.Client(timeout=settings.CVE_LOOKUP_TIMEOUT_SECONDS) as client:
            response = client.get(NVD_ENDPOINT, params={
                "keywordSearch": f"{product} {version}",
                "resultsPerPage": settings.CVE_LOOKUP_MAX_PER_SERVICE,
            })
            response.raise_for_status()
            data = response.json()

        for item in data.get("vulnerabilities", [])[: settings.CVE_LOOKUP_MAX_PER_SERVICE]:
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id:
                continue
            score, severity = _extract_score(cve)
            description = ""
            for desc in cve.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            results.append({
                "cve_id": cve_id,
                "cvss_score": score,
                "severity": severity,
                "description": description[:400],
            })
    except Exception as exc:  # best-effort: cualquier fallo no interrumpe el escaneo
        logger.info("Consulta NVD fallida para %s %s: %s", product, version, exc)
        results = []

    _cache[key] = results
    return results


def _extract_score(cve: Dict[str, Any]) -> Tuple[float, str]:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            data = entries[0].get("cvssData", {})
            score = float(data.get("baseScore", 0.0))
            return score, _severity_from_cvss(score)
    return 0.0, "info"


def confirm_cves(banner: str, component: str) -> List[Dict[str, Any]]:
    """De un banner a una lista de hallazgos `cve` listos para persistir."""
    if not enabled():
        return []
    parsed = parse_banner(banner)
    if not parsed:
        return []
    product, version = parsed

    findings: List[Dict[str, Any]] = []
    for cve in lookup(product, version):
        findings.append({
            "cve_id": cve["cve_id"][:64],
            "title": f"{product} {version} — {cve['cve_id']}",
            "description": cve["description"] or f"CVE confirmado por versión en {component}.",
            "cvss_score": cve["cvss_score"],
            "severity": cve["severity"],
            "finding_type": "cve",
            "affected_component": component,
            "solution": f"Actualizar {product} a una versión posterior a la {version} que corrija {cve['cve_id']}.",
            "source": "nvd",
        })
    return findings
