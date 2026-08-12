"""Autenticación de doble factor con TOTP (compatible con Google Authenticator).

Las columnas `mfa_enabled` y `mfa_secret` existían en el modelo desde el inicio pero
no había código detrás. Este módulo las hace funcionales: genera el secreto, el
código QR de aprovisionamiento y verifica los códigos de seis dígitos.
"""

import base64
import io

import pyotp
import qrcode

ISSUER = "GuardIA GT"


def new_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(secret: str, account: str) -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(name=account, issuer_name=ISSUER)


def qr_data_uri(uri: str) -> str:
    """Devuelve el QR como data URI PNG, listo para incrustar en un <img src>."""
    img = qrcode.make(uri)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def verify(secret: str, code: str) -> bool:
    if not secret or not code:
        return False
    # `valid_window=1` tolera un desfase de reloj de ±30 s.
    return pyotp.TOTP(secret).verify(code.strip().replace(" ", ""), valid_window=1)
