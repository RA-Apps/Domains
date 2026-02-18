"""SSL/TLS утилиты."""

import socket
import ssl
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID


def get_cn(name: x509.Name) -> str | None:
    try:
        attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        return attrs[0].value if attrs else None
    except (IndexError, ValueError, AttributeError):
        return None


def get_issuer_field(issuer: x509.Name, oid) -> str | None:
    """Извлекает значение поля из объекта issuer по OID."""
    try:
        attrs = issuer.get_attributes_for_oid(oid)
        return attrs[0].value if attrs else None
    except (IndexError, ValueError, AttributeError):
        return None


def get_ssl_info(domain: str, timeout: float = 5.0) -> dict[str, Any]:
    result: dict[str, Any] = {}

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)

        cert = x509.load_der_x509_certificate(der_cert, default_backend())

        result["subject_cn"] = get_cn(cert.subject)
        result["issuer_cn"] = get_cn(cert.issuer)

        # Дополнительные поля издателя
        result["issuer_o"] = get_issuer_field(
            cert.issuer, NameOID.ORGANIZATION_NAME)
        result["issuer_c"] = get_issuer_field(
            cert.issuer, NameOID.COUNTRY_NAME)
        result["issuer_ou"] = get_issuer_field(
            cert.issuer, NameOID.ORGANIZATIONAL_UNIT_NAME)

        valid_from = cert.not_valid_before_utc
        valid_to = cert.not_valid_after_utc

        result["valid_from"] = valid_from.strftime(
            "%Y-%m-%d") if valid_from else None
        result["valid_to"] = valid_to.strftime(
            "%Y-%m-%d") if valid_to else None

        if valid_to:
            now = datetime.now(timezone.utc)
            result["days_remaining"] = (valid_to - now).days

        return result

    except socket.gaierror as e:
        result["error"] = "Не удалось разрешить домен"
    except socket.timeout:
        result["error"] = "Таймаут соединения"
    except ConnectionRefusedError:
        result["error"] = "Соединение отклонено (порт 443 закрыт?)"
    except ssl.SSLError as e:
        result["error"] = f"Ошибка SSL/TLS handshake: {e.__class__.__name__} – {e}"
    except ValueError as e:
        result["error"] = f"Ошибка парсинга сертификата: {e}"
    except Exception as e:
        result["error"] = f"Неожиданная ошибка: {type(e).__name__}: {e}"

    if "error" not in result:
        result["error"] = "Не удалось получить или разобрать сертификат"

    return result
