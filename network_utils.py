"""Сетевые утилиты: ASN, WHOIS lookups (оптимизированные)."""

import socket
from typing import Dict, Optional
from functools import lru_cache

import dns.resolver


@lru_cache(maxsize=512)
def asn_lookup(ip: str) -> Dict[str, Optional[str]]:
    """Возвращает ASN и провайдера в формате 'nameASN:asn' (с кэшированием)."""
    asn = None
    provider = None
    netname = None

    # 1. Попытка DNS Cymru (быстрее всего)
    try:
        reversed_ip = ".".join(reversed(ip.split(".")))
        query = f"{reversed_ip}.origin.asn.cymru.com"
        answers = dns.resolver.resolve(query, "TXT", lifetime=3)
        txt = answers[0].to_text().strip('"')
        parts = [p.strip() for p in txt.split("|")]
        asn = parts[0] if parts else None
        if asn:
            try:
                as_answers = dns.resolver.resolve(
                    f"AS{asn}.asn.cymru.com", "TXT", lifetime=3)
                as_txt = as_answers[0].to_text().strip('"')
                as_parts = [p.strip() for p in as_txt.split("|")]
                provider = as_parts[-1] if as_parts else None
            except Exception:
                pass
    except Exception:
        pass

    # 2. Если DNS не дал результата, пробуем whois.cymru.com (только при необходимости)
    if not asn:
        try:
            s = socket.create_connection(("whois.cymru.com", 43), timeout=4)
            s.sendall(f"begin\nverbose\n{ip}\nend\n".encode())
            s.settimeout(4)
            resp = b""
            try:
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
            except socket.timeout:
                pass
            s.close()
            lines = [l.strip() for l in resp.decode(errors="ignore").splitlines() if l.strip()]
            if len(lines) >= 2:
                cols = [c.strip() for c in lines[-1].split("|")]
                asn = cols[0] if cols else None
                if len(cols) >= 2 and not provider:
                    provider = cols[-1]
        except Exception:
            pass

    # 3. Получение netname из RIR whois (только если нужно)
    if not provider:
        try:
            s = socket.create_connection(("whois.ripe.net", 43), timeout=3)
            s.sendall(f"{ip}\r\n".encode())
            s.settimeout(3)
            resp = b""
            try:
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
            except socket.timeout:
                pass
            s.close()
            for line in resp.decode(errors='ignore').splitlines():
                if line.lower().startswith('netname:'):
                    netname = line.split(':', 1)[1].strip()
                    break
        except Exception:
            pass

    # Формируем провайдера в стиле "nameASN:asn"
    if netname and asn:
        provider_str = f"{netname}ASN:{asn}"
    elif provider and asn:
        provider_str = f"{provider}ASN:{asn}"
    elif netname:
        provider_str = netname
    elif provider:
        provider_str = provider
    else:
        provider_str = None

    return {"asn": asn, "provider": provider_str}
