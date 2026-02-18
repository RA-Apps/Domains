"""Сетевые утилиты: ASN, WHOIS lookups."""

import socket
from typing import Dict, Optional

import dns.resolver
import whois


def asn_lookup(ip: str) -> Dict[str, Optional[str]]:
    """Возвращает ASN и провайдера в формате 'nameASN:asn'."""
    asn = None
    provider = None

    # Функция для whois.cymru.com (текстовый протокол)
    def query_cymru_whois(ip_addr):
        try:
            s = socket.create_connection(("whois.cymru.com", 43), timeout=6)
            s.sendall(f"begin\nverbose\n{ip_addr}\nend\n".encode())
            resp = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
            s.close()
            lines = [l.strip() for l in resp.decode(
                errors="ignore").splitlines() if l.strip()]
            if len(lines) >= 2:
                cols = [c.strip() for c in lines[-1].split("|")]
                return cols[0] if cols else None, cols[-1] if len(cols) >= 2 else None
        except Exception as e:
            print(f"Cymru whois error: {e}")
        return None, None

    # Попытка DNS Cymru
    try:
        reversed_ip = ".".join(reversed(ip.split(".")))
        query = f"{reversed_ip}.origin.asn.cymru.com"
        answers = dns.resolver.resolve(query, "TXT")
        txt = answers[0].to_text().strip('"')
        parts = [p.strip() for p in txt.split("|")]
        asn = parts[0] if parts else None
        if asn:
            try:
                as_answers = dns.resolver.resolve(
                    f"AS{asn}.asn.cymru.com", "TXT")
                as_txt = as_answers[0].to_text().strip('"')
                as_parts = [p.strip() for p in as_txt.split("|")]
                provider = as_parts[-1] if as_parts else None
            except Exception:
                pass
    except Exception:
        pass

    # Если DNS не дал ASN, пробуем whois.cymru.com
    if not asn:
        asn, provider = query_cymru_whois(ip)

    # Получение netname из RIR whois
    netname = None
    try:
        # Пробуем RIPE
        s = socket.create_connection(("whois.ripe.net", 43), timeout=6)
        s.sendall(f"{ip}\r\n".encode())
        resp = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
        s.close()
        for line in resp.decode(errors='ignore').splitlines():
            if line.lower().startswith('netname:'):
                netname = line.split(':', 1)[1].strip()
                break
    except Exception as e:
        print(f"RIPE whois error: {e}")

    # Fallback через библиотеку whois
    if not netname:
        try:
            w = whois.whois(ip)
            netname = w.get('netname') or w.get('net_name') or w.get('NetName')
        except Exception as e:
            print(f"Whois fallback error: {e}")

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
