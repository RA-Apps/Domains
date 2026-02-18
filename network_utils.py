"""Сетевые утилиты: ASN, WHOIS lookups (оптимизированные)."""

import concurrent.futures
import socket
from typing import Dict, Optional, List
from functools import lru_cache

import dns.resolver


# Порты для сканирования (уменьшенный список для скорости)
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 8080, 8443]


def check_port(ip: str, port: int, timeout: float = 1.0) -> bool:
    """Проверяет, открыт ли порт на указанном IP."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def scan_ports(ip: str, ports: List[int] = None, timeout: float = 1.0, max_workers: int = 20) -> List[int]:
    """Сканирует список портов на указанном IP параллельно."""
    if ports is None:
        ports = COMMON_PORTS
    
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(check_port, ip, port, timeout): port 
            for port in ports
        }
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            if future.result():
                open_ports.append(port)
    
    return sorted(open_ports)


def _parse_ripe_whois(ip: str) -> Dict[str, Optional[str]]:
    """Парсит whois.ripe.net для получения org-name, netname, country и asn."""
    result = {"netname": None, "org_name": None, "country": None, "asn": None}
    
    try:
        s = socket.create_connection(("whois.ripe.net", 43), timeout=5)
        s.sendall(f"{ip}\r\n".encode())
        s.settimeout(5)
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
        
        text = resp.decode(errors='ignore')
        
        # Ищем netname
        for line in text.splitlines():
            if line.lower().startswith('netname:'):
                result["netname"] = line.split(':', 1)[1].strip()
                break
        
        # Ищем org-name
        for line in text.splitlines():
            if line.lower().startswith('org-name:'):
                result["org_name"] = line.split(':', 1)[1].strip()
                break
        
        # Ищем country
        for line in text.splitlines():
            if line.lower().startswith('country:'):
                result["country"] = line.split(':', 1)[1].strip()
                break
        
        # Ищем origin (ASN) в route
        for line in text.splitlines():
            if line.lower().startswith('origin:'):
                asn = line.split(':', 1)[1].strip()
                if asn.upper().startswith('AS'):
                    asn = asn[2:]
                result["asn"] = asn
                break
                
    except Exception:
        pass
    
    return result


@lru_cache(maxsize=512)
def asn_lookup(ip: str) -> Dict[str, Optional[str]]:
    """Возвращает ASN и провайдера (с кэшированием)."""
    asn = None
    provider = None
    country = None
    
    # 1. Сначала пробуем whois.ripe.net
    ripe_data = _parse_ripe_whois(ip)
    
    # Формируем provider: org-name + country
    if ripe_data["org_name"]:
        provider = ripe_data["org_name"]
        if ripe_data["country"]:
            provider += f", {ripe_data['country']}"
    elif ripe_data["netname"]:
        provider = ripe_data["netname"]
        if ripe_data["country"]:
            provider += f", {ripe_data['country']}"
    
    asn = ripe_data["asn"]
    country = ripe_data["country"]
    
    # 2. Если whois не дал ASN, пробуем DNS Cymru
    if not asn:
        try:
            reversed_ip = ".".join(reversed(ip.split(".")))
            query = f"{reversed_ip}.origin.asn.cymru.com"
            answers = dns.resolver.resolve(query, "TXT", lifetime=3)
            txt = answers[0].to_text().strip('"')
            parts = [p.strip() for p in txt.split("|")]
            asn = parts[0] if parts else None
        except Exception:
            pass
    
    # 3. Если whois не дал provider или дал бесполезный NON-RIPE, пробуем DNS Cymru
    if (not provider or provider.startswith("NON-RIPE")) and asn:
        try:
            as_answers = dns.resolver.resolve(
                f"AS{asn}.asn.cymru.com", "TXT", lifetime=3)
            as_txt = as_answers[0].to_text().strip('"')
            as_parts = [p.strip() for p in as_txt.split("|")]
            cymru_provider = as_parts[-1] if as_parts else None
            if cymru_provider:
                provider = cymru_provider
        except Exception:
            pass
    
    return {"asn": asn, "provider_raw": provider, "country": country}
