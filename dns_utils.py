"""DNS утилиты (оптимизированные с таймаутами)."""

from typing import List, Optional
import dns.resolver
import dns.reversename


# Стандартный резолвер с таймаутом
_resolver = dns.resolver.Resolver()
_resolver.timeout = 3
_resolver.lifetime = 5


def resolve_ns(domain: str) -> List[str]:
    """Получение NS записей для домена (с fallback на родительский)."""
    def query(d):
        try:
            answers = _resolver.resolve(d, "NS", lifetime=3)
            return [str(r.target).rstrip('.') for r in answers]
        except Exception:
            return []
    ns = query(domain)
    if not ns and len(domain.split('.')) > 2:
        ns = query('.'.join(domain.split('.')[-2:]))
    return ns


def resolve_mx(domain: str) -> List[str]:
    try:
        answers = _resolver.resolve(domain, "MX", lifetime=3)
        return [f"{r.preference} {str(r.exchange).rstrip('.')}" for r in answers]
    except Exception:
        return []


def resolve_txt(domain: str) -> List[str]:
    try:
        answers = _resolver.resolve(domain, "TXT", lifetime=3)
        txt_records = []
        for r in answers:
            if not getattr(r, "strings", None):
                continue
            parts = [part.decode() if hasattr(part, "decode") else str(part)
                     for part in r.strings]
            txt_records.append("".join(parts))
        return txt_records
    except Exception:
        return []


def extract_records_by_prefix(txt_records: List[str], prefix: str) -> List[str]:
    """Извлекает TXT записи, начинающиеся с заданного префикса (регистронезависимо)."""
    return [rec for rec in txt_records if rec.lower().startswith(prefix.lower())]


def resolve_ip_via_dns(domain: str, dns_server: str) -> List[str]:
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [dns_server]
    resolver.timeout = 3
    resolver.lifetime = 5
    try:
        answers = resolver.resolve(domain, "A", lifetime=3)
        return [r.address for r in answers]
    except Exception:
        return []


def get_ptr(ip: str) -> Optional[str]:
    try:
        rev = dns.reversename.from_address(ip)
        ptr = _resolver.resolve(rev, "PTR", lifetime=3)
        return str(ptr[0]).rstrip('.')
    except Exception:
        return None
