"""DNS утилиты (оптимизированные с таймаутами)."""

import concurrent.futures
from typing import List, Optional, Dict, Any
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


# Стандартные DKIM селекторы для проверки
DKIM_SELECTORS = [
    "mail", "default", "dkim", "google", "selector1", "selector2", 
    "k1", "k2", "smtp", "email", "mx", "cloud", "amazonses",
    "s1", "s2", "sig", "key1", "key2", "mandrill", "sendgrid",
    "zoho", "yandex", "mailru", "pdd", "pp", "smtpapi"
]


def _check_dkim_selector(domain: str, selector: str) -> Optional[str]:
    """Проверяет один DKIM селектор (для параллельного выполнения)."""
    dkim_domain = f"{selector}._domainkey.{domain}"
    try:
        answers = _resolver.resolve(dkim_domain, "TXT", lifetime=1.5)
        for r in answers:
            if not getattr(r, "strings", None):
                continue
            parts = [part.decode() if hasattr(part, "decode") else str(part)
                     for part in r.strings]
            record = "".join(parts)
            if record.lower().startswith("v=dkim"):
                return f"[{selector}] {record}"
    except Exception:
        pass
    return None


def resolve_dkim(domain: str, selectors: List[str] = None, max_workers: int = 10) -> List[str]:
    """
    Ищет DKIM записи для домена в стандартных селекторах (параллельно).
    
    Args:
        domain: Домен для проверки
        selectors: Список селекторов (если None, используются стандартные)
        max_workers: Количество параллельных потоков
    
    Returns:
        Список найденных DKIM записей с указанием селектора
    """
    if selectors is None:
        # Приоритетные селекторы первыми
        selectors = ["mail", "default", "dkim", "google", "selector1", "selector2"]
    
    dkim_records = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_selector = {
            executor.submit(_check_dkim_selector, domain, sel): sel 
            for sel in selectors
        }
        for future in concurrent.futures.as_completed(future_to_selector):
            result = future.result()
            if result:
                dkim_records.append(result)
    
    return dkim_records


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


def parse_spf(spf_record: str) -> Dict[str, Any]:
    """
    Парсит SPF запись в структурированный формат.
    
    Returns:
        {
            "raw": "v=spf1 ip4:...",
            "version": "spf1",
            "mechanisms": [
                {"type": "ip4", "value": "192.168.1.0/24", "qualifier": "+"},
                ...
            ],
            "modifiers": [
                {"name": "redirect", "value": "_spf.google.com"}
            ],
            "all_policy": {"qualifier": "~", "action": "softfail"}
        }
    """
    result = {
        "raw": spf_record,
        "version": None,
        "mechanisms": [],
        "modifiers": [],
        "all_policy": None
    }
    
    if not spf_record:
        return result
    
    parts = spf_record.split()
    
    for part in parts:
        # Версия SPF
        if part.lower().startswith("v=spf"):
            result["version"] = part.split("=")[1]
            continue
        
        # Модификаторы (name=value)
        if "=" in part and not part.startswith("ip"):
            name, value = part.split("=", 1)
            result["modifiers"].append({"name": name, "value": value})
            continue
        
        # Квалификатор механизма
        qualifier = "+"  # pass по умолчанию
        if part[0] in "+-~?":
            qualifier = part[0]
            part = part[1:]
        
        # Механизм "all"
        if part == "all":
            actions = {
                "+": "pass",
                "-": "fail", 
                "~": "softfail",
                "?": "neutral"
            }
            result["all_policy"] = {
                "qualifier": qualifier,
                "action": actions.get(qualifier, "unknown")
            }
            continue
        
        # Разбор механизмов
        mechanism = {"type": None, "value": None, "qualifier": qualifier}
        
        if ":" in part:
            mech_type, mech_value = part.split(":", 1)
            mechanism["type"] = mech_type
            mechanism["value"] = mech_value
        elif part.startswith("a"):
            mechanism["type"] = "a"
            mechanism["value"] = part[2:] if len(part) > 1 and part[1] == ":" else None
        elif part.startswith("mx"):
            mechanism["type"] = "mx"
            mechanism["value"] = part[3:] if len(part) > 2 and part[2] == ":" else None
        elif part.startswith("ptr"):
            mechanism["type"] = "ptr"
            mechanism["value"] = part[4:] if len(part) > 3 and part[3] == ":" else None
        elif part.startswith("exists"):
            mechanism["type"] = "exists"
            mechanism["value"] = part[7:] if len(part) > 6 else None
        else:
            mechanism["type"] = part
        
        result["mechanisms"].append(mechanism)
    
    return result


def format_spf_parsed(parsed: Dict[str, Any]) -> str:
    """Форматирует распарсенную SPF запись в красивый текст."""
    lines = []
    
    # Политика all
    if parsed.get("all_policy"):
        policy = parsed["all_policy"]
        qualifier_map = {
            "+": ("✅", "PASS"),
            "-": ("❌", "FAIL"),
            "~": ("⚠️", "SOFTFAIL"),
            "?": ("❓", "NEUTRAL")
        }
        icon, text = qualifier_map.get(policy["qualifier"], ("❓", "UNKNOWN"))
        lines.append(f"\n  • Политика по умолчанию: {icon} {text}")
    
    # Группировка механизмов
    mech_groups = {}
    for mech in parsed.get("mechanisms", []):
        mtype = mech["type"]
        if mtype not in mech_groups:
            mech_groups[mtype] = []
        mech_groups[mtype].append(mech)
    
    # Вывод по группам
    type_names = {
        "ip4": "• IPv4 адреса/сети",
        "ip6": "• IPv6 адреса/сети", 
        "a": "• A-записи",
        "mx": "• MX-записи",
        "include": "• Включённые SPF",
        "exists": "• Exists проверки",
        "ptr": "• PTR проверки"
    }
    
    qualifier_icons = {"+": "✓", "-": "✗", "~": "~", "?": "?"}
    
    for mtype in ["include", "ip4", "ip6", "a", "mx", "exists", "ptr"]:
        if mtype in mech_groups:
            lines.append(f"\n  {type_names.get(mtype, mtype)}:")
            for mech in mech_groups[mtype]:
                icon = qualifier_icons.get(mech["qualifier"], "✓")
                value = mech["value"] or "(текущий домен)"
                lines.append(f"    {icon} {value}")
    
    # Модификаторы
    if parsed.get("modifiers"):
        lines.append(f"\n    Модификаторы:")
        for mod in parsed["modifiers"]:
            lines.append(f"   • {mod['name']}={mod['value']}")
    
    return "\n".join(lines)
