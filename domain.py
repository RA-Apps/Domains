import socket
import whois
import dns.resolver
import dns.reversename
import concurrent.futures
import time
import idna
import ssl
from datetime import datetime, timezone
import sys
from typing import List, Dict, Any, Optional, Callable
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

# =========================== Утилиты повторных попыток ===========================

def retry(func: Callable, *args, max_attempts=3, delay=1, **kwargs):
    """Универсальная обёртка для повторных попыток выполнения функции."""
    for attempt in range(max_attempts):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            print(f"Retry {attempt+1}/{max_attempts} for {func.__name__}: {e}")
            if attempt < max_attempts - 1:
                time.sleep(delay)
    return None

# =========================== DNS / WHOIS helper'ы ===========================

def resolve_ns(domain: str) -> List[str]:
    """Получение NS записей для домена (с fallback на родительский)."""
    def query(d):
        try:
            answers = dns.resolver.resolve(d, "NS")
            return [str(r.target).rstrip('.') for r in answers]
        except Exception:
            return []
    ns = query(domain)
    if not ns and len(domain.split('.')) > 2:
        ns = query('.'.join(domain.split('.')[-2:]))
    return ns

def resolve_mx(domain: str) -> List[str]:
    try:
        answers = dns.resolver.resolve(domain, "MX")
        return [f"{r.preference} {str(r.exchange).rstrip('.')}" for r in answers]
    except Exception:
        return []

def resolve_txt(domain: str) -> List[str]:
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        txt_records = []
        for r in answers:
            if not getattr(r, "strings", None):
                continue
            parts = [part.decode() if hasattr(part, "decode") else str(part) for part in r.strings]
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
    try:
        answers = resolver.resolve(domain, "A")
        return [r.address for r in answers]
    except Exception:
        return []

def get_ptr(ip: str) -> Optional[str]:
    try:
        rev = dns.reversename.from_address(ip)
        ptr = dns.resolver.resolve(rev, "PTR")
        return str(ptr[0]).rstrip('.')
    except Exception:
        return None

# =========================== Форматирование дат ===========================

def format_date(date) -> Optional[str]:
    """Преобразует объект даты whois или список в строку YYYY-MM-DD."""
    if isinstance(date, list):
        date = date[0] if date else None
    if date:
        try:
            return date.strftime("%Y-%m-%d")
        except AttributeError:
            pass
    return None

def parse_cert_date(value: str) -> str:
    """Преобразует дату из сертификата в формат YYYY-MM-DD."""
    try:
        dt = datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")
        return dt.strftime("%Y-%m-%d")
    except Exception:
        return value

# =========================== SSL информация ===========================

def extract_dn_field(dn, field_name="commonName"):
    for entry in dn:
        for k, v in entry:
            if k.lower() == field_name.lower():
                return v
    return None

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
        result["issuer_cn"]  = get_cn(cert.issuer)

        # Дополнительные поля издателя
        result["issuer_o"]  = get_issuer_field(cert.issuer, NameOID.ORGANIZATION_NAME)
        result["issuer_c"]  = get_issuer_field(cert.issuer, NameOID.COUNTRY_NAME)
        result["issuer_ou"] = get_issuer_field(cert.issuer, NameOID.ORGANIZATIONAL_UNIT_NAME)

        valid_from  = cert.not_valid_before_utc
        valid_to    = cert.not_valid_after_utc

        result["valid_from"]  = valid_from.strftime("%Y-%m-%d")  if valid_from  else None
        result["valid_to"]    = valid_to.strftime("%Y-%m-%d")    if valid_to    else None

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
# =========================== GeoIP информация ===========================

def get_geoip_info(ip: str) -> Dict[str, Any]:
    """Получение геоинформации через несколько API."""
    apis = [
        ("http://ip-api.com/json/{}", lambda d: {
            "country": d.get('country', 'N/A'),
            "country_code": d.get('countryCode', 'N/A'),
            "region": d.get('regionName', 'N/A'),
            "city": d.get('city', 'N/A'),
            "zip": d.get('zip', 'N/A'),
            "lat": d.get('lat', 'N/A'),
            "lon": d.get('lon', 'N/A'),
            "timezone": d.get('timezone', 'N/A'),
            "isp": d.get('isp', 'N/A'),
            "org": d.get('org', 'N/A')
        }),
        ("https://ipapi.co/{}/json/", lambda d: {
            "country": d.get('country_name', 'N/A'),
            "country_code": d.get('country_code', 'N/A'),
            "region": d.get('region', 'N/A'),
            "city": d.get('city', 'N/A'),
            "zip": d.get('postal', 'N/A'),
            "lat": d.get('latitude', 'N/A'),
            "lon": d.get('longitude', 'N/A'),
            "timezone": d.get('timezone', 'N/A'),
            "isp": d.get('org', 'N/A'),
            "org": d.get('org', 'N/A')
        })
    ]

    for url_template, mapper in apis:
        try:
            resp = requests.get(url_template.format(ip), timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                if data.get('status') != 'fail':  # для ip-api.com успех имеет status='success'
                    return mapper(data)
        except Exception as e:
            print(f"GeoIP error ({url_template}): {e}")
            continue

    return {k: "N/A" for k in ["country", "country_code", "region", "city", "zip", "lat", "lon", "timezone", "isp", "org"]}

# =========================== ASN информация ===========================

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
            lines = [l.strip() for l in resp.decode(errors="ignore").splitlines() if l.strip()]
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
                as_answers = dns.resolver.resolve(f"AS{asn}.asn.cymru.com", "TXT")
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

# =========================== Обработка одного домена ===========================

def process_domain(domain: str) -> Dict[str, Any]:
    try:
        puny_domain = idna.encode(domain).decode('ascii')
    except Exception as e:
        print(f"IDNA error: {e}")
        puny_domain = domain

    data = {
        "domain": domain,
        "whois": [],
        "servers": [],
        "ns": [],
        "mail": {"mx": [], "spf": [], "dkim": []},
        "ssl": {}
    }

    # ========== WHOIS (может не получиться, но это не критично) ==========
    whois_data = retry(whois.whois, puny_domain, max_attempts=2, delay=1)
    
    if whois_data:
        try:
            # Проверяем наличие имени домена в ответе
            has_domain_info = False
            if hasattr(whois_data, 'domain_name') and whois_data.domain_name:
                has_domain_info = True
            elif isinstance(whois_data, dict) and whois_data.get('domain_name'):
                has_domain_info = True
                
            if has_domain_info:
                # Реальные NS для сравнения
                resolved_ns = resolve_ns(puny_domain)
                resolved_ns_norm = {ns.lower().rstrip('.') for ns in resolved_ns if ns}

                # Добавляем информацию из whois, исключая NS, которые совпадают с реальными
                fields = [
                    ('registrar', 'Registrar'),
                    ('registrar_url', 'Registrar URL'), 
                    ('org', 'Org'),
                    ('updated_date', 'Update Date'),
                    ('creation_date', 'Creation Date'),
                    ('expiration_date', 'Expiration Date')
                ]
                
                for attr, label in fields:
                    val = None
                    if hasattr(whois_data, attr):
                        val = getattr(whois_data, attr, None)
                    elif isinstance(whois_data, dict):
                        val = whois_data.get(attr)
                        
                    if val:
                        if 'date' in attr:
                            val = format_date(val)
                        if val:
                            data["whois"].append(f"{label}: {val}")
                
                # Name servers из whois
                name_servers = None
                if hasattr(whois_data, 'name_servers'):
                    name_servers = whois_data.name_servers
                elif isinstance(whois_data, dict):
                    name_servers = whois_data.get('name_servers')
                    
                if name_servers:
                    if isinstance(name_servers, str):
                        name_servers = [name_servers]
                    for ns in name_servers or []:
                        try:
                            ns_norm = ns.lower().rstrip('.')
                        except Exception:
                            continue
                        if ns_norm and ns_norm not in resolved_ns_norm:
                            data["whois"].append(f"Name Server: {ns_norm}")
        except Exception as e:
            print(f"  Ошибка обработки WHOIS данных: {e}")
    
    # ========== DNS информация (выполняется всегда) ==========
    
    # NS записи
    data["ns"] = resolve_ns(puny_domain)
    
    # MX записи
    mx_records = resolve_mx(puny_domain)
    
    # TXT записи
    txt_records = resolve_txt(puny_domain)
    
    data["mail"] = {
        "mx": mx_records,
        "spf": extract_records_by_prefix(txt_records, "v=spf1"),
        "dkim": extract_records_by_prefix(txt_records, "v=dkim1"),
        "dmarc": extract_records_by_prefix(txt_records, "v=dmarc1")
    }
    
    # ========== SSL информация ==========
    data["ssl"] = get_ssl_info(puny_domain)

    # ========== IP адреса через разные DNS ==========
    dns_servers = {"1.1.1.1": "Cloudflare", "8.8.8.8": "Google", "77.88.8.8": "Yandex"}
    
    for dns_ip, provider_name in dns_servers.items():
        ips = resolve_ip_via_dns(puny_domain, dns_ip)
        for ip in ips:
            ptr = get_ptr(ip)
            asn_data = asn_lookup(ip)
            geo = get_geoip_info(ip)
            data["servers"].append({
                "resolver": provider_name,
                "ip": ip,
                "ptr": ptr,
                "provider": asn_data.get("provider"),
                "asn": asn_data.get("asn"),
                "geoip": geo
            })
    
    # Убираем дубликаты IP
    if data["servers"]:
        unique_servers = []
        seen_ips = set()
        for server in data["servers"]:
            if server["ip"] not in seen_ips:
                seen_ips.add(server["ip"])
                unique_servers.append(server)
        data["servers"] = unique_servers
    
    return data
# =========================== Красивый вывод ===========================

def print_pretty_results(results: Dict[str, Any]):
    for idx, (domain, data) in enumerate(results.items(), 1):
        print("\n" + "=" * 80)
        print(f"📌 ДОМЕН #{idx}: {domain}")
        print("=" * 80)

        # WHOIS
        if data.get("whois"):
            print("\n📋 WHOIS ИНФОРМАЦИЯ:")
            for item in data["whois"]:
                print(f"  • {item}")
        else:
            print("\n📋 WHOIS: информация не получена (возможно скрыта регистратором)")

        # NS
        if data.get("ns"):
            print("\n🌐 NS СЕРВЕРЫ:")
            for ns in data["ns"]:
                print(f"  • {ns}")
        else:
            print("\n🌐 NS: не найдены")

        # Почта
        mail = data.get("mail", {})
        if mail.get("mx"):
            print("\n📧 MX ЗАПИСИ:")
            for rec in mail["mx"]:
                print(f"  • {rec}")
        
        if mail.get("spf"):
            print("\n🛡️ SPF ЗАПИСИ:")
            for rec in mail["spf"]:
                print(f"  • {rec}")
        
        if mail.get("dkim"):
            print("\n🔑 DKIM ЗАПИСИ:")
            for rec in mail["dkim"]:
                print(f"  • {rec}")
                
        if mail.get("dmarc"):
            print("\n📋 DMARC ЗАПИСИ:")
            for rec in mail["dmarc"]:
                print(f"  • {rec}")

        # Серверы (IP)
        if data.get("servers"):
            print("\n🖥️ IP АДРЕСА И ПРОВАЙДЕРЫ:")
            for server in data["servers"]:
                print(f"\n    IP : {server['ip']}")
                if server.get("ptr"):
                    print(f"    PTR: {server['ptr']}")
                if server.get("provider"):
                    if "NON-RIPE-NCC-MANAGED-ADDRESS-BLOCKASN" not in server["provider"]:
                        print(f"    ASN: {server['provider']}")
                if server.get("geoip", {}).get("isp") and server["geoip"]["isp"] != "N/A":
                    print(f"    ISP: {server['geoip']['isp']}")
                if server.get("geoip", {}).get("country") and server["geoip"]["country"] != "N/A":
                    print(f"    LOC: {server['geoip']['country']}")

        # SSL
        ssl_info = data.get("ssl", {})
        if "error" in ssl_info:
            print(f"\n🔒 SSL: ошибка → {ssl_info['error']}")
        elif ssl_info:
            print("\n🔒 SSL СЕРТИФИКАТ:")
            if subject := ssl_info.get("subject_cn"):
                print(f"  • Common Name     : {subject}")

            # Issuer (блок, который просили расширить)
            issuer_parts = []
            if cn := ssl_info.get("issuer_cn"):
                issuer_parts.append(f"CN={cn}")
            if o := ssl_info.get("issuer_o"):
                issuer_parts.append(f"O={o}")
            if ou := ssl_info.get("issuer_ou"):
                issuer_parts.append(f"OU={ou}")
            if c := ssl_info.get("issuer_c"):
                issuer_parts.append(f"C={c}")
            if issuer_parts:
                print(f"  • Issuer          : {', '.join(issuer_parts)}")
            else:
                print(f"  • Issuer          : {ssl_info.get('issuer_cn', 'N/A')}")

            if from_date := ssl_info.get("valid_from"):
                print(f"  • Действителен с  : {from_date}")
            if to_date := ssl_info.get("valid_to"):
                print(f"  • Действителен до : {to_date}")

            if (days := ssl_info.get("days_remaining")) is not None:
                if days < 0:
                    print(f"  • Статус          : ❌ просрочен на {-days} дней")
                elif days == 0:
                    print(f"  • Статус          : ❗ истекает сегодня")
                elif days <= 30:
                    print(f"  • Статус          : ⚠️ истекает через {days} дней")
                else:
                    print(f"  • Статус          : ✅ ещё {days} дней")
        else:
            print("\n🔒 SSL: нет данных")


# =========================== Основной запуск ===========================

def process_domains(domains: List[str]):
    print(f"\n🚀 Начинаем обработку...\n")
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        results = dict(zip(domains, executor.map(process_domain, domains)))
    print_pretty_results(results)

def main():
    if len(sys.argv) < 2:
        print("Использование: python main.py [домен1] [домен2] ...")
        sys.exit(1)
    domains = sys.argv[1:]
    process_domains(domains)

if __name__ == "__main__":
    main()