"""Основной модуль для анализа доменов (оптимизированный)."""

import sys
import concurrent.futures
from typing import List, Dict, Any, Optional
from functools import partial

import idna
import whois

from utils import retry, format_date
from dns_utils import resolve_ns, resolve_mx, resolve_txt, extract_records_by_prefix, resolve_ip_via_dns, get_ptr, parse_spf, format_spf_parsed, resolve_dkim, resolve_dmarc, parse_dmarc, format_dmarc_parsed
from ssl_utils import get_ssl_info
from network_utils import asn_lookup, scan_ports, COMMON_PORTS, raw_whois_query


# Прямые WHOIS серверы для TLD, которые не обрабатываются библиотекой whois
# Формат: TLD -> (whois-сервер, кодировка ответа)
DIRECT_WHOIS_SERVERS = {
    "by": ("whois.cctld.by", "utf-8"),
    "бел": ("whois.cctld.by", "utf-8"),
    "xn--90ais": ("whois.cctld.by", "utf-8"),
}

# Поля для парсинга прямого ответа (ключ "key: value" -> подпись в выводе)
WHOIS_DIRECT_FIELDS = [
    ("registrar", "Registrar"),
    ("org", "Org"),
    ("update date", "Update Date"),
    ("creation date", "Creation Date"),
    ("expiration date", "Expiration Date"),
]



# DNS серверы для резолва
DNS_SERVERS = {
    "1.1.1.1": "Cloudflare",
    "8.8.8.8": "Google",
    "77.88.8.8": "Yandex"
}


def get_direct_whois_data(puny_domain: str) -> Dict[str, Any]:
    """Прямой WHOIS запрос к серверу реестра для TLD без поддержки в библиотеке whois."""
    result = {
        "whois_items": [],
        "name_servers": set()
    }

    tld = puny_domain.rsplit(".", 1)[-1].lower()
    server_encoding = DIRECT_WHOIS_SERVERS.get(tld)
    if not server_encoding:
        return result

    server, encoding = server_encoding
    text = retry(raw_whois_query, server, puny_domain, encoding=encoding, max_attempts=2, delay=1)
    if not text:
        return result

    # Парсим построчно формат "Key: value"
    fields = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if not value:
            continue
        if key == "name server":
            result["name_servers"].add(value.lower().rstrip("."))
        elif key not in fields:
            fields[key] = value

    # Если в ответе нет имени домена — домен не найден
    if not fields.get("domain name"):
        return {"whois_items": [], "name_servers": set()}

    for attr, label in WHOIS_DIRECT_FIELDS:
        val = fields.get(attr)
        if val:
            result["whois_items"].append(f"{label}: {val}")

    return result


def get_whois_data(puny_domain: str) -> Dict[str, Any]:
    """Получение WHOIS данных (вынесено для параллельного выполнения)."""
    whois_data = retry(whois.whois, puny_domain, max_attempts=2, delay=1)
    result = {
        "whois_items": [],
        "name_servers": set()
    }

    if whois_data:
        try:
            # Проверяем наличие имени домена в ответе
            has_domain_info = False
            if hasattr(whois_data, 'domain_name') and whois_data.domain_name:
                has_domain_info = True
            elif isinstance(whois_data, dict) and whois_data.get('domain_name'):
                has_domain_info = True

            if has_domain_info:
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
                            result["whois_items"].append(f"{label}: {val}")

                # Name servers из whois
                name_servers = None
                if hasattr(whois_data, 'name_servers'):
                    name_servers = whois_data.name_servers
                elif isinstance(whois_data, dict):
                    name_servers = whois_data.get('name_servers')

                if name_servers:
                    if isinstance(name_servers, str):
                        name_servers = [name_servers]
                    for ns in name_servers:
                        try:
                            ns_norm = ns.lower().rstrip('.')
                            if ns_norm:
                                result["name_servers"].add(ns_norm)
                        except Exception:
                            continue
        except Exception as e:
            print(f"  Ошибка обработки WHOIS данных: {e}")

    # Если библиотека whois не дала данных — пробуем прямой запрос к серверу реестра
    if not result["whois_items"] and not result["name_servers"]:
        direct = get_direct_whois_data(puny_domain)
        if direct["whois_items"] or direct["name_servers"]:
            return direct

    return result


def process_server_info(ip: str, provider_name: str) -> Dict[str, Any]:
    """Обработка информации о сервере (IP) - для параллельного выполнения."""
    ptr = get_ptr(ip)
    asn_data = asn_lookup(ip)
    
    return {
        "resolver": provider_name,
        "ip": ip,
        "ptr": ptr,
        "provider_raw": asn_data.get("provider_raw"),
        "asn_country": asn_data.get("country")
    }


def resolve_ip_parallel(puny_domain: str, dns_ip: str, provider_name: str) -> List[Dict[str, Any]]:
    """Резолв IP через конкретный DNS сервер."""
    ips = resolve_ip_via_dns(puny_domain, dns_ip)
    return [(ip, provider_name) for ip in ips]


def process_domain(domain: str, scan_ports_flag: bool = False, custom_ports: Optional[List[int]] = None) -> Dict[str, Any]:
    """Обработка одного домена - сбор всей информации (оптимизированная)."""
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
        "ssl": {},
        "open_ports": {}
    }

    # ========== Параллельное выполнение независимых операций ==========
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        # 1. Запускаем WHOIS и DNS запросы параллельно
        future_whois = executor.submit(get_whois_data, puny_domain)
        future_ns = executor.submit(resolve_ns, puny_domain)
        future_mx = executor.submit(resolve_mx, puny_domain)
        future_txt = executor.submit(resolve_txt, puny_domain)
        future_dkim = executor.submit(resolve_dkim, puny_domain)
        future_dmarc = executor.submit(resolve_dmarc, puny_domain)
        future_ssl = executor.submit(get_ssl_info, puny_domain)
        
        # 2. Резолв IP через разные DNS серверы параллельно
        future_ips = {
            executor.submit(resolve_ip_via_dns, puny_domain, dns_ip): provider_name
            for dns_ip, provider_name in DNS_SERVERS.items()
        }
        
        # Собираем результаты DNS
        data["ns"] = future_ns.result()
        mx_records = future_mx.result()
        txt_records = future_txt.result()
        dkim_records = future_dkim.result()
        dmarc_records = future_dmarc.result()
        data["ssl"] = future_ssl.result()
        
        # Обработка WHOIS
        whois_result = future_whois.result()
        resolved_ns_norm = {ns.lower().rstrip('.') for ns in data["ns"] if ns}
        
        # Добавляем WHOIS поля
        data["whois"] = whois_result["whois_items"]
        
        # Добавляем NS из WHOIS, которых нет в реальных NS
        for ns in whois_result["name_servers"]:
            if ns not in resolved_ns_norm:
                data["whois"].append(f"Name Server: {ns}")
        
        # Обработка почтовых записей
        spf_records = extract_records_by_prefix(txt_records, "v=spf1")
        spf_parsed = [parse_spf(rec) for rec in spf_records]
        
        # Парсим DMARC записи
        dmarc_parsed = [parse_dmarc(rec) for rec in dmarc_records]
        
        data["mail"] = {
            "mx": mx_records,
            "spf": spf_records,
            "spf_parsed": spf_parsed,
            "dkim": dkim_records,
            "dmarc": dmarc_records,
            "dmarc_parsed": dmarc_parsed
        }
        
        # 3. Собираем все IP адреса
        all_ips = []  # [(ip, provider_name), ...]
        for future in concurrent.futures.as_completed(future_ips):
            provider_name = future_ips[future]
            try:
                ips = future.result()
                all_ips.extend([(ip, provider_name) for ip in ips])
            except Exception:
                pass
        
        # 4. Параллельно получаем информацию о каждом IP
        future_server_info = {
            executor.submit(process_server_info, ip, provider_name): (ip, provider_name)
            for ip, provider_name in all_ips
        }
        
        for future in concurrent.futures.as_completed(future_server_info):
            try:
                server_data = future.result()
                data["servers"].append(server_data)
            except Exception:
                pass
    
    # Убираем дубликаты IP (сохраняем первый встреченный)
    unique_ips = []
    if data["servers"]:
        unique_servers = []
        seen_ips = set()
        for server in data["servers"]:
            if server["ip"] not in seen_ips:
                seen_ips.add(server["ip"])
                unique_servers.append(server)
                unique_ips.append(server["ip"])
        data["servers"] = unique_servers
    
    # Сканирование портов только для первого IP (если включено)
    if scan_ports_flag and unique_ips:
        first_ip = unique_ips[0]
        ports_to_scan = custom_ports if custom_ports else COMMON_PORTS
        open_ports = scan_ports(first_ip, ports_to_scan, timeout=0.8)
        if open_ports:
            data["open_ports"][first_ip] = open_ports

    return data


def print_pretty_results(results: Dict[str, Any]):
    """Красивый вывод результатов."""
    for idx, (domain, data) in enumerate(results.items(), 1):
        print("\n" + "=" * 80)
        print(f"📌 ДОМЕН #{idx}: {domain}")
        print("=" * 80)

        # WHOIS
        if data.get("whois"):
            print("\nWHOIS ИНФОРМАЦИЯ:\n")
            for item in data["whois"]:
                print(f"  • {item}")
        else:
            print("\nWHOIS: информация не получена (возможно скрыта регистратором)")

        # NS
        if data.get("ns"):
            print("\nNS СЕРВЕРЫ:\n")
            for ns in data["ns"]:
                print(f"  • {ns}")
        else:
            print("\nNS: не найдены")

        # Почта
        mail = data.get("mail", {})
        if mail.get("mx"):
            print("\nMX ЗАПИСИ:\n")
            for rec in mail["mx"]:
                print(f"  • {rec}")

        if mail.get("spf_parsed"):
            print("\nSPF ЗАПИСИ:")
            for idx, parsed in enumerate(mail["spf_parsed"], 1):
                if len(mail["spf_parsed"]) > 1:
                    print(f"\n    Запись #{idx}:")
                print(format_spf_parsed(parsed))

        if mail.get("dkim"):
            print("\nDKIM ЗАПИСИ:\n")
            for rec in mail["dkim"]:
                # Формат: [selector] v=DKIM1...
                if rec.startswith("[") and "]" in rec:
                    selector, dkim_data = rec[1:].split("]", 1)
                    print(f"  • Селектор: {selector}")
                    print(f"    {dkim_data.strip()}")
                else:
                    print(f"  • {rec}")

        if mail.get("dmarc_parsed"):
            print("\nDMARC ЗАПИСИ:")
            for parsed in mail["dmarc_parsed"]:
                print(format_dmarc_parsed(parsed))

        # Серверы (IP)
        if data.get("servers"):
            print("\nIP АДРЕСА И ПРОВАЙДЕРЫ:")
            for server in data["servers"]:
                print(f"\n  • IP : {server['ip']}")
                # PTR
                if server.get("ptr"):
                    print(f"    PTR: {server['ptr']}")
                # ISP - информация о провайдере (org-name + country)
                provider_raw = server.get("provider_raw")
                if provider_raw and "NON-RIPE-NCC-MANAGED-ADDRESS-BLOCK" not in provider_raw:
                    print(f"    {provider_raw}")
                # Country (LOC) - из whois, если нет - из geoip
                country = server.get("asn_country")
                if not country and server.get("geoip", {}).get("country") and server["geoip"]["country"] != "N/A":
                    country = server["geoip"]["country"]

        # Открытые порты
        open_ports = data.get("open_ports", {})
        if open_ports:
            print("\nОТКРЫТЫЕ ПОРТЫ:")
            for ip, ports in open_ports.items():
                ports_str = ", ".join(str(p) for p in ports)
                print(f"  • {ports_str}")

        # SSL
        ssl_info = data.get("ssl", {})
        if "error" in ssl_info:
            print(f"\nSSL: ошибка → {ssl_info['error']}")
        elif ssl_info:
            print("\nSSL СЕРТИФИКАТ:\n")
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
                print(
                    f"  • Issuer          : {ssl_info.get('issuer_cn', 'N/A')}")

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
                    print(
                        f"  • Статус          : ⚠️ истекает через {days} дней")
                else:
                    print(f"  • Статус          : ещё {days} дней")
        else:
            print("\nSSL: нет данных")

def process_domains(domains: List[str], scan_ports_flag: bool = False, custom_ports: Optional[List[int]] = None):
    """Основная функция обработки списка доменов."""  
    # Увеличиваем количество workers для параллельной обработки доменов
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        results = dict(zip(domains, executor.map(
            lambda d: process_domain(d, scan_ports_flag, custom_ports), domains)))
    
    print_pretty_results(results)


def parse_args(args: List[str]) -> tuple:
    """Парсит аргументы командной строки.
    
    Returns:
        (domains, scan_ports_flag, custom_ports)
    """
    domains = []
    scan_ports_flag = False
    custom_ports = []
    
    i = 0
    while i < len(args):
        if args[i] == '-p':
            scan_ports_flag = True
            # Собираем порты после -p до следующего флага или конца
            i += 1
            while i < len(args) and not args[i].startswith('-'):
                try:
                    port = int(args[i])
                    if 1 <= port <= 65535:
                        custom_ports.append(port)
                    else:
                        print(f"Предупреждение: порт {port} вне диапазона 1-65535, пропускаем")
                except ValueError:
                    # Если не число, считаем это доменом
                    domains.append(args[i])
                i += 1
        else:
            domains.append(args[i])
            i += 1
    
    return domains, scan_ports_flag, custom_ports if custom_ports else None


def main():
    if len(sys.argv) < 2:
        print("Использование: python domain.py [домен1] [домен2] ... [-p [порт1 порт2 ...]]")
        print("Примеры:")
        print("  python domain.py example.com")
        print("  python domain.py example.com -p")
        print("  python domain.py example.com -p 9090 4141")
        sys.exit(1)
    
    domains, scan_ports_flag, custom_ports = parse_args(sys.argv[1:])
    
    if not domains:
        print("Ошибка: не указаны домены")
        sys.exit(1)
    
    process_domains(domains, scan_ports_flag, custom_ports)
    print("")


if __name__ == "__main__":
    main()
