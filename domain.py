"""Основной модуль для анализа доменов."""

import sys
import concurrent.futures
from typing import List, Dict, Any

import idna
import whois

from utils import retry, format_date
from dns_utils import resolve_ns, resolve_mx, resolve_txt, extract_records_by_prefix, resolve_ip_via_dns, get_ptr
from ssl_utils import get_ssl_info
from network_utils import asn_lookup
from geoip_utils import get_geoip_info


# DNS серверы для резолва
DNS_SERVERS = {
    "1.1.1.1": "Cloudflare",
    "8.8.8.8": "Google",
    "77.88.8.8": "Yandex"
}


def process_domain(domain: str) -> Dict[str, Any]:
    """Обработка одного домена - сбор всей информации."""
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
                resolved_ns_norm = {ns.lower().rstrip('.')
                                    for ns in resolved_ns if ns}

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
    for dns_ip, provider_name in DNS_SERVERS.items():
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


def print_pretty_results(results: Dict[str, Any]):
    """Красивый вывод результатов."""
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
                    print(f"  • Статус          : ✅ ещё {days} дней")
        else:
            print("\n🔒 SSL: нет данных")


def process_domains(domains: List[str]):
    """Основная функция обработки списка доменов."""
    print(f"\n🚀 Начинаем обработку...\n")
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        results = dict(zip(domains, executor.map(process_domain, domains)))
    print_pretty_results(results)


def main():
    if len(sys.argv) < 2:
        print("Использование: python domain.py [домен1] [домен2] ...")
        sys.exit(1)
    domains = sys.argv[1:]
    process_domains(domains)


if __name__ == "__main__":
    main()
