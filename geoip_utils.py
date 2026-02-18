"""GeoIP утилиты."""

from typing import Dict, Any

import requests


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
