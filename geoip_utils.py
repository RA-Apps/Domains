"""GeoIP утилиты (оптимизированные с кэшированием и асинхронностью)."""

import asyncio
from typing import Dict, Any, Optional
from functools import lru_cache

import aiohttp


async def _fetch_geoip(session: aiohttp.ClientSession, url: str) -> Optional[Dict]:
    """Асинхронный запрос к GeoIP API."""
    try:
        async with session.get(url) as resp:
            if resp.status == 200:
                data = await resp.json()
                if data.get('status') != 'fail':
                    return data
    except Exception:
        pass
    return None


def _map_ipapi(data: Dict) -> Dict[str, Any]:
    """Маппер для ip-api.com."""
    return {
        "country": data.get('country', 'N/A'),
        "country_code": data.get('countryCode', 'N/A'),
        "region": data.get('regionName', 'N/A'),
        "city": data.get('city', 'N/A'),
        "zip": data.get('zip', 'N/A'),
        "lat": data.get('lat', 'N/A'),
        "lon": data.get('lon', 'N/A'),
        "timezone": data.get('timezone', 'N/A'),
        "isp": data.get('isp', 'N/A'),
        "org": data.get('org', 'N/A')
    }


def _map_ipapico(data: Dict) -> Dict[str, Any]:
    """Маппер для ipapi.co."""
    return {
        "country": data.get('country_name', 'N/A'),
        "country_code": data.get('country_code', 'N/A'),
        "region": data.get('region', 'N/A'),
        "city": data.get('city', 'N/A'),
        "zip": data.get('postal', 'N/A'),
        "lat": data.get('latitude', 'N/A'),
        "lon": data.get('longitude', 'N/A'),
        "timezone": data.get('timezone', 'N/A'),
        "isp": data.get('org', 'N/A'),
        "org": data.get('org', 'N/A')
    }


async def _get_geoip_info_async(ip: str) -> Dict[str, Any]:
    """Асинхронное получение геоинформации."""
    apis = [
        (f"http://ip-api.com/json/{ip}", _map_ipapi),
        (f"https://ipapi.co/{ip}/json/", _map_ipapico),
    ]
    
    # Создаём сессию с ограничениями и таймаутом
    timeout = aiohttp.ClientTimeout(total=5, connect=2)
    connector = aiohttp.TCPConnector(
        limit=10,
        limit_per_host=5,
        ttl_dns_cache=300,
        use_dns_cache=True,
    )
    
    async with aiohttp.ClientSession(
        connector=connector,
        timeout=timeout
    ) as session:
        # Запрашиваем все API параллельно, берем первый успешный
        tasks = [_fetch_geoip(session, url) for url, _ in apis]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for (url, mapper), data in zip(apis, results):
            if isinstance(data, dict):
                return mapper(data)
    
    return {k: "N/A" for k in ["country", "country_code", "region", "city", "zip", "lat", "lon", "timezone", "isp", "org"]}


# Синхронная обертка с кэшированием
@lru_cache(maxsize=512)
def get_geoip_info(ip: str) -> Dict[str, Any]:
    """Получение геоинформации (с кэшированием)."""
    return asyncio.run(_get_geoip_info_async(ip))
