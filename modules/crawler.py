"""
Modulo de CRAWLING / descoberta de superficie de ataque.

Extrai possiveis pontos de injecao (query strings e formularios)
a partir das URLs ativas encontradas no recon.
"""

import requests
from urllib.parse import urlparse, parse_qs, urljoin
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed


def extract_injection_points(base_url, session, timeout=8, max_links=50):
    """
    Faz o crawling de uma URL, retornando uma lista de dicts:
      {url, method, param, base_params}
    representando cada parametro testavel.
    """
    points = []
    try:
        resp = session.get(base_url, timeout=timeout)
    except requests.RequestException:
        return points

    parsed = urlparse(base_url)

    # 1. Parametros presentes na propria URL
    qs = parse_qs(parsed.query)
    for param in qs:
        points.append({
            "url": base_url,
            "method": "GET",
            "param": param,
            "base_params": {k: v[0] for k, v in qs.items()},
        })

    try:
        soup = BeautifulSoup(resp.text, "html.parser")
    except Exception:
        return points

    # 2. Links internos com query string
    for link in soup.find_all("a", href=True)[:max_links]:
        full_url = urljoin(base_url, link["href"])
        p = urlparse(full_url)
        if p.netloc != parsed.netloc:
            continue
        qs_link = parse_qs(p.query)
        for param in qs_link:
            points.append({
                "url": full_url,
                "method": "GET",
                "param": param,
                "base_params": {k: v[0] for k, v in qs_link.items()},
            })

    # 3. Formularios (GET/POST)
    for form in soup.find_all("form"):
        action = form.get("action") or base_url
        form_url = urljoin(base_url, action)
        method = (form.get("method") or "GET").upper()

        base_params = {}
        field_names = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            field_names.append(name)
            base_params[name] = inp.get("value", "test")

        for name in field_names:
            points.append({
                "url": form_url,
                "method": method,
                "param": name,
                "base_params": dict(base_params),
            })

    return points


def crawl_targets(urls, threads=10, timeout=8, max_links=50):
    """
    Executa extract_injection_points em paralelo para uma lista de URLs
    e retorna a lista deduplicada de pontos de injecao.
    """
    session = requests.Session()
    session.headers.update({"User-Agent": "xss-scanner/1.0 (+authorized-security-testing)"})

    all_points = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(extract_injection_points, url, session, timeout, max_links): url
            for url in urls
        }
        for future in as_completed(futures):
            all_points.extend(future.result())

    seen = set()
    unique = []
    for p in all_points:
        key = (p["url"], p["method"], p["param"])
        if key not in seen:
            seen.add(key)
            unique.append(p)
    return unique
