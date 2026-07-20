"""
Modulo de EXPLORACAO.

Injeta cada payload da wordlist em cada ponto de injecao encontrado
no crawling e verifica se o payload volta refletido sem sanitizacao
na resposta HTTP (heuristica de XSS refletido).

Limitacoes conhecidas (deixar claro no relatorio):
- Deteccao e por reflexao textual no HTML de resposta, nao executa JS.
  Nao cobre XSS DOM-based que depende de execucao no navegador
  (para isso, integrar Selenium/Playwright e checar dialogos/alerts).
- Todo "positivo" deve ser validado manualmente (confirmar contexto:
  dentro de <script>, atributo, comentario HTML, etc. pode gerar
  falso positivo/negativo).
"""

import uuid
import requests
from urllib.parse import urlparse, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed


def load_payloads(path):
    with open(path, "r", encoding="utf-8") as f:
        return [line.rstrip("\n") for line in f if line.strip() and not line.startswith("#")]


def _test_point(point, payload, session, timeout):
    # marcador unico por teste, para reduzir falso positivo
    # (evita confundir com o payload ja existente na pagina por outro motivo)
    marker = uuid.uuid4().hex[:8]
    injected = payload.replace("MARKER", marker) if "MARKER" in payload else payload + marker

    params = dict(point["base_params"])
    params[point["param"]] = injected

    # remove query string da URL base para evitar parametro duplicado
    # (ex: requests concatenaria ?q=default&q=payload e o servidor usaria
    # o primeiro valor, mascarando o positivo)
    parsed = urlparse(point["url"])
    clean_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))

    try:
        if point["method"] == "GET":
            resp = session.get(clean_url, params=params, timeout=timeout)
        else:
            resp = session.post(clean_url, data=params, timeout=timeout)
    except requests.RequestException as e:
        return {**point, "payload": payload, "status": "erro", "detail": str(e)}

    body = resp.text
    reflected_raw = injected in body
    marker_present = marker in body

    if reflected_raw:
        status = "positivo"
    elif marker_present:
        status = "encoded"  # o marcador voltou, mas o payload foi sanitizado/encodado
    else:
        status = "negativo"

    return {
        **point,
        "payload": payload,
        "status": status,
        "http_status": resp.status_code,
        "response_len": len(body),
    }


def scan_injection_points(points, payloads, threads=15, timeout=8, stop_on_first_hit=True):
    """
    Testa cada (ponto de injecao x payload). Retorna lista de resultados
    com status: positivo | encoded | negativo | erro.

    stop_on_first_hit: ao achar 1 positivo num ponto, resultados
    subsequentes desse mesmo ponto sao descartados do relatorio final
    (otimizacao para nao poluir o output; os requests ja disparados
    ainda sao concluidos).
    """
    session = requests.Session()
    session.headers.update({"User-Agent": "xss-scanner/1.0 (+authorized-security-testing)"})

    tasks = [(point, payload) for point in points for payload in payloads]
    results = []
    hit_points = set()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(_test_point, point, payload, session, timeout): (point, payload)
            for point, payload in tasks
        }
        for future in as_completed(futures):
            point, payload = futures[future]
            key = (point["url"], point["method"], point["param"])

            if stop_on_first_hit and key in hit_points:
                continue

            result = future.result()
            results.append(result)

            if result["status"] == "positivo":
                hit_points.add(key)

    return results
