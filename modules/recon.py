"""
Modulo de RECONHECIMENTO.

Responsavel por:
1. Enumerar subdominios do dominio alvo via subfinder.
2. Verificar quais hosts estao ativos (respondendo HTTP/HTTPS).
"""

import shutil
import subprocess
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed


def check_subfinder_installed():
    return shutil.which("subfinder") is not None


def run_subfinder(domain, timeout=120):
    """
    Executa `subfinder -d <domain> -silent -all` e retorna a lista
    de subdominios encontrados (sem duplicatas).

    Requer subfinder instalado e no PATH:
      go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    """
    if not check_subfinder_installed():
        raise RuntimeError(
            "subfinder nao encontrado no PATH. Instale com:\n"
            "  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        )

    cmd = ["subfinder", "-d", domain, "-silent", "-all"]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"subfinder excedeu o timeout de {timeout}s para {domain}")

    if result.returncode != 0 and not result.stdout.strip():
        raise RuntimeError(f"subfinder falhou: {result.stderr.strip()}")

    subdomains = sorted(set(
        line.strip() for line in result.stdout.splitlines() if line.strip()
    ))
    return subdomains


def _probe(host, session, timeout):
    # tenta https primeiro, depois http (TTP comum de probing tipo httpx)
    candidates = [host] if host.startswith("http") else [f"https://{host}", f"http://{host}"]
    for target in candidates:
        try:
            resp = session.get(target, timeout=timeout, allow_redirects=True)
            if resp.status_code < 500:
                return target
        except requests.RequestException:
            continue
    return None


def probe_alive_hosts(hosts, threads=20, timeout=5):
    """
    Verifica quais hosts estao ativos (equivalente simplificado ao httpx).
    Retorna lista de URLs base (com esquema) que responderam.
    """
    alive = []
    session = requests.Session()
    session.headers.update({"User-Agent": "xss-scanner/1.0 (+authorized-security-testing)"})

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(_probe, h, session, timeout): h for h in hosts}
        for future in as_completed(futures):
            result = future.result()
            if result:
                alive.append(result)
    return sorted(set(alive))
