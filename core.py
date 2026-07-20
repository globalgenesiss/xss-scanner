"""
CORE: logica compartilhada entre o modo CLI (main.py) e o menu interativo
(menu.py). Mantida em um unico lugar para nao duplicar a logica de scan
(e evitar reintroduzir bugs corrigidos, como parametro duplicado na URL).
"""

import requests
from modules import recon, crawler, scanner, report


def _run_scan_and_report(injection_points, payloads_path, output_prefix,
                          threads, timeout, stop_on_first_hit):
    payloads = scanner.load_payloads(payloads_path)
    total = len(payloads) * len(injection_points)
    print(f"\n[SCAN] Testando {len(payloads)} payload(s) em {len(injection_points)} "
          f"ponto(s) (~{total} requisicoes)...")

    results = scanner.scan_injection_points(
        injection_points, payloads,
        threads=threads, timeout=timeout, stop_on_first_hit=stop_on_first_hit,
    )

    report.print_console_report(results)
    report.save_json_report(results, f"{output_prefix}.json")
    report.save_csv_report(results, f"{output_prefix}.csv")
    print(f"Relatorios salvos em: {output_prefix}.json  e  {output_prefix}.csv")
    return results


def full_scan(domain, payloads_path, output_prefix, threads=15, timeout=8,
              max_links=50, subdomains_file=None, stop_on_first_hit=True):
    """
    OPCAO 1 (fluxo completo): subfinder -> probing -> crawl -> scan -> report.
    Levanta RuntimeError se subfinder nao estiver instalado/falhar.
    """
    print(f"\n[RECON] Enumerando subdominios de {domain}...")
    if subdomains_file:
        with open(subdomains_file) as f:
            subdomains = [l.strip() for l in f if l.strip()]
    else:
        subdomains = recon.run_subfinder(domain)

    print(f"[RECON] {len(subdomains)} subdominio(s) encontrado(s).")
    if not subdomains:
        subdomains = [domain]

    print("[RECON] Verificando hosts ativos (HTTP/HTTPS)...")
    alive_urls = recon.probe_alive_hosts(subdomains, threads=threads, timeout=timeout)
    print(f"[RECON] {len(alive_urls)} host(s) ativo(s).")
    if not alive_urls:
        print("Nenhum host ativo encontrado.")
        return []

    print("\n[CRAWL] Extraindo parametros de URL e campos de formulario...")
    injection_points = crawler.crawl_targets(
        alive_urls, threads=threads, timeout=timeout, max_links=max_links
    )
    print(f"[CRAWL] {len(injection_points)} ponto(s) de injecao candidato(s).")
    if not injection_points:
        print("Nenhum parametro/formulario encontrado para testar.")
        return []

    return _run_scan_and_report(
        injection_points, payloads_path, output_prefix, threads, timeout, stop_on_first_hit
    )


def single_url_scan(url, payloads_path, output_prefix, threads=10, timeout=8,
                     max_links=50, stop_on_first_hit=True):
    """
    OPCAO 2 (uma pagina so): pula subfinder/recon inteiramente. Faz o
    crawling apenas da URL colada (extrai query params e formularios
    dessa pagina) e roda o teste de XSS direto nela.
    """
    print(f"\n[CRAWL] Extraindo parametros e formularios de {url} ...")
    session = requests.Session()
    session.headers.update({"User-Agent": "xss-scanner/1.0 (+authorized-security-testing)"})

    injection_points = crawler.extract_injection_points(
        url, session, timeout=timeout, max_links=max_links
    )
    print(f"[CRAWL] {len(injection_points)} ponto(s) de injecao candidato(s).")
    if not injection_points:
        print("Nenhum parametro (query string) ou campo de formulario encontrado nessa pagina.")
        return []

    return _run_scan_and_report(
        injection_points, payloads_path, output_prefix, threads, timeout, stop_on_first_hit
    )
