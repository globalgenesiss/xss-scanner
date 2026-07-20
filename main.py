#!/usr/bin/env python3
"""
XSS Scanner
===========
Modo 1 - Menu interativo: rode `python3 main.py` sem argumentos.
Modo 2 - CLI direto (scripts/automacao):
  python3 main.py -d example.com -y                 # recon completo
  python3 main.py -u "https://site.com/busca?q=1" -y  # so essa pagina

AVISO LEGAL: use APENAS em ativos que voce possui ou tem autorizacao
explicita por escrito para testar. Testes nao autorizados podem
configurar crime (Lei 12.737/2012 e Marco Civil da Internet no Brasil,
CFAA nos EUA, Computer Misuse Act no Reino Unido, etc).
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import core
import menu

DEFAULT_PAYLOADS = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "payloads", "xss_payloads.txt"
)


def parse_args():
    parser = argparse.ArgumentParser(
        description="XSS Scanner - recon de subdominios + teste automatizado de XSS refletido."
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("-d", "--domain", help="Dominio alvo: roda o fluxo completo (subfinder + crawl)")
    target.add_argument("-u", "--url", help="Testa apenas essa URL colada (pula subfinder/recon)")

    parser.add_argument("-p", "--payloads", default=DEFAULT_PAYLOADS, help="Arquivo de payloads XSS")
    parser.add_argument("-o", "--output", default="report", help="Prefixo dos arquivos de saida (.json/.csv)")
    parser.add_argument("--threads", type=int, default=15, help="Threads para probing/crawling/scan")
    parser.add_argument("--timeout", type=int, default=8, help="Timeout por requisicao (s)")
    parser.add_argument("--max-links", type=int, default=50, help="Max links por pagina no crawling")
    parser.add_argument("--subdomains-file", help="(so com -d) Pula o subfinder e usa lista propria de subdominios")
    parser.add_argument("--no-stop-on-hit", action="store_true", help="Continua testando todos os payloads mesmo apos achar 1 positivo por ponto")
    parser.add_argument("-y", "--yes", action="store_true", help="Confirma autorizacao para testar o alvo (pula o prompt)")
    return parser.parse_args()


def confirm_authorization(target_name, yes):
    if yes:
        return True
    resp = input(
        f"\nVoce confirma que possui autorizacao explicita para testar '{target_name}'? [s/N]: "
    ).strip().lower()
    return resp == "s"


def main():
    # sem argumentos -> abre o menu interativo
    if len(sys.argv) == 1:
        menu.main()
        return

    args = parse_args()
    target_name = args.domain or args.url

    if not confirm_authorization(target_name, args.yes):
        print("Autorizacao nao confirmada. Encerrando.")
        sys.exit(1)

    try:
        if args.url:
            core.single_url_scan(
                url=args.url,
                payloads_path=args.payloads,
                output_prefix=args.output,
                threads=args.threads,
                timeout=args.timeout,
                max_links=args.max_links,
                stop_on_first_hit=not args.no_stop_on_hit,
            )
        else:
            core.full_scan(
                domain=args.domain,
                payloads_path=args.payloads,
                output_prefix=args.output,
                threads=args.threads,
                timeout=args.timeout,
                max_links=args.max_links,
                subdomains_file=args.subdomains_file,
                stop_on_first_hit=not args.no_stop_on_hit,
            )
    except RuntimeError as e:
        print(f"[ERRO] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
