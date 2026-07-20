"""
MENU interativo de terminal.

[1] Recon completo (subfinder + crawl) + teste de XSS automatico.
[2] Teste de XSS apenas na URL colada (pula subfinder/recon).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import core

DEFAULT_PAYLOADS = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "payloads", "xss_payloads.txt"
)


def ask(prompt, default=None):
    suffix = f" [{default}]" if default is not None else ""
    resp = input(f"{prompt}{suffix}: ").strip()
    return resp if resp else default


def ask_int(prompt, default):
    resp = ask(prompt, str(default))
    try:
        return int(resp)
    except (TypeError, ValueError):
        return default


def confirm_authorization(target):
    resp = input(
        f"\nVoce confirma que possui autorizacao explicita para testar '{target}'? [s/N]: "
    ).strip().lower()
    return resp == "s"


def show_menu():
    print("\n" + "=" * 62)
    print("  XSS SCANNER")
    print("=" * 62)
    print("  [1] Recon completo (subfinder + crawl) + teste XSS automatico")
    print("  [2] Teste de XSS apenas em uma URL colada")
    print("  [0] Sair")
    print("=" * 62)
    return input("Escolha uma opcao: ").strip()


def option_full_scan():
    domain = ask("Dominio alvo (ex: example.com)")
    if not domain:
        print("Dominio nao informado.")
        return

    if not confirm_authorization(domain):
        print("Autorizacao nao confirmada. Cancelando.")
        return

    try:
        core.full_scan(
            domain=domain,
            payloads_path=DEFAULT_PAYLOADS,
            output_prefix="report",
            threads=15,
            timeout=8,
        )
    except RuntimeError as e:
        print(f"[ERRO] {e}")


def option_single_url():
    url = ask("Cole a URL a testar (ex: https://site.com/busca?q=1)")
    if not url:
        print("URL nao informada.")
        return

    if not confirm_authorization(url):
        print("Autorizacao nao confirmada. Cancelando.")
        return

    core.single_url_scan(
        url=url,
        payloads_path=DEFAULT_PAYLOADS,
        output_prefix="report_url",
        threads=10,
        timeout=8,
    )


def main():
    while True:
        choice = show_menu()
        if choice == "1":
            option_full_scan()
        elif choice == "2":
            option_single_url()
        elif choice == "0":
            print("Encerrando.")
            break
        else:
            print("Opcao invalida.")


if __name__ == "__main__":
    main()
