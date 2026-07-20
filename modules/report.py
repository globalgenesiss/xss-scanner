"""
Modulo de RELATORIO (pos-exploracao) e recomendacoes de MITIGACAO.
"""

import json
import csv
from datetime import datetime, timezone


def print_console_report(results):
    positives = [r for r in results if r["status"] == "positivo"]
    encoded = [r for r in results if r["status"] == "encoded"]
    errors = [r for r in results if r["status"] == "erro"]

    print("\n" + "=" * 72)
    print("RELATORIO XSS SCANNER")
    print("=" * 72)
    print(f"Total de testes executados          : {len(results)}")
    print(f"Positivos (refletido sem sanitizar) : {len(positives)}")
    print(f"Refletidos porem encoded/sanitizados : {len(encoded)}")
    print(f"Erros de conexao/timeout            : {len(errors)}")
    print("-" * 72)

    if positives:
        print("\n[!] CANDIDATOS A VULNERABILIDADE (validar manualmente o contexto):\n")
        for r in positives:
            print(f"  URL     : {r['url']}")
            print(f"  Metodo  : {r['method']}")
            print(f"  Param   : {r['param']}")
            print(f"  Payload : {r['payload']}")
            print(f"  HTTP    : {r.get('http_status')}")
            print("-" * 72)
    else:
        print("\nNenhuma reflexao nao sanitizada foi encontrada com os payloads testados.")

    print("\n[MITIGACAO RECOMENDADA]")
    print(" - Output encoding contextual (HTML/JS/URL/attr) -- OWASP XSS Prevention Cheat Sheet")
    print(" - Content-Security-Policy restritiva (ex: script-src 'self'; object-src 'none')")
    print(" - Sanitizacao de input via allowlist (nao denylist) e bibliotecas testadas (ex: DOMPurify no client)")
    print(" - Cookies de sessao com flags HttpOnly, Secure e SameSite=Strict/Lax")
    print(" - Validar cada 'positivo' manualmente (contexto HTML/JS/atributo muda a exploracao real)")
    print(" - Mapear achados em MITRE ATT&CK (T1189 Drive-by Compromise / TTPs de client-side)")
    print("=" * 72 + "\n")


def save_json_report(results, path):
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_tests": len(results),
        "positives": len([r for r in results if r["status"] == "positivo"]),
        "results": results,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)


def save_csv_report(results, path):
    if not results:
        return
    fieldnames = ["url", "method", "param", "payload", "status", "http_status"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for r in results:
            writer.writerow(r)
