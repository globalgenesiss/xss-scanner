# XSS Scanner

Ferramenta de automação de recon + teste de XSS refletido.

**Fluxo:** Reconhecimento (subfinder) → Crawling (parâmetros/formulários) → Exploração (injeção de payloads) → Relatório/Mitigação.


## Instalação

```bash
# 1. Dependências Python
pip install -r requirements.txt

# 2. subfinder (Go >= 1.21)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
export PATH=$PATH:$(go env GOPATH)/bin
```

## Uso

### Menu interativo (recomendado)

```bash
python3 main.py
```

```
==============================================================
  XSS SCANNER
==============================================================
  [1] Recon completo (subfinder + crawl) + teste XSS automatico
  [2] Teste de XSS apenas em uma URL colada
  [0] Sair
==============================================================
Escolha uma opcao:
```

- **Opção 1** — pede o domínio, confirma autorização, e roda automaticamente o fluxo completo: `subfinder` → probing de hosts vivos → crawling de todos os paths/parâmetros → teste de XSS em cada ponto → relatório.
- **Opção 2** — pede uma URL específica (colada por você), confirma autorização, **pula o subfinder/recon inteiramente** e testa XSS só nos parâmetros/formulários daquela página.

### CLI direto (scripts/automação/CI)

```bash
# Equivalente a opcao 1 do menu
python3 main.py -d example.com -y

# Equivalente a opcao 2 do menu
python3 main.py -u "https://site.com/busca?q=1" -y
```

### Opções principais

| Flag | Descrição | Default |
|---|---|---|
| `-d, --domain` | Domínio alvo (fluxo completo) — mutuamente exclusivo com `-u` | — |
| `-u, --url` | Testa só essa URL colada, pula subfinder/recon — mutuamente exclusivo com `-d` | — |
| `-p, --payloads` | Arquivo de payloads XSS | `payloads/xss_payloads.txt` |
| `-o, --output` | Prefixo dos relatórios (`.json`/`.csv`) | `report` |
| `--threads` | Threads de probing/crawl/scan | `15` |
| `--timeout` | Timeout por requisição (s) | `8` |
| `--max-links` | Máx. links por página no crawling | `50` |
| `--subdomains-file` | Pula o subfinder e usa lista própria de subdomínios | — |
| `--no-stop-on-hit` | Continua testando todos payloads mesmo após 1 positivo | `False` |
| `-y, --yes` | Confirma autorização sem prompt interativo | `False` |

### Exemplo pulando o subfinder (útil se já tem a lista, ou para ambiente de teste)

```bash
python3 main.py -d meusite.com -y --subdomains-file subs.txt
```

## Arquitetura

```
xss_scanner/
├── main.py                 # entrypoint: menu (sem args) ou CLI (com args)
├── menu.py                  # menu interativo de terminal (opcoes 1 e 2)
├── core.py                  # logica compartilhada: full_scan() e single_url_scan()
├── modules/
│   ├── recon.py            # subfinder + probing de hosts vivos (estilo httpx)
│   ├── crawler.py           # extração de query params e formulários
│   ├── scanner.py          # injeção de payloads + detecção de reflexão
│   └── report.py           # console/JSON/CSV + recomendações de mitigação
├── payloads/
│   └── xss_payloads.txt    # wordlist de payloads (editável)
└── requirements.txt
```

## Como a detecção funciona

Para cada parâmetro encontrado (query string em links/URLs e campos de
formulário GET/POST), a ferramenta injeta cada payload da wordlist com um
**marcador único** (substitui `MARKER`) e verifica a resposta HTTP:

- **`positivo`** – payload voltou refletido *sem alteração* no corpo da resposta (candidato forte a XSS refletido).
- **`encoded`** – o marcador voltou, mas o payload foi alterado/escapado (indício de sanitização funcionando).
- **`negativo`** – nem o marcador voltou (parâmetro não refletido nessa página, ou filtrado/bloqueado).
- **`erro`** – falha de conexão/timeout.

## Limitações (importante)

- **Heurística por reflexão textual**, não executa JavaScript. Não cobre:
  - XSS **DOM-based** (depende de execução no navegador — próximo passo natural seria integrar Selenium/Playwright e checar `alert()`/mutação do DOM real).
  - XSS **stored** que só reflete em outra página/sessão.
- Formulários com CSRF token dinâmico podem falhar (o token é reenviado com valor antigo/capturado no crawling).

## Mitigação (resumo)

- Output encoding contextual (HTML/JS/URL/atributo) — OWASP XSS Prevention Cheat Sheet.
- `Content-Security-Policy` restritiva (ex: `script-src 'self'; object-src 'none'`).
- Sanitização de input via **allowlist**, nunca denylist.
- Cookies de sessão com `HttpOnly`, `Secure`, `SameSite=Strict/Lax`.
- Mapeamento em MITRE ATT&CK: client-side attacks relacionados a XSS costumam servir como vetor inicial (ex: T1189 Drive-by Compromise) para roubo de sessão/token.
