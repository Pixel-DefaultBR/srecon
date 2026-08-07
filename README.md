# srecon — Shodan Recon (srv1876073)

CLI de recon com Shodan, encaixada na estação de auditoria. Consultas Shodan são
**passivas** (batem no banco do Shodan, não no alvo); o `pipeline` faz scan **ativo**
e por isso é **bloqueado por scope** (Regra de ouro do `/root/audits/README.md`).

## Instalar
```bash
pipx install -e /root/audits/tools/srecon        # editável (dá pra tunar)
srecon init                                        # cola a API key (não ecoa)
# ou:  export SHODAN_API_KEY=...                   # via env
srecon selftest                                    # checagens offline (sem API)
```

## Comandos
```bash
srecon info                                        # plano, créditos, limites
srecon host 1.2.3.4                                # portas, serviços, CVEs (passivo)
srecon host cortex.cloudwiser.com.br --history
srecon search 'org:"ACME" port:443' --facets country,product --limit 200
srecon search 'ssl.cert.subject.cn:"*.example.com"' --count   # só conta, economiza credits
srecon search '...' --save-as ca-tls               # salva query reutilizável
srecon search --saved ca-tls
srecon scope-check cortex.cloudwiser.com.br        # testa autorização (offline)

# pipeline ativo (httpx-toolkit -> nuclei -> testssl), gated por scope/
srecon pipeline cortex.cloudwiser.com.br
srecon pipeline --from-search 'org:"ACME"' --search-limit 30 --dry-run
srecon pipeline 10.0.0.5 --stages httpx,nuclei --severity high,critical
```

## Scope-gating
- Alvo precisa bater em algum `/root/audits/scope/*.txt` (domínio, wildcard `*.x` ou CIDR).
- `--scope-file caminho.txt` usa um arquivo específico.
- `--i-am-authorized` ignora o gate (registrado no relatório) — só com autorização escrita.
- Hosts fora de escopo vindos de `--from-search` são **descartados**, não escaneados.

## Saídas
- `reports/<slug>/<YYYYMMDDTHHMMSSZ>/` — `host.json`/`.md`, `search.json`/`.csv`,
  `pipeline.md` + saídas brutas dos estágios (`httpx.jsonl`, `nuclei.jsonl`, `testssl_*.json`).

## Config
- API key: `SHODAN_API_KEY` (env) > `~/.config/srecon/config.toml` > `~/.shodan/api_key`.
- Workspace: `SRECON_WORKSPACE` (default `/root/audits`).
