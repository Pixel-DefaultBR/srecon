# srecon — Shodan Recon (srv1876073)

CLI de recon com Shodan, encaixada na estação de auditoria. Consultas Shodan são
**passivas** (batem no banco do Shodan, não no alvo); o `pipeline` faz scan **ativo**
e por isso é **bloqueado por scope** (Regra de ouro do `/root/audits/README.md`).

## Instalar
```bash
# host novo / reprodutível: instala o toolchain pinado (Go tools + testssl) + srecon
./install.sh                                       # pins sobrescrevíveis por env
# já tem o toolchain (ex: Kali com os pacotes): só a tool
pipx install -e /root/audits/tools/srecon          # editável (dá pra tunar)

srecon init                                        # cola a API key (não ecoa)
# ou:  export SHODAN_API_KEY=...                   # via env
srecon selftest                                    # checagens offline (sem API)

pip install -e '.[test]' && pytest                 # dev: roda a suíte
```
O `install.sh` usa `go install` (nomes `httpx`/`dnsx`/…) e o `resolve_bin` acha tanto
esses quanto os renomeados do Kali (`httpx-toolkit`/`testssl`). **Metasploit fica de fora**
(pesado); `srecon msf` só precisa do cache `~/.msf4/store/modules_metadata.json`.

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

# enum de subdomínios (passivo/OSINT): subfinder -> dnsx, anota in/out de escopo
srecon subs cloudwiser.com.br
srecon subs cloudwiser.com.br --fast --no-resolve

# CVE intel via CVEDB (grátis, sem key/credits): CVSS, EPSS, KEV + módulos MSF
srecon cve CVE-2021-44228 CVE-2011-2523 --msf
# rollup cross-host: agrega CVEs de todos os host.json salvos, enriquece e mapeia MSF
srecon vulns --enrich --msf --min-cvss 7.0

# metasploit: casa versões/CVEs achados com módulos (offline, via cache de metadata)
srecon msf 1.2.3.4                       # lookup passivo no Shodan -> CVEs/produtos -> módulos
srecon msf --cve CVE-2021-44228          # CVE direto -> módulos
srecon msf 10.0.0.5 --cve CVE-2021-44228 --rc   # gera triage.rc (RHOSTS pronto, sem 'run')
srecon msf --report reports/host-x/.../host.json --min-rank great

# pipeline ativo (httpx-toolkit -> nuclei -> testssl), gated por scope/
srecon pipeline cortex.cloudwiser.com.br
srecon pipeline --from-search 'org:"ACME"' --search-limit 30 --dry-run
srecon pipeline 10.0.0.5 --stages httpx,nuclei --severity high,critical
# FUNIL: enumera subdomínios do domínio e joga os vivos no pipeline (gated por scope *.dom)
srecon pipeline --from-subs cloudwiser.com.br
srecon pipeline --from-file alvos.txt    # 1 alvo por linha ('#' = comentário)

# crawl ativo com katana (gated por scope): URLs/JS/params/subs + forms/segredos/API + diff
srecon crawl cortex.cloudwiser.com.br
srecon crawl https://app.cortex.cloudwiser.com.br/ -d 4 -H 'Cookie: session=abc'
srecon crawl cortex.cloudwiser.com.br --chain --severity high,critical   # -> httpx -> nuclei
srecon crawl cortex.cloudwiser.com.br --dry-run
```

## Segurança de escopo — nunca testa host fora do alvo
A ferramenta **descobre** URLs/hosts de terceiros (JS de tráfego externo, redirects, subs),
mas **nunca manda tráfego ativo** para o que não está autorizado:
- `pipeline` (`--from-*`) passa tudo pelo `decide_scope`: o que está fora é **descartado**.
- `crawl` particiona os achados: só `all-urls-inscope.txt` alimenta o `--chain`/`--httpx`;
  hosts externos vão para `external-hosts.txt` marcado **"NÃO testar"** e ficam de fora.
- Arquivos de escopo entendem linhas de **negação/comentário** ("Fora de escopo: x", `#`, `//`):
  nada citado nelas é autorizado.

## crawl — incrementos sobre o katana-auto.sh original
- **scope-gating** (mesma Regra de ouro): crawl é ativo, recusa alvo fora de `scope/*.txt`.
- **diff entre runs**: symlink `latest` + `diff-new-*.txt` (URLs/params/subs/API/JS novos).
- **extração enriquecida**: `param-names.txt`, `api-endpoints.txt`, `forms.txt`,
  `secrets.txt` (regras AWS/GCP/JWT/private-key/etc; **0600**).
- **APIs escondidas**: mineração dos **bodies de JS** (que o katana salva) atrás de rotas
  embutidas (`fetch()`, `/api/v1/...`, URLs absolutas) → `js-endpoints.txt`.
- **params p/ fuzzing**: `params-all.txt` = união de params de URL + inputs de forms + JS.
- **encadeamento**: `--httpx` (probe -> `live.txt`) e `--chain` (httpx-toolkit -> nuclei),
  rodando **só** sobre `all-urls-inscope.txt` (hosts externos ficam em `external-hosts.txt`).

## Scope-gating
- Alvo precisa bater em algum `/root/audits/scope/*.txt` (domínio, wildcard `*.x` ou CIDR).
- `--scope-file caminho.txt` usa um arquivo específico.
- `--i-am-authorized` ignora o gate (registrado no relatório) — só com autorização escrita.
- Hosts fora de escopo vindos de `--from-search` são **descartados**, não escaneados.

## Saídas
- `reports/<slug>/<YYYYMMDDTHHMMSSZ>/` — `host.json`/`.md`, `search.json`/`.csv`,
  `pipeline.md` + saídas brutas dos estágios (`httpx.jsonl`, `nuclei.jsonl`, `testssl_*.json`).
- crawl: `reports/crawl-<host>/<stamp>/` com `output.jsonl`, `all-urls.txt`, `js.txt`,
  `param-names.txt`, `api-endpoints.txt`, `forms.txt`, `secrets.txt`, `subdomains.txt`,
  `diff-new-*.txt`, `crawl-report.md`, `run-meta.{txt,json}` (0600) + symlink `latest`.

## Config
- API key: `SHODAN_API_KEY` (env) > `~/.config/srecon/config.toml` > `~/.shodan/api_key`.
- Workspace: `SRECON_WORKSPACE` (default `/root/audits`).
