#!/usr/bin/env bash
#
# field-test.sh — teste de campo da srecon contra o alvo PÚBLICO e SANCIONADO
# da Acunetix (família vulnweb).  Ref: http://www.vulnweb.com/
#
# Exercita: guardrail de escopo, recon passivo, crawl ativo AUTORIZADO e o
# encadeamento recon -> exploit. Só aponte para alvos que você tem autorização
# de testar — a Regra de ouro (scope-gating) existe justamente por isso.
set -euo pipefail

TARGET="testaspnet.vulnweb.com"
OUT_OF_SCOPE="example.com"        # exemplo de alvo NÃO autorizado (deve ser recusado)

# 0) Registrar a autorização no escopo (scan ativo exige scope/*.txt)
cat > /root/audits/scope/vulnweb.txt <<'SCOPE'
# Acunetix "vulnweb" — alvos publicamente liberados para testar scanners.
# Ref: http://www.vulnweb.com/
vulnweb.com
*.vulnweb.com
SCOPE

echo "########## 1) GUARDRAIL — recusa o que está fora de escopo (sem tocar no alvo) ##########"
srecon scope-check "$TARGET"                    # AUTORIZADO (após o passo 0)
srecon scope-check "$OUT_OF_SCOPE" || true      # FORA DE ESCOPO (exit 3)
srecon crawl "$OUT_OF_SCOPE" || true            # RECUSA antes de qualquer request

echo "########## 2) RECON PASSIVO (lê Shodan/OSINT — não toca no alvo) ##########"
srecon host "$TARGET"                           # portas/serviços/CVEs via Shodan
srecon subs vulnweb.com --fast                  # subfinder -> dnsx, anota escopo
# exemplo de hunt de origem atrás de CDN (barato, --count):
# srecon search 'ssl.cert.subject.CN:"exemplo.com"' --count

echo "########## 3) CRAWL ATIVO (autorizado via escopo) ##########"
# JS mining (APIs escondidas), params p/ fuzz, forms, e BLINDAGEM: hosts externos
# descobertos vão p/ external-hosts.txt e NUNCA são testados.
srecon crawl "$TARGET" -d 2 --duration 2m

echo "########## 4) RECON -> EXPLOIT (offline — não toca no alvo) ##########"
HOSTJSON=$(ls -t /root/audits/reports/"$TARGET"/*/host.json | head -1)
srecon msf --report "$HOSTJSON"                 # produto/CVE -> módulos Metasploit
srecon vulns --msf                              # rollup cross-host + módulos

echo "OK — teste de campo concluído."
