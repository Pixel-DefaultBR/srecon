"""Descoberta de conteúdo (diretórios/arquivos) com ffuf — funções puras/testáveis.

O ffuf faz o brute-force ATIVO; aqui só montamos o comando, resolvemos wordlist e
parseamos o JSON. A lista curada de "arquivos interessantes" é embutida (não depende
de seclists estar instalado).
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

# wordlists de diretórios, em ordem de preferência (Kali/seclists/dirb)
_WORDLIST_CANDIDATES = [
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
]

# lista curada de arquivos/paths de alto valor — independe de seclists
INTERESTING_FILES = [
    # VCS / metadados
    ".git/HEAD", ".git/config", ".gitignore", ".svn/entries", ".hg/store", ".bzr/README",
    # segredos / ambiente
    ".env", ".env.local", ".env.dev", ".env.prod", ".env.backup",
    ".aws/credentials", ".ssh/id_rsa", ".npmrc", ".dockercfg", ".docker/config.json",
    ".htpasswd", ".htaccess", ".bash_history",
    # config de app
    "web.config", "appsettings.json", "config.php", "wp-config.php", "wp-config.php.bak",
    "settings.py", "application.properties", "config.json", "config.yml", "config.yaml",
    "credentials.json", "secrets.json",
    # info / status / debug
    "phpinfo.php", "info.php", "test.php", "server-status", "server-info",
    "actuator", "actuator/env", "actuator/health", "actuator/heapdump",
    # APIs / docs
    "swagger.json", "swagger-ui.html", "openapi.json", "api-docs", "v2/api-docs",
    "graphql", "graphiql", ".well-known/security.txt",
    # painéis
    "adminer.php", "phpmyadmin/", "admin/", "administrator/", "manager/html",
    # backups / dumps
    "backup.zip", "backup.tar.gz", "backup.sql", "db.sql", "database.sql", "dump.sql",
    "www.zip", "site.zip", "web.zip", "app.zip", "release.zip", "backup/",
    # chaves / logs
    "id_rsa", "id_dsa", "error_log", "access.log", "debug.log",
    # descoberta clássica
    "robots.txt", "sitemap.xml", ".DS_Store",
]


def default_wordlist() -> Optional[str]:
    env = os.environ.get("SRECON_WORDLIST")
    if env and Path(env).is_file():
        return env
    for w in _WORDLIST_CANDIDATES:
        if Path(w).is_file():
            return w
    return None


def write_wordlist(items, path: Path) -> Path:
    path.write_text("\n".join(items) + "\n", encoding="utf-8")
    return path


def build_ffuf_cmd(ffuf_bin: str, base_url: str, wordlist: str, out_json: Path,
                   match_codes: str = "200,204,301,302,307,401,403,405,500",
                   extensions: str = "", threads: int = 40, rate: int = 0,
                   timeout_req: int = 10) -> list:
    url = base_url.rstrip("/") + "/FUZZ"
    cmd = [
        ffuf_bin, "-u", url, "-w", f"{wordlist}:FUZZ",
        "-mc", match_codes, "-of", "json", "-o", str(out_json),
        "-t", str(threads), "-timeout", str(timeout_req),
        "-ac",              # auto-calibra p/ cortar falso-positivo (wildcard/soft-404)
        "-s",               # silencioso
    ]
    if rate and rate > 0:
        cmd += ["-rate", str(rate)]
    if extensions:
        cmd += ["-e", extensions]
    return cmd


def parse_ffuf_json(path: Path) -> list:
    """Achados do ffuf: [{url,status,length,words,lines,input}] ordenados por status,url."""
    if not Path(path).is_file():
        return []
    try:
        data = json.loads(Path(path).read_text(errors="ignore"))
    except (OSError, ValueError):
        return []
    out: list = []
    for r in (data.get("results") or []):
        inp = r.get("input") or {}
        out.append({
            "url": r.get("url"),
            "status": r.get("status"),
            "length": r.get("length"),
            "words": r.get("words"),
            "lines": r.get("lines"),
            "input": inp.get("FUZZ") if isinstance(inp, dict) else None,
        })
    out.sort(key=lambda h: (h.get("status") or 0, h.get("url") or ""))
    return out
