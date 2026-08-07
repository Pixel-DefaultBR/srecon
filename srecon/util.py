from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path


def utc_stamp() -> str:
    """Timestamp UTC no formato da casa: YYYYMMDDTHHMMSSZ."""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def slugify(s: str, max_len: int = 100) -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"[^a-z0-9._-]+", "-", s)
    s = re.sub(r"\.{2,}", "-", s)          # nunca deixar '..' -> evita subir de diretório
    s = s.strip("-.")[:max_len].strip("-.")  # teto p/ limite de 255 bytes por componente
    return s or "target"


def output_dir(base: Path, target: str) -> Path:
    """Cria e retorna base/<slug>/<UTCstamp>/ (convenção reports/ da casa).
    Desambigua colisão no mesmo segundo (senão o 2º run sobrescreveria o 1º)."""
    parent = base / slugify(target)
    stamp = utc_stamp()
    d = parent / stamp
    for i in range(2, 1000):
        try:
            d.mkdir(parents=True, exist_ok=False)
            return d
        except FileExistsError:
            d = parent / f"{stamp}-{i}"
    d.mkdir(parents=True, exist_ok=True)   # fallback improvável
    return d
