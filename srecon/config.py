from __future__ import annotations

import os
import stat
from pathlib import Path

try:
    import tomllib  # py311+
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None

APP_NAME = "srecon"
DEFAULT_WORKSPACE = Path("/root/audits")
CONFIG_DIR = Path(os.environ.get("SRECON_CONFIG_DIR", str(Path.home() / ".config" / APP_NAME)))
CONFIG_FILE = CONFIG_DIR / "config.toml"
QUERIES_FILE = CONFIG_DIR / "queries.toml"


class ConfigError(Exception):
    pass


def workspace() -> Path:
    return Path(os.environ.get("SRECON_WORKSPACE", str(DEFAULT_WORKSPACE)))


def scope_dir() -> Path:
    return workspace() / "scope"


def loot_dir() -> Path:
    return workspace() / "loot"


def reports_dir() -> Path:
    return workspace() / "reports"


def _read_toml(path: Path) -> dict:
    if tomllib is None or not path.is_file():
        return {}
    try:
        with path.open("rb") as fh:
            return tomllib.load(fh)
    except (OSError, ValueError):
        return {}


def resolve_api_key() -> str:
    key = os.environ.get("SHODAN_API_KEY")
    if key and key.strip():
        return key.strip()
    data = _read_toml(CONFIG_FILE)
    if data.get("api_key"):
        return str(data["api_key"]).strip()
    for p in (Path.home() / ".shodan" / "api_key", Path.home() / ".config" / "shodan" / "api_key"):
        if p.is_file():
            v = p.read_text(errors="ignore").strip()
            if v:
                return v
    raise ConfigError(
        "Nenhuma API key do Shodan encontrada.\n"
        "  - defina:  export SHODAN_API_KEY=<sua_key>\n"
        "  - ou rode: srecon init"
    )


def _toml_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _has_control_chars(s: str) -> bool:
    return any(ord(c) < 0x20 for c in s)


def _ensure_config_dir() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(CONFIG_DIR, stat.S_IRWXU)  # 0700
    except OSError:
        pass


def _write_private(path: Path, content: str) -> None:
    """Cria o arquivo já com 0600 — sem a janela 0644 entre write e chmod."""
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, content.encode("utf-8"))
    finally:
        os.close(fd)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # garante 0600 mesmo se já existia


def save_api_key(key: str) -> Path:
    _ensure_config_dir()
    _write_private(CONFIG_FILE, f'api_key = "{_toml_escape(key.strip())}"\n')
    return CONFIG_FILE


def load_saved_queries() -> dict:
    return _read_toml(QUERIES_FILE)


def save_query(name: str, query: str) -> Path:
    if _has_control_chars(name) or _has_control_chars(query):
        raise ValueError("nome/query não podem conter quebras de linha ou caracteres de controle.")
    _ensure_config_dir()
    queries = load_saved_queries()
    queries[name] = query
    lines = [f'"{_toml_escape(k)}" = "{_toml_escape(v)}"' for k, v in queries.items()]
    _write_private(QUERIES_FILE, "\n".join(lines) + "\n")
    return QUERIES_FILE
