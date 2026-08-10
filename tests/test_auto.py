from srecon.commands import auto

KNOWN = {"host", "crawl", "auto", "scope-check", "subs", "pipeline"}


def test_route_argv_bare_target_gets_auto():
    assert auto.route_argv(["example.com"], KNOWN) == ["auto", "example.com"]
    assert auto.route_argv(["example.com", "--dry-run"], KNOWN) == ["auto", "example.com", "--dry-run"]
    assert auto.route_argv(["1.2.3.4", "--passive-only"], KNOWN) == ["auto", "1.2.3.4", "--passive-only"]


def test_route_argv_known_command_untouched():
    assert auto.route_argv(["host", "1.2.3.4"], KNOWN) == ["host", "1.2.3.4"]
    assert auto.route_argv(["scope-check", "x"], KNOWN) == ["scope-check", "x"]
    assert auto.route_argv(["crawl", "x", "--chain"], KNOWN) == ["crawl", "x", "--chain"]
    # 'auto' explícito não é duplicado
    assert auto.route_argv(["auto", "x"], KNOWN) == ["auto", "x"]


def test_route_argv_flags_only_or_empty_untouched():
    assert auto.route_argv([], KNOWN) == []
    assert auto.route_argv(["--help"], KNOWN) == ["--help"]
    assert auto.route_argv(["--version"], KNOWN) == ["--version"]
    assert auto.route_argv(["-V"], KNOWN) == ["-V"]


def test_looks_like_ip():
    assert auto.looks_like_ip("1.2.3.4")
    assert auto.looks_like_ip("2001:db8::1")
    assert not auto.looks_like_ip("example.com")
    assert not auto.looks_like_ip("app.example.com")
    assert not auto.looks_like_ip("")


def test_auto_dry_run_out_of_scope_skips_active(tmp_path, monkeypatch):
    # workspace vazio -> nenhum scope -> alvo fora de escopo -> ativo NÃO entra no plano
    monkeypatch.setenv("SRECON_WORKSPACE", str(tmp_path))
    (tmp_path / "scope").mkdir()
    from typer.testing import CliRunner
    from srecon.cli import app

    result = CliRunner().invoke(app, ["auto", "fora.invalid", "--dry-run"])
    assert result.exit_code == 0
    assert "plano:" in result.output
    assert "dry-run" in result.output
    assert "crawl (ATIVO)" not in result.output      # fora de escopo -> sem ativo


def _dry(tmp_path, monkeypatch, target, scope_text=None):
    monkeypatch.setenv("SRECON_WORKSPACE", str(tmp_path))
    scope_dir = tmp_path / "scope"
    scope_dir.mkdir(exist_ok=True)
    if scope_text:
        (scope_dir / "s.txt").write_text(scope_text)
    from typer.testing import CliRunner
    from srecon.cli import app
    return CliRunner().invoke(app, ["auto", target, "--dry-run"])


def test_auto_plan_includes_new_passive_and_triage_stages(tmp_path, monkeypatch):
    # domínio fora de escopo: urls/assets/candidates(passivo)/triage no plano; ativo não
    out = _dry(tmp_path, monkeypatch, "fora.invalid").output
    assert "urls históricas" in out
    assert "assets" in out
    assert "candidates" in out and "só classificação passiva" in out
    assert "triage" in out
    assert "crawl (ATIVO)" not in out


def test_auto_plan_candidates_active_when_in_scope(tmp_path, monkeypatch):
    out = _dry(tmp_path, monkeypatch, "app.autotest.com",
               scope_text="*.autotest.com").output
    assert "prova ATIVA" in out                      # em escopo -> candidates prova
    assert "crawl (ATIVO)" in out
    assert "triage" in out


def test_auto_plan_ip_skips_urls_and_candidates(tmp_path, monkeypatch):
    out = _dry(tmp_path, monkeypatch, "8.8.8.8").output
    assert "urls históricas" not in out              # wayback por IP não entra
    assert "candidates" not in out                   # candidates depende de urls
    assert "assets" in out                            # ASN/netblock ainda vale p/ IP
    assert "triage" in out
