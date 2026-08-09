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
