from srecon import util


def test_slugify_anti_traversal():
    s = util.slugify("../../etc/passwd")
    assert ".." not in s and "/" not in s
    assert util.slugify("a/b c") == "a-b-c"
    assert util.slugify("") == "target"
    assert util.slugify("...") == "target"       # vira '-' e é limpo


def test_output_dir_no_overwrite(tmp_path, monkeypatch):
    # dois runs no MESMO segundo não podem colidir/sobrescrever
    monkeypatch.setattr(util, "utc_stamp", lambda: "20260101T000000Z")
    d1 = util.output_dir(tmp_path, "host-x")
    d2 = util.output_dir(tmp_path, "host-x")
    assert d1 != d2
    assert d1.is_dir() and d2.is_dir()
    assert d2.name == "20260101T000000Z-2"
