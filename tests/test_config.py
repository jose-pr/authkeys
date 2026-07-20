"""Config loading: path lists, dicts, bytes, getlist, env interpolation."""

from authkeys import AuthkeysConfig


def test_getlist_splits_and_strips():
    conf = AuthkeysConfig.from_config({"s": {"v": "a\n  b \n\nc"}})
    assert conf.getlist("s", "v") == ["a", "b", "c"]


def test_from_config_dict():
    conf = AuthkeysConfig.from_config({"globals": {"usermap": "x"}})
    assert conf["globals"]["usermap"] == "x"


def test_from_config_bytes():
    conf = AuthkeysConfig.from_config(b"[globals]\nusermap = y\n")
    assert conf["globals"]["usermap"] == "y"


def test_from_config_path_and_colon_list(tmp_path):
    p = tmp_path / "a.conf"
    p.write_text("[globals]\nusermap = frompath\n")
    conf = AuthkeysConfig.from_config(f"/nope.conf:{p}")
    assert conf["globals"]["usermap"] == "frompath"


def test_from_config_first_existing_path_wins(tmp_path):
    a = tmp_path / "a.conf"
    b = tmp_path / "b.conf"
    a.write_text("[globals]\nk = a\n")
    b.write_text("[globals]\nk = b\n")
    conf = AuthkeysConfig.from_config([a, b])
    assert conf["globals"]["k"] == "a"


def test_env_interpolation(monkeypatch):
    monkeypatch.setenv("AUTHKEYS_TEST_SECRET", "s3cr3t")
    conf = AuthkeysConfig.from_config(b"[serve]\napi_key = ${env:AUTHKEYS_TEST_SECRET}\n")
    assert conf["serve"]["api_key"] == "s3cr3t"


def test_env_interpolation_missing_is_empty(monkeypatch):
    monkeypatch.delenv("AUTHKEYS_MISSING", raising=False)
    conf = AuthkeysConfig.from_config(b"[serve]\napi_key = ${env:AUTHKEYS_MISSING}\n")
    assert conf["serve"]["api_key"] == ""


def test_cache_and_globals_sections_always_present():
    conf = AuthkeysConfig.from_config()
    assert conf.has_section("cache")
    assert conf.has_section("globals")


# --- Windows drive-letter paths in --config (regression) -------------------


def test_windows_absolute_path_is_not_split_on_drive_colon(tmp_path):
    r"""A Windows absolute path must not be split into drive + remainder.

    ``--config C:\path\ak.conf`` previously became ``["C", "\path\ak.conf"]``, so
    the file was never read and the caller silently got an empty config (which,
    for ``serve``, skipped the fail-closed api_key check and hung).
    """
    p = tmp_path / "ak.conf"
    p.write_text("[serve]\napi_key = secret\n")
    conf = AuthkeysConfig.from_config(str(p))
    assert conf.has_section("serve")
    assert conf["serve"]["api_key"] == "secret"


def test_colon_separated_list_still_splits(tmp_path):
    a = tmp_path / "a.conf"
    b = tmp_path / "b.conf"
    b.write_text("[globals]\nk = from_b\n")
    # First path doesn't exist -> falls through to the second.
    conf = AuthkeysConfig.from_config(f"{a}:{b}")
    assert conf["globals"]["k"] == "from_b"
