"""Env-var validation for `python -m netscope` (#38).

A typo'd NETSCOPE_PORT / NETSCOPE_NMAP_TIMEOUT used to die with a bare
ValueError traceback from inside main(). These tests must not start a
server: uvicorn.run is monkeypatched, and the parsing helpers are pure.
"""

import pytest

import netscope.__main__ as main_module
from netscope import vendor_registry


@pytest.fixture(autouse=True)
def no_real_nmap_install(monkeypatch):
    """`main()` reads nmap's data file at startup. On a machine where nmap IS
    installed that pulls 52k real registrations into a process-wide table,
    which then leaks into later test modules (it broke
    `test_vendor_registry.py` on a Windows box with nmap in `PATH`). Pin the
    search to nothing so startup tests are deterministic everywhere."""
    monkeypatch.delenv("NMAPDIR", raising=False)
    monkeypatch.setattr(vendor_registry.shutil, "which", lambda name: None)


def test_parse_port_accepts_valid_values():
    assert main_module.parse_port("8000") == 8000
    assert main_module.parse_port("1") == 1
    assert main_module.parse_port("65535") == 65535


def test_parse_port_rejects_non_integer_with_the_var_name():
    with pytest.raises(ValueError) as exc:
        main_module.parse_port("8000abc")
    assert "NETSCOPE_PORT" in str(exc.value)
    assert "8000abc" in str(exc.value)


def test_parse_port_rejects_out_of_range():
    for bad in ("0", "-1", "65536", "99999"):
        with pytest.raises(ValueError) as exc:
            main_module.parse_port(bad)
        assert "NETSCOPE_PORT" in str(exc.value), bad


def test_parse_timeout_accepts_valid_values():
    assert main_module.parse_timeout("300") == 300.0
    assert main_module.parse_timeout("0.5") == 0.5


def test_parse_timeout_rejects_non_numeric_with_the_var_name():
    with pytest.raises(ValueError) as exc:
        main_module.parse_timeout("five")
    assert "NETSCOPE_NMAP_TIMEOUT" in str(exc.value)
    assert "five" in str(exc.value)


def test_parse_timeout_rejects_non_positive_and_non_finite():
    # 0 / negative would kill nmap instantly; nan/inf would never kill it.
    for bad in ("0", "-5", "nan", "inf", "-inf"):
        with pytest.raises(ValueError) as exc:
            main_module.parse_timeout(bad)
        assert "NETSCOPE_NMAP_TIMEOUT" in str(exc.value), bad


def test_main_exits_with_actionable_message_instead_of_traceback(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NETSCOPE_PORT", "8000abc")
    monkeypatch.setattr(main_module.uvicorn, "run", lambda *a, **k: None)
    with pytest.raises(SystemExit) as exc:
        main_module.main()
    message = str(exc.value)
    assert "NETSCOPE_PORT" in message, message
    assert "8000abc" in message, message


def test_main_rejects_bad_timeout(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NETSCOPE_NMAP_TIMEOUT", "0")
    monkeypatch.setattr(main_module.uvicorn, "run", lambda *a, **k: None)
    with pytest.raises(SystemExit) as exc:
        main_module.main()
    assert "NETSCOPE_NMAP_TIMEOUT" in str(exc.value)


def test_bad_config_never_creates_a_database(monkeypatch, tmp_path):
    """The timeout used to be parsed *after* `SQLiteStore()`, so a bad
    `NETSCOPE_NMAP_TIMEOUT=abc` crashed with a traceback and left a
    freshly created 49 KB `netscope.db` behind in the current directory."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("NETSCOPE_DB", raising=False)
    monkeypatch.setenv("NETSCOPE_NMAP_TIMEOUT", "abc")
    monkeypatch.setattr(main_module.uvicorn, "run", lambda *a, **k: None)
    created: list[str] = []
    monkeypatch.setattr(
        main_module, "SQLiteStore", lambda *a, **k: created.append("store")
    )
    with pytest.raises(SystemExit):
        main_module.main()
    assert created == [], "store must not be constructed when config is invalid"
    assert not (tmp_path / "netscope.db").exists()


def test_main_starts_normally_with_valid_env(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NETSCOPE_PORT", "8123")
    monkeypatch.setenv("NETSCOPE_NMAP_TIMEOUT", "12.5")
    monkeypatch.setenv("NETSCOPE_DB", str(tmp_path / "ok.db"))
    started: dict[str, object] = {}
    monkeypatch.setattr(
        main_module.uvicorn, "run", lambda app, **kw: started.update(kw)
    )
    main_module.main()
    assert started["port"] == 8123
    assert (tmp_path / "ok.db").exists()


# --- #security: "*" must not switch the Host check off ---------------------


def test_main_refuses_wildcard_allowed_hosts(monkeypatch, tmp_path):
    """Starlette reads "*" as allow-every-host, which silently disables the
    DNS-rebinding defence — and only the error message suggests trying it."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("NETSCOPE_DB", raising=False)
    monkeypatch.setenv("NETSCOPE_ALLOWED_HOSTS", "192.168.0.14, *")
    monkeypatch.setattr(main_module.uvicorn, "run", lambda *a, **k: None)
    created: list[str] = []
    monkeypatch.setattr(
        main_module, "SQLiteStore", lambda *a, **k: created.append("store")
    )
    with pytest.raises(SystemExit) as exc:
        main_module.main()
    assert "NETSCOPE_ALLOWED_HOSTS" in str(exc.value)
    assert "disables the Host" in str(exc.value)
    assert created == [], "config must be rejected before the store exists"


def test_main_accepts_explicit_allowed_hosts(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NETSCOPE_DB", str(tmp_path / "hosts.db"))
    monkeypatch.setenv("NETSCOPE_ALLOWED_HOSTS", "192.168.0.14, atom.local")
    started: dict[str, object] = {}
    monkeypatch.setattr(
        main_module.uvicorn, "run", lambda app, **kw: started.update(kw)
    )
    main_module.main()
    assert started["port"] == 8000


def test_main_rejects_bad_max_addresses(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("NETSCOPE_DB", raising=False)
    monkeypatch.setenv("NETSCOPE_MAX_TARGET_ADDRESSES", "lots")
    monkeypatch.setattr(main_module.uvicorn, "run", lambda *a, **k: None)
    with pytest.raises(SystemExit) as exc:
        main_module.main()
    assert "NETSCOPE_MAX_TARGET_ADDRESSES" in str(exc.value)
