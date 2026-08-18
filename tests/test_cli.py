import sys
from types import ModuleType

from ballotproof.cli import run_cli
from ballotproof.source_worker import TransportRegistry, load_transport_spec


class SyntheticTransport:
    def send(self, request):
        raise AssertionError("synthetic transport should not be called by loader test")


def test_transport_spec_loads_zero_argument_factory(monkeypatch):
    module = ModuleType("ballotproof_test_transport")
    module.build = lambda: SyntheticTransport()
    monkeypatch.setitem(sys.modules, module.__name__, module)

    source_id, transport = load_transport_spec(
        "demo-source=ballotproof_test_transport:build"
    )

    assert source_id == "demo-source"
    assert isinstance(transport, SyntheticTransport)


def test_worker_status_returns_nonzero_before_any_worker_state(tmp_path, capsys):
    result = run_cli(["worker", "--data-dir", str(tmp_path), "--status"])

    assert result == 1
    assert '"healthy": false' in capsys.readouterr().out


def test_transport_registry_from_specs_rejects_duplicates(monkeypatch):
    module = ModuleType("ballotproof_duplicate_transport")
    module.build = lambda: SyntheticTransport()
    monkeypatch.setitem(sys.modules, module.__name__, module)
    spec = "demo-source=ballotproof_duplicate_transport:build"

    try:
        TransportRegistry.from_specs([spec, spec])
    except ValueError as exc:
        assert "already registered" in str(exc)
    else:
        raise AssertionError("duplicate transport specs were accepted")
