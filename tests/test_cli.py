from click.testing import CliRunner

import cli as cli_module
from refactor import formatter


def test_check_passes_no_colour_to_formatter(monkeypatch, tmp_path):
    source = tmp_path / "sample.c"
    source.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")

    seen = {}

    def fake_configure_output(no_colour: bool = False):
        seen["no_colour"] = no_colour

    monkeypatch.setattr(formatter, "configure_output", fake_configure_output)
    monkeypatch.setattr(cli_module, "_run_detectors", lambda parsed, registry: [])

    runner = CliRunner()
    result = runner.invoke(cli_module.cli, ["check", "--no-colour", str(source)])

    assert result.exit_code == 0
    assert seen["no_colour"] is True