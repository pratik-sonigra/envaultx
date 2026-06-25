import json
import pytest
from click.testing import CliRunner
from envault.cli import cli


@pytest.fixture
def runner():
    return CliRunner()


# --- scan ---

def test_scan_clean_text(runner):
    result = runner.invoke(cli, ["scan", "Hello, this is a normal sentence."])
    assert result.exit_code == 0
    assert "clean" in result.output


def test_scan_with_secret(runner):
    result = runner.invoke(cli, ["scan", "key: sk-abcdefghijklmnopqrstuvwxyz1234567890"])
    assert result.exit_code == 1
    assert "high" in result.output


def test_scan_json_format(runner):
    result = runner.invoke(cli, ["scan", "--format", "json", "key: sk-abcdefghijklmnopqrstuvwxyz1234567890"])
    assert result.exit_code == 1
    data = json.loads(result.output)
    assert data["has_secrets"] is True
    assert data["risk_level"] == "high"


def test_scan_markdown_format(runner):
    result = runner.invoke(cli, ["scan", "--format", "markdown", "key: sk-abcdefghijklmnopqrstuvwxyz1234567890"])
    assert result.exit_code == 1
    assert "## Scan Results" in result.output


def test_scan_from_file(runner, tmp_path):
    f = tmp_path / "test.txt"
    f.write_text("sk-abcdefghijklmnopqrstuvwxyz1234567890")
    result = runner.invoke(cli, ["scan", "--file", str(f)])
    assert result.exit_code == 1


# --- redact ---

def test_redact_removes_secret(runner):
    result = runner.invoke(cli, ["redact", "key: sk-abcdefghijklmnopqrstuvwxyz1234567890"])
    assert result.exit_code == 0
    assert "sk-abcdefghijklmnopqrstuvwxyz1234567890" not in result.output
    assert "[OPENAI_KEY_1]" in result.output


def test_redact_sanitize_flag(runner):
    result = runner.invoke(cli, ["redact", "--sanitize", "key: sk-abcdefghijklmnopqrstuvwxyz1234567890"])
    assert result.exit_code == 0
    assert "[REDACTED]" in result.output


def test_redact_to_output_file(runner, tmp_path):
    out_file = tmp_path / "redacted.txt"
    result = runner.invoke(cli, [
        "redact", "key: sk-abcdefghijklmnopqrstuvwxyz1234567890",
        "--output", str(out_file),
    ])
    assert result.exit_code == 0
    content = out_file.read_text()
    assert "sk-abcdefghijklmnopqrstuvwxyz1234567890" not in content


def test_redact_vault_out(runner, tmp_path):
    vault_file = tmp_path / "vault.json"
    result = runner.invoke(cli, [
        "redact", "key: sk-abcdefghijklmnopqrstuvwxyz1234567890",
        "--vault-out", str(vault_file),
    ])
    assert result.exit_code == 0
    vault_data = json.loads(vault_file.read_text())
    assert len(vault_data) > 0


# --- restore ---

def test_restore_roundtrip(runner, tmp_path):
    vault_file = tmp_path / "vault.json"
    original = "key: sk-abcdefghijklmnopqrstuvwxyz1234567890"

    # Redact first
    runner.invoke(cli, [
        "redact", original,
        "--vault-out", str(vault_file),
        "--output", str(tmp_path / "redacted.txt"),
    ])

    redacted_text = (tmp_path / "redacted.txt").read_text()

    # Restore
    result = runner.invoke(cli, [
        "restore", redacted_text,
        "--vault", str(vault_file),
    ])
    assert result.exit_code == 0
    assert "sk-abcdefghijklmnopqrstuvwxyz1234567890" in result.output


# --- patterns ---

def test_patterns_list(runner):
    result = runner.invoke(cli, ["patterns"])
    assert result.exit_code == 0
    assert "OPENAI_KEY" in result.output
    assert "EMAIL" in result.output


def test_patterns_json(runner):
    result = runner.invoke(cli, ["patterns", "--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert isinstance(data, list)
    assert len(data) > 0
    assert "category" in data[0]


def test_patterns_filter_category(runner):
    result = runner.invoke(cli, ["patterns", "--category", "EMAIL"])
    assert result.exit_code == 0
    assert "EMAIL" in result.output
    assert "OPENAI_KEY" not in result.output
