from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from .envault import Envault
from .vault import Vault
from .config import EnvaultConfig
from .patterns import PATTERNS
from .exceptions import EnvaultError, ConfigurationError


def _load_text(text: str | None, file: str | None, stdin: bool) -> str:
    """Read text from argument, file, or stdin."""
    sources = sum([text is not None, file is not None, stdin])
    if sources > 1:
        raise click.UsageError("Provide only one of TEXT, --file, or --stdin")
    if text is not None:
        return text
    if file is not None:
        try:
            return Path(file).read_text(encoding="utf-8")
        except OSError as e:
            raise click.ClickException(f"Cannot read file: {e}") from e
    if stdin or not sys.stdin.isatty():
        return sys.stdin.read()
    raise click.UsageError("Provide TEXT argument, --file, or --stdin")


def _format_scan_result(result, fmt: str, text: str) -> str:
    from .scanner import ScanResult
    if fmt == "json":
        data = {
            "has_secrets": result.has_secrets,
            "risk_level": result.risk_level,
            "summary": result.summary,
            "detections": [
                {
                    "category": d.category,
                    "confidence": d.confidence,
                    "span": list(d.span),
                    "original": d.original,
                }
                for d in result.detections
            ],
        }
        return json.dumps(data, indent=2)
    if fmt == "markdown":
        lines = [
            f"## Scan Results",
            f"",
            f"**Risk Level:** {result.risk_level}",
            f"**Secrets Found:** {result.has_secrets}",
            f"",
        ]
        if result.summary:
            lines.append("### Categories")
            for cat, count in result.summary.items():
                lines.append(f"- {cat}: {count}")
        if result.detections:
            lines.append("")
            lines.append("### Detections")
            for d in result.detections:
                lines.append(f"- `{d.category}` (confidence: {d.confidence:.2f}) at chars {d.span[0]}-{d.span[1]}")
        return "\n".join(lines)
    # text format
    lines = [
        f"Risk level: {result.risk_level}",
        f"Secrets found: {result.has_secrets}",
    ]
    for cat, count in result.summary.items():
        lines.append(f"  {cat}: {count}")
    return "\n".join(lines)


@click.group()
def cli() -> None:
    """envault — What your LLM sees, stays safe."""


@cli.command()
@click.argument("text", required=False)
@click.option("--file", "-f", "file", type=click.Path(), default=None)
@click.option("--stdin", "use_stdin", is_flag=True)
@click.option("--threshold", type=float, default=None)
@click.option("--format", "fmt", type=click.Choice(["text", "json", "markdown"]), default=None)
@click.option("--nlp", is_flag=True, default=False)
def scan(text: str | None, file: str | None, use_stdin: bool, threshold: float | None, fmt: str | None, nlp: bool) -> None:
    """Scan text for secrets and PII."""
    try:
        cfg = EnvaultConfig.load()
    except ConfigurationError as e:
        click.echo(f"Config error: {e}", err=True)
        sys.exit(3)

    effective_threshold = threshold if threshold is not None else cfg.threshold
    effective_fmt = fmt if fmt is not None else cfg.default_format

    try:
        content = _load_text(text, file, use_stdin)
    except click.UsageError as e:
        click.echo(str(e), err=True)
        sys.exit(4)
    except click.ClickException as e:
        click.echo(str(e), err=True)
        sys.exit(2)

    try:
        ev = Envault(threshold=effective_threshold, nlp=nlp)
        result = ev.scan(content)
    except EnvaultError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    click.echo(_format_scan_result(result, effective_fmt, content))
    sys.exit(1 if result.has_secrets else 0)


@cli.command()
@click.argument("text", required=False)
@click.option("--file", "-f", "file", type=click.Path(), default=None)
@click.option("--stdin", "use_stdin", is_flag=True)
@click.option("--threshold", type=float, default=None)
@click.option("--format", "fmt", type=click.Choice(["text", "json", "markdown"]), default=None)
@click.option("--output", "-o", type=click.Path(), default=None, help="Write redacted text to file")
@click.option("--vault-out", type=click.Path(), default=None, help="Write vault JSON to file")
@click.option("--vault-password", default=None, help="Encrypt vault with password")
@click.option("--sanitize", is_flag=True, default=False, help="Use fixed [REDACTED] placeholder")
@click.option("--nlp", is_flag=True, default=False)
def redact(
    text: str | None,
    file: str | None,
    use_stdin: bool,
    threshold: float | None,
    fmt: str | None,
    output: str | None,
    vault_out: str | None,
    vault_password: str | None,
    sanitize: bool,
    nlp: bool,
) -> None:
    """Redact secrets from text."""
    try:
        cfg = EnvaultConfig.load()
    except ConfigurationError as e:
        click.echo(f"Config error: {e}", err=True)
        sys.exit(3)

    effective_threshold = threshold if threshold is not None else cfg.threshold

    try:
        content = _load_text(text, file, use_stdin)
    except click.UsageError as e:
        click.echo(str(e), err=True)
        sys.exit(4)
    except click.ClickException as e:
        click.echo(str(e), err=True)
        sys.exit(2)

    try:
        ev = Envault(threshold=effective_threshold, nlp=nlp)
        if sanitize:
            redacted_text = ev.sanitize(content, threshold=effective_threshold)
            vault_obj = None
        else:
            redacted_text, vault_obj = ev.redact(content, threshold=effective_threshold)
    except EnvaultError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    if output:
        try:
            Path(output).write_text(redacted_text, encoding="utf-8")
        except OSError as e:
            click.echo(f"Cannot write output: {e}", err=True)
            sys.exit(2)
    else:
        click.echo(redacted_text)

    if vault_out and vault_obj is not None:
        try:
            if vault_password:
                vault_bytes = vault_obj.to_encrypted_bytes(vault_password)
                Path(vault_out).write_bytes(vault_bytes)
            else:
                Path(vault_out).write_text(
                    json.dumps(vault_obj.to_dict(), indent=2), encoding="utf-8"
                )
        except OSError as e:
            click.echo(f"Cannot write vault: {e}", err=True)
            sys.exit(2)


@cli.command()
@click.argument("text", required=False)
@click.option("--file", "-f", "file", type=click.Path(), default=None)
@click.option("--stdin", "use_stdin", is_flag=True)
@click.option("--vault", "vault_path", required=True, type=click.Path(), help="Path to vault file")
@click.option("--vault-password", default=None)
@click.option("--output", "-o", type=click.Path(), default=None)
def restore(
    text: str | None,
    file: str | None,
    use_stdin: bool,
    vault_path: str,
    vault_password: str | None,
    output: str | None,
) -> None:
    """Restore redacted text using a vault."""
    try:
        content = _load_text(text, file, use_stdin)
    except click.UsageError as e:
        click.echo(str(e), err=True)
        sys.exit(4)
    except click.ClickException as e:
        click.echo(str(e), err=True)
        sys.exit(2)

    try:
        vpath = Path(vault_path)
        if vault_password:
            vault_bytes = vpath.read_bytes()
            vault_obj = Vault.from_encrypted_bytes(vault_bytes, vault_password)
        else:
            vault_data = json.loads(vpath.read_text(encoding="utf-8"))
            vault_obj = Vault()
            for ph, orig in vault_data.items():
                vault_obj._placeholder_to_original[ph] = orig
                vault_obj._original_to_placeholder[orig] = ph
    except Exception as e:
        click.echo(f"Failed to load vault: {e}", err=True)
        sys.exit(2)

    ev = Envault()
    restored = ev.restore(content, vault_obj)

    if output:
        try:
            Path(output).write_text(restored, encoding="utf-8")
        except OSError as e:
            click.echo(f"Cannot write output: {e}", err=True)
            sys.exit(2)
    else:
        click.echo(restored)


@cli.command()
@click.option("--category", default=None, help="Filter by category name")
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text")
def patterns(category: str | None, fmt: str) -> None:
    """List all supported detection patterns."""
    pats = PATTERNS
    if category:
        pats = [p for p in pats if p["category"].lower() == category.lower()]

    if fmt == "json":
        data = [
            {"category": p["category"], "confidence": p["confidence"]}
            for p in pats
        ]
        click.echo(json.dumps(data, indent=2))
    else:
        for p in pats:
            click.echo(f"{p['category']:<30} confidence={p['confidence']}")


@cli.command()
@click.option("--transport", type=click.Choice(["stdio", "sse"]), default="stdio")
@click.option("--port", type=int, default=8000)
def mcp(transport: str, port: int) -> None:
    """Start the envault MCP server."""
    from .mcp_server import mcp as _mcp
    if transport == "sse":
        _mcp.run(transport="sse", port=port)
    else:
        _mcp.run(transport="stdio")
