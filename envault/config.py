from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from .exceptions import ConfigurationError

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore
    except ImportError:
        tomllib = None  # type: ignore


@dataclass
class EnvaultConfig:
    threshold: float = 0.5
    categories: list[str] = field(default_factory=list)
    exclude_categories: list[str] = field(default_factory=list)
    nlp: bool = False
    llm_assist: bool = False
    default_format: str = "text"
    vault_dir: str = ""

    @classmethod
    def load(cls) -> "EnvaultConfig":
        """Load config from file, then apply env var overrides."""
        raw: dict = {}

        # Determine config file path
        config_path: Path | None = None
        env_path = os.environ.get("ENVAULT_CONFIG")
        if env_path:
            config_path = Path(env_path)
        elif Path(".envault.toml").exists():
            config_path = Path(".envault.toml")
        else:
            user_config = Path.home() / ".config" / "envault" / "config.toml"
            if user_config.exists():
                config_path = user_config

        if config_path:
            if tomllib is None:
                raise ConfigurationError(
                    "TOML config support requires tomli on Python < 3.11: pip install tomli"
                )
            try:
                with open(config_path, "rb") as f:
                    raw = tomllib.load(f)
            except Exception as e:
                raise ConfigurationError(f"Failed to load config from {config_path}: {e}") from e

        cfg_section = raw.get("envault", raw)

        threshold = float(cfg_section.get("threshold", 0.5))
        categories = list(cfg_section.get("categories", []))
        exclude_categories = list(cfg_section.get("exclude_categories", []))
        nlp = bool(cfg_section.get("nlp", False))
        llm_assist = bool(cfg_section.get("llm_assist", False))
        default_format = str(cfg_section.get("default_format", "text"))
        vault_dir = str(cfg_section.get("vault_dir", ""))

        # Environment variable overrides
        if "ENVAULT_THRESHOLD" in os.environ:
            try:
                threshold = float(os.environ["ENVAULT_THRESHOLD"])
            except ValueError:
                raise ConfigurationError("ENVAULT_THRESHOLD must be a float")
        if "ENVAULT_NLP" in os.environ:
            nlp = os.environ["ENVAULT_NLP"].lower() in ("1", "true", "yes")
        if "ENVAULT_FORMAT" in os.environ:
            default_format = os.environ["ENVAULT_FORMAT"]
        if "ENVAULT_VAULT_DIR" in os.environ:
            vault_dir = os.environ["ENVAULT_VAULT_DIR"]

        return cls(
            threshold=threshold,
            categories=categories,
            exclude_categories=exclude_categories,
            nlp=nlp,
            llm_assist=llm_assist,
            default_format=default_format,
            vault_dir=vault_dir,
        )
