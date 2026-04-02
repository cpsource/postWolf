"""
Renewal configuration for MTC certificates.

Reads settings from a renew.conf INI-style file. Defaults are sensible
for a single-host deployment where ~/.TPM holds the local certificates
and the MTC CA server handles issuance.
"""

import configparser
import os
from pathlib import Path

DEFAULT_CONF = Path(__file__).parent / "renew.conf"


class RenewConfig:
    """Parsed renewal configuration."""

    def __init__(self, path: str | Path | None = None):
        self._cp = configparser.ConfigParser()
        # Defaults
        self._cp.read_dict({
            "renewal": {
                "server": "http://localhost:8443",
                "tpm_dir": str(Path.home() / ".TPM"),
                "renew_days_before": "30",
                "validity_days": "90",
                "rotate_keys": "false",
                "key_algorithm": "EC-P256",
                "dry_run": "false",
            },
            "neon": {
                "enabled": "false",
                "env_file": str(Path.home() / ".env"),
                "env_var": "MERKLE_NEON",
            },
            "hooks": {
                "pre_renew": "",
                "post_renew": "",
                "on_error": "",
            },
            "logging": {
                "level": "INFO",
                "file": "",
            },
        })

        if path and Path(path).exists():
            self._cp.read(path)
        elif DEFAULT_CONF.exists():
            self._cp.read(DEFAULT_CONF)

    # --- renewal section ---

    @property
    def server(self) -> str:
        return self._cp.get("renewal", "server")

    @property
    def tpm_dir(self) -> Path:
        return Path(self._cp.get("renewal", "tpm_dir")).expanduser()

    @property
    def renew_days_before(self) -> int:
        return self._cp.getint("renewal", "renew_days_before")

    @property
    def validity_days(self) -> int:
        return self._cp.getint("renewal", "validity_days")

    @property
    def rotate_keys(self) -> bool:
        return self._cp.getboolean("renewal", "rotate_keys")

    @property
    def key_algorithm(self) -> str:
        return self._cp.get("renewal", "key_algorithm")

    @property
    def dry_run(self) -> bool:
        return self._cp.getboolean("renewal", "dry_run")

    # --- neon section ---

    @property
    def neon_enabled(self) -> bool:
        return self._cp.getboolean("neon", "enabled")

    @property
    def neon_connection_string(self) -> str | None:
        """Load MERKLE_NEON from env or env_file."""
        var = self._cp.get("neon", "env_var")
        val = os.getenv(var)
        if val:
            return val

        env_file = Path(self._cp.get("neon", "env_file")).expanduser()
        if not env_file.exists():
            return None

        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if line.startswith(f"{var}="):
                    return line.split("=", 1)[1].strip('"').strip("'")
        return None

    # --- hooks ---

    @property
    def pre_renew_hook(self) -> str:
        return self._cp.get("hooks", "pre_renew").strip()

    @property
    def post_renew_hook(self) -> str:
        return self._cp.get("hooks", "post_renew").strip()

    @property
    def on_error_hook(self) -> str:
        return self._cp.get("hooks", "on_error").strip()

    # --- logging ---

    @property
    def log_level(self) -> str:
        return self._cp.get("logging", "level")

    @property
    def log_file(self) -> str:
        return self._cp.get("logging", "file").strip()
