#!/usr/bin/env python3
"""Check the production Compose DSN override contract without starting containers."""

import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    repo = Path(__file__).resolve().parent.parent
    key = "TRANSPONDER_GLITCHTIP_DSN"
    environment = os.environ.copy()
    environment.pop(key, None)

    with tempfile.TemporaryDirectory() as directory:
        env_file = Path(directory) / "test.env"
        for source in ("host", "env_file"):
            for name, value in (
                ("absent", None),
                ("empty", ""),
                ("whitespace", "   "),
                ("nonempty", "https://test-key@glitch.example/1"),
            ):
                case_environment = environment.copy()
                env_file.write_text("")
                if value is not None:
                    if source == "host":
                        case_environment[key] = value
                    else:
                        env_file.write_text(f"{key}='{value}'\n")

                result = subprocess.run(
                    [
                        "docker", "compose", "--env-file", str(env_file),
                        "-f", str(repo / "compose.prod.yml"),
                        "config", "--format", "json",
                    ],
                    cwd=repo,
                    env=case_environment,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if result.returncode:
                    raise SystemExit(f"Compose config failed for {source}/{name}")
                configured = json.loads(result.stdout)["services"]["transponder"][
                    "environment"
                ]
                # Compose may retain an unresolved pass-through entry as null;
                # that means the variable is unset in the container.
                if configured.get(key) != value:
                    raise SystemExit(f"DSN override contract failed for {source}/{name}")
                print(f"PASS {source}/{name}")


if __name__ == "__main__":
    main()
