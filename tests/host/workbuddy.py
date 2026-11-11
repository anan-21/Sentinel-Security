"""Register Sentinel in a temporary WorkBuddy/CodeBuddy CLI project and check stdio."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cli", help="path to the WorkBuddy bundled codebuddy executable"
    )
    args = parser.parse_args()
    bundled = Path(
        "/Applications/WorkBuddy.app/Contents/Resources/app.asar.unpacked/cli/bin/codebuddy"
    )
    cli = args.cli or (str(bundled) if bundled.is_file() else shutil.which("codebuddy"))
    if not cli:
        parser.error("WorkBuddy bundled CLI unavailable; supply --cli")
    repo = Path(__file__).resolve().parents[2]
    with tempfile.TemporaryDirectory() as temp:
        project = Path(temp) / "project"
        project.mkdir()
        config = Path(temp) / "config"
        config.mkdir()
        environment = {
            **os.environ,
            "CODEBUDDY_CONFIG_DIR": str(config),
            "NO_COLOR": "1",
        }
        spec = {
            "type": "stdio",
            "command": sys.executable,
            "args": ["-m", "sentinel.cli", "mcp"],
            "env": {"PYTHONPATH": str(repo)},
        }

        def invoke(*args):
            return subprocess.run(
                [cli, "mcp", *args],
                cwd=project,
                env=environment,
                capture_output=True,
                text=True,
                timeout=45,
                check=True,
            )

        invoke("add-json", "--scope", "project", "sentinel-smoke", json.dumps(spec))
        result = invoke("get", "sentinel-smoke")
        # Restrict output to the single synthetic server. Do not print user config.
        if "Connected" not in result.stdout or "sentinel-smoke" not in result.stdout:
            raise RuntimeError("synthetic MCP server did not report Connected")
        print("WorkBuddy bundled CLI: synthetic project, Sentinel stdio Connected")


if __name__ == "__main__":
    main()
