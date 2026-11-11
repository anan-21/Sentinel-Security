from pathlib import Path
import sys
import subprocess
import tempfile
import shutil

repo = Path.cwd()
with tempfile.TemporaryDirectory() as folder:
    t = Path(folder)
    reg = next(
        d / "node_modules"
        for d in Path(shutil.which("dsh")).resolve().parents
        if (d / "node_modules/@deepseek-ai/dsh-tools/package.json").exists()
    )
    (t / "node_modules").symlink_to(reg, target_is_directory=True)
    subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel.cli",
            "install",
            "dsh",
            "--skills-root",
            str(t / "skills"),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    shutil.copy(repo / "tests/host/dsh.mjs", t / "dsh.mjs")
    shutil.copy(repo / "integrations/dsh/inventory/index.mjs", t / "inventory.mjs")
    sys.exit(subprocess.run(["node", "dsh.mjs"], cwd=t).returncode)
