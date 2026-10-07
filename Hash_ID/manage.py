"""Atalhos portáveis com dependências locais, sem alterar o Python do sistema.

Execute ``python manage.py setup`` uma vez e ``python manage.py run HASH``.
O ambiente .deps evita depender de ativação de venv no Windows.
"""

import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
SOURCES = [
    "hash_identifier.py", "test_hash_identifier.py", "test_mvp.py", "manage.py"
]


def main() -> int:
    """Encaminha comandos como listas, preservando caracteres especiais."""
    args = sys.argv[1:]
    if not args or args[0] not in {
            "setup", "run", "test", "lint", "format", "fix"
    }:
        print(
            "Uso: python manage.py {setup|run|test|lint|format|fix} [argumentos]"
        )
        return 2
    command, *extra = args
    if extra[:1] == ["--"]:
        extra = extra[1:]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / ".deps") + os.pathsep + str(ROOT)
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    env["PYLINTHOME"] = str(ROOT / ".pylint_cache")
    env["UV_CACHE_DIR"] = str(ROOT / ".uv-cache")
    commands: list[list[str]]
    if command == "setup":
        commands = [
            [
                "uv", "export", "--locked", "--all-extras",
                "--no-emit-project", "--output-file", ".deps-requirements.txt",
                "--quiet"
            ],
            [
                "uv", "pip", "install", "--python", sys.executable, "--target",
                ".deps", "--require-hashes", "-r", ".deps-requirements.txt"
            ],
        ]
    elif command == "run":
        commands = [[sys.executable, "hash_identifier.py", *extra]]
    elif command == "test":
        commands = [[
            sys.executable, "-m", "pytest", "-p", "no:cacheprovider",
            "test_hash_identifier.py", "test_mvp.py", *extra
        ]]
    elif command == "lint":
        commands = [
            [sys.executable, "-m", "ruff", "check", *SOURCES],
            [
                sys.executable, "-m", "mypy", "--strict", "hash_identifier.py",
                "manage.py"
            ],
            [
                sys.executable, "-m", "pylint", "--jobs=1",
                "hash_identifier.py", "manage.py"
            ],
        ]
    elif command == "fix":
        commands = [[sys.executable, "-m", "ruff", "check", "--fix", *SOURCES]]
    else:
        commands = [[sys.executable, "-m", "yapf", "-i", *SOURCES]]
    try:
        for invocation in commands:
            result = subprocess.run(invocation, cwd=ROOT, env=env, check=False)
            if result.returncode:
                return result.returncode
    except OSError as error:
        print(f"Não foi possível executar: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
