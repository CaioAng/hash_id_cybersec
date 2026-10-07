"""Testes de aceitação dos desafios 1 e 2, incluindo a CLI real."""

from collections.abc import Iterator
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

import pytest

from hash_identifier import identify

MD5 = "5f4dcc3b5aa765d61d8327deb882cf99"
SCRIPT = Path(__file__).with_name("hash_identifier.py")


@pytest.fixture
def input_file() -> Iterator[Path]:
    """Arquivo exclusivo de cada teste, removido mesmo quando há falha."""
    path = SCRIPT.parent / f".test-input-{uuid.uuid4().hex}.txt"
    try:
        yield path
    finally:
        path.unlink(missing_ok=True)


def run_cli(*args: str, stdin: str = "") -> subprocess.CompletedProcess[str]:
    """Executa sem shell para preservar literalmente os caracteres dos hashes."""
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        input=stdin,
        capture_output=True,
        encoding="utf-8",
        check=False,
        env={
            **os.environ, "PYTHONIOENCODING": "utf-8"
        },
    )


def test_new_prefix() -> None:
    """A regra Solaris contém vírgula, não outro cifrão."""
    result = identify("$md5,rounds=5000$salt$digest")[0]
    assert result.algorithm == "Solaris MD5 crypt"
    assert result.confidence == "high"


def test_new_hex_length() -> None:
    """96 bits não podem ser apresentados como Tiger-128."""
    result = identify("a1" * 12)[0]
    assert "96" in result.algorithm
    assert result.confidence == "low"
    assert all(c.algorithm != "Tiger-128" for c in identify("a1" * 12))


@pytest.mark.parametrize("sample,label", [
    ("https://example.org/a?q=x", "URL"),
    ("0x1234abcd", "Hex"),
    ("JBSWY3DPEHPK3PXP", "Base32"),
    ("1BoatSLRHtKNngkdXEeobR76b53LETtpyT", "Base58"),
])
def test_other_formats(sample: str, label: str) -> None:
    """Codificações e endereços são pistas de baixa confiança."""
    result = identify(sample)[0]
    assert label in result.algorithm
    assert result.confidence == "low"
    assert result.hashcat_mode is None


@pytest.mark.parametrize(
    "sample", ["!@#$%^&*", "0xXYZ!", "abcdefghijk+?", "a" * 23 + "!"])
def test_invalid_charsets(sample: str) -> None:
    """Um caractere isolado de Base64 não basta."""
    assert identify(sample) == []


def test_hashcat_modes() -> None:
    """Modo zero é válido e não deve ser confundido com ausência."""
    candidates = identify(MD5)
    assert candidates[0].hashcat_mode == 0
    assert next(c for c in candidates
                if c.algorithm == "NTLM").hashcat_mode == 1000
    assert identify("$2b$12$example")[0].hashcat_mode == 3200


def test_json_and_top() -> None:
    """JSON é consumível diretamente, com limite e modo."""
    result = run_cli("--json", "--top", "1", MD5)
    assert result.returncode == 0
    assert result.stderr == ""
    data = json.loads(result.stdout)
    assert len(data) == 1
    assert data[0]["algorithm"] == "MD5"
    assert data[0]["hashcat_mode"] == 0


def test_unknown_json() -> None:
    """Nenhum candidato produz array vazio e código 1."""
    result = run_cli("--json", "???")
    assert result.returncode == 1
    assert json.loads(result.stdout) == []


@pytest.mark.parametrize("top", ["0", "-1", "abc"])
def test_invalid_top(top: str) -> None:
    """Limites inválidos produzem erro de uso, nunca traceback."""
    result = run_cli("--top", top, MD5)
    assert result.returncode == 2
    assert "Traceback" not in result.stderr


def test_file_json_lines(input_file: Path) -> None:
    """BOM, vazios e duplicatas preservam a numeração original."""
    path = input_file
    path.write_text(f"{MD5}\n\n???\n{MD5}\n", encoding="utf-8-sig")
    result = run_cli("--file", str(path), "--json")
    assert result.returncode == 1
    records = [json.loads(line) for line in result.stdout.splitlines()]
    assert [record["line"] for record in records] == [1, 3, 4]
    assert records[0]["input"] == MD5
    assert records[0]["candidates"] == records[2]["candidates"]
    assert records[1]["candidates"] == []


def test_stdin() -> None:
    """Sem posicional, cada linha do stdin é uma entrada."""
    result = run_cli("--json", stdin=f"{MD5}\n{'a' * 64}\n")
    assert result.returncode == 0
    assert len(result.stdout.splitlines()) == 2


def test_explicit_stdin() -> None:
    """--file - também aceita stdin."""
    result = run_cli("--file", "-", "--json", stdin=MD5)
    assert result.returncode == 0
    assert json.loads(result.stdout)["input"] == MD5


def test_empty_stdin() -> None:
    """Lote vazio não deve indicar sucesso."""
    result = run_cli("--json", stdin="\n \n")
    assert result.returncode == 1
    assert result.stdout == ""


def test_file_errors(input_file: Path) -> None:
    """Arquivo inexistente, codificação inválida e fontes conflitantes."""
    path = input_file
    assert run_cli("--file", str(path)).returncode == 2
    path.write_bytes(b"\xff\xfe\x80")
    result = run_cli("--file", str(path))
    assert result.returncode == 2
    assert "Traceback" not in result.stderr
    assert run_cli("--file", str(path), MD5).returncode == 2


def test_table_and_batch_text() -> None:
    """Saída humana apresenta o modo e lote usa uma linha por entrada."""
    result = run_cli(MD5)
    assert result.returncode == 0
    assert "hashcat" in result.stdout
    assert "hashcat -m 0" in result.stdout
    batch = run_cli(stdin=f"{MD5}\n???\n")
    assert batch.returncode == 1
    assert len(batch.stdout.splitlines()) == 2


def test_literal_markup() -> None:
    """Entrada não pode ser interpretada como formatação Rich."""
    result = run_cli("$md5,[red]texto[/red]")
    assert result.returncode == 0
    assert "[red]" in result.stdout
