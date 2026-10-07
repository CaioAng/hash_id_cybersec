"""
©AngelaMos | 2026
Copyright (C) 2026 Murilo Miacci
hash_identifier.py

Identifica que tipo de hash uma string é, inspecionando seu formato.

Quando alguém lhe entrega uma string de caracteres aleatórios como
`5f4dcc3b5aa765d61d8327deb882cf99` ou `$2b$12$EixZaYVK1fsbw1ZfbX3OXe...`,
a primeira pergunta é: qual algoritmo a produziu? Você NÃO pode quebrar
ou analisar um hash sem saber qual "sabor" de hash está olhando. Toda
ferramenta de quebra — hashcat, john the ripper — precisa que você
especifique um algoritmo antes de começar.

Este script faz a parte da observação. Dada uma string de hash, ele retorna
candidatos classificados com uma pontuação de confiança e um motivo curto.

────────────────────────────────────────────────────────────────────
Como a identificação realmente funciona
────────────────────────────────────────────────────────────────────
Não há mágica aqui. Strings de hash carregam pistas de formato:

  1. PREFIXO. Muitos hashes modernos são armazenados no "formato de string PHC" —
     um formato autodescritivo que começa com um marcador como `$2b$`
     (bcrypt) ou `$argon2id$` (Argon2id). Quando vemos um prefixo
     conhecido, sabemos o algoritmo com ALTA confiança.

  2. COMPRIMENTO. A saída hexadecimal bruta de uma função de hash tem sempre o
     mesmo comprimento: MD5 produz 16 bytes = 32 caracteres hex; SHA-1 produz 20
     bytes = 40 caracteres hex; SHA-256 produz 32 bytes = 64 caracteres hex,
     e assim por diante. O comprimento por si só estreita o campo.

  3. CONJUNTO DE CARACTERES (CHARSET). Diferentes formatos usam diferentes alfabetos.
     Hashes hexadecimais usam apenas 0-9 e a-f. Base64 usa 0-9, A-Z, a-z, +, /, e =.
     Uma string com `+` nela não é um hash hexadecimal.

Portanto, nosso algoritmo é: tentar regras de prefixo primeiro, recorrer a regras
de comprimento + charset, e retornar os candidatos classificados por confiança.

────────────────────────────────────────────────────────────────────
O que este script pode e não pode fazer
────────────────────────────────────────────────────────────────────
PODE:    sugerir algoritmos prováveis para um hash que você encontrou.
NÃO PODE: dizer qual é a senha que originou o hash.
          (isso é trabalho do hashcat — veja ../../beginner/hash-cracker)

────────────────────────────────────────────────────────────────────
O que este arquivo expõe
────────────────────────────────────────────────────────────────────
  HashCandidate          — um palpite classificado (algoritmo, confiança, motivo)
  identify(text)         — retorna candidatos classificados para uma string de hash
  main()                 — ponto de entrada da CLI usado por `hashid <hash>`
"""

# Biblioteca padrão: analisa flags de linha de comando como `--top 3` em um
# objeto amigável para não termos que fatiar `sys.argv` manualmente.
import argparse
import base64
import binascii
import json
from collections.abc import Iterable
from contextlib import nullcontext
from pathlib import Path

# Biblioteca padrão: acesso a internos do interpretador — usamos para
# escrever no stderr e sair do processo com um código de status específico.
import sys

# Biblioteca padrão: um decorador que transforma uma classe em um registro de
# dados pequeno e imutável sem escrever código repetitivo de `__init__`.
from dataclasses import asdict, dataclass

# Biblioteca padrão: uma dica de tipo que fixa um valor a um pequeno conjunto
# fixo de strings (aqui: "high", "medium", "low"). O Mypy captura erros de digitação.
from typing import Literal

# Terceiros (rich): o impressor que desenha a tabela no terminal,
# com suporte a cores e Unicode.
from rich.console import Console

# Terceiros (rich): constrói a tabela ASCII colorida que imprimimos para
# os candidatos a hash classificados.
from rich.table import Table
from rich.text import Text

# =============================================================================
# Tipo de Confiança — apenas três valores válidos
# =============================================================================
# Literal["high", "medium", "low"] é uma dica de tipo que diz "esta string
# pode ser APENAS um destes três valores". O Mypy pegará erros como "hgih"
# em tempo de edição. Escolhemos Literal em vez de Enum porque prefiro
# Literals para conjuntos fixos pequenos.

Confidence = Literal["high", "medium", "low"]

# =============================================================================
# Tipo de Resultado — o que identify() retorna para cada palpite
# =============================================================================


@dataclass(frozen=True, slots=True)
class HashCandidate:
    """
    Uma possível identificação de uma string de hash.

    `frozen=True` torna a dataclass imutável — uma vez criada, seus
    campos não podem mudar. `slots=True` torna as instâncias leves na
    memória. Juntas, essas duas flags criam um "objeto de valor" limpo.

    Campos
    ------
    algorithm
        Nome legível do algoritmo como "SHA-256" ou "bcrypt".
    confidence
        Quão certos estamos. "high" vem de correspondências de prefixo definitivas,
        "medium" de correspondências de comprimento que têm apenas um candidato
        óbvio, "low" para comprimentos que podem ser muitas coisas.
    reason
        Explicação curta exibida ao lado do nome do algoritmo. Mantém a
        saída depurável — o usuário pode ver POR QUE cada palpite foi feito.
    """

    algorithm: str
    confidence: Confidence
    reason: str
    hashcat_mode: int | None = None

    def __post_init__(self) -> None:
        """Completa o modo conhecido sem alterar a interface dos candidatos."""
        if self.hashcat_mode is None:
            object.__setattr__(self, "hashcat_mode",
                               HASHCAT_MODES.get(self.algorithm))


# Modos conferidos no catálogo oficial do hashcat v7.1.2.
# Ausência significa que não oferecemos uma correspondência direta confirmada.
HASHCAT_MODES: dict[str, int] = {
    "MD5": 0,
    "SHA-1": 100,
    "MySQL323": 200,
    "MySQL5": 300,
    "phpass": 400,
    "MD5 crypt": 500,
    "MD4": 900,
    "NTLM": 1000,
    "SHA-224": 1300,
    "SHA-256": 1400,
    "DES crypt": 1500,
    "Apache MD5-crypt": 1600,
    "SHA-512": 1700,
    "SHA-512 crypt": 1800,
    "bcrypt": 3200,
    "SHA-256 crypt": 7400,
    "SHA-384": 10800,
}

# =============================================================================
# Regras de Prefixo — o sinal mais forte que temos
# =============================================================================
# Hashes modernos usam strings estilo PHC: um marcador `$` inicial diz
# exatamente qual algoritmo produziu o hash. Quando vemos um desses
# prefixos, relatamos ALTA confiança. O terceiro elemento de cada tupla
# é uma nota curta que incluímos no campo de motivo.
#
# A ordem importa quando os prefixos se sobrepõem. Listamos prefixos mais
# específicos PRIMEIRO para que correspondam antes dos genéricos.

PREFIX_RULES: list[tuple[str, str, str]] = [
    ("$md5,", "Solaris MD5 crypt",
     "variante Solaris com parâmetros após a vírgula"),
    # Família Argon2 — venceu a Password Hashing Competition de 2015
    ("$argon2id$", "Argon2id", "string PHC moderna, o padrão atual"),
    ("$argon2i$", "Argon2i",
     "string PHC, variante resistente a canais laterais"),
    ("$argon2d$", "Argon2d", "string PHC, variante resistente a GPU"),
    # bcrypt e suas variantes — cavalo de batalha dos últimos 15 anos
    ("$2y$", "bcrypt", "string PHC bcrypt, variante 2y (PHP)"),
    ("$2b$", "bcrypt", "string PHC bcrypt, variante 2b (atual)"),
    ("$2a$", "bcrypt", "string PHC bcrypt, variante 2a (legado)"),
    ("$2x$", "bcrypt", "string PHC bcrypt, variante 2x (correção de legado)"),
    # Família Unix crypt(3) — o que o /etc/shadow usa no Linux
    ("$6$", "SHA-512 crypt", "Unix crypt(3) usando SHA-512 (padrão no Linux)"),
    ("$5$", "SHA-256 crypt", "Unix crypt(3) usando SHA-256"),
    ("$1$", "MD5 crypt", "Unix crypt(3) usando MD5 (legado, fraco)"),
    # Variante MD5 do Apache htpasswd — mesma família MD5 do $1$ acima, mas
    # com o ajuste de manipulação de salt do Apache. Este é o formato que
    # `htpasswd -m` emite por padrão.
    ("$apr1$", "Apache MD5-crypt",
     "variante MD5 do Apache htpasswd (`htpasswd -m`)"),
    # yescrypt — novo padrão Linux em algumas distribuições
    ("$y$", "yescrypt", "string PHC, sucessor moderno do Linux crypt"),
    # phpass — usado pelo WordPress, phpBB e outros apps PHP
    ("$P$", "phpass", "hash de senha do WordPress / phpBB"),
    ("$H$", "phpass", "variante phpass estilo phpBB"),
    # Drupal 7
    ("$S$", "Drupal 7 (SHA-512)", "hash estilo PHC do Drupal 7"),
    # scrypt como algumas implementações o codificam
    ("$7$", "scrypt", "hash estilo PHC scrypt"),
    # Padrão do Django — reconhecível pelo nome do algoritmo no prefixo
    ("pbkdf2_sha256$", "Django PBKDF2-SHA256", "hash de senha padrão do Django"
     ),
    ("pbkdf2_sha1$", "Django PBKDF2-SHA1", "hash de senha legado do Django"),
    ("bcrypt_sha256$", "Django bcrypt-SHA256", "wrapper bcrypt do Django"),
    ("argon2$", "Django Argon2", "wrapper Argon2 do Django"),
    # Esquemas de senha LDAP — carga base64 após o marcador
    ("{SSHA}", "LDAP SSHA", "SHA-1 com salt do LDAP (carga base64)"),
    ("{SHA}", "LDAP SHA", "SHA-1 do LDAP (carga base64)"),
    ("{SMD5}", "LDAP SMD5", "MD5 com salt do LDAP (carga base64)"),
    ("{MD5}", "LDAP MD5", "MD5 do LDAP (carga base64)"),
    ("{CRYPT}", "LDAP CRYPT", "LDAP envolvendo um hash crypt(3)"),
]

# =============================================================================
# Regras de comprimento e hex — fallback quando nenhum prefixo correspondeu
# =============================================================================
# A saída bruta de um hash tem sempre o mesmo comprimento, então uma string de
# N caracteres hex estreita o algoritmo. A lista de algoritmos para cada
# comprimento é ordenada pela prevalência no MUNDO REAL. O primeiro item recebe
# confiança MÉDIA (o "padrão mais provável"), o restante BAIXA.

# Caracteres hex são 0-9 mais a-f (ou A-F se maiúsculos)
HEX_CHARSET: frozenset[str] = frozenset("0123456789abcdefABCDEF")

# Conjunto de caracteres hex apenas maiúsculos — alguns formatos (MySQL5) APENAS
# emitem hex maiúsculo. Verificar isso nos permite rejeitar strings minúsculas
# como falsos positivos.
_HEX_UPPER_CHARSET: frozenset[str] = frozenset("0123456789ABCDEF")

# Comprimento-em-caracteres-hex → lista de algoritmos, ordenada por frequência
HEX_LENGTH_RULES: dict[int, list[str]] = {
    # 24 hex = 96 bits; não há evidência para atribuir um algoritmo específico.
    24: ["Hexadecimal de 96 bits (possível hash truncado)"],
    # 16 caracteres hex = 8 bytes = 64 bits. Saída do OLD_PASSWORD() do MySQL.
    16: ["MySQL323", "CRC-64"],
    # 32 caracteres hex = 16 bytes = 128 bits
    32: ["MD5", "NTLM", "MD4", "RIPEMD-128"],
    # 40 caracteres hex = 20 bytes = 160 bits
    40: ["SHA-1", "RIPEMD-160"],
    # 48 caracteres hex = 24 bytes = 192 bits
    48: ["Tiger-192"],
    # 56 caracteres hex = 28 bytes = 224 bits
    56: ["SHA-224", "SHA3-224"],
    # 64 caracteres hex = 32 bytes = 256 bits
    64: ["SHA-256", "SHA3-256", "BLAKE2s-256", "RIPEMD-256"],
    # 80 caracteres hex = 40 bytes = 320 bits (incomum)
    80: ["RIPEMD-320"],
    # 96 caracteres hex = 48 bytes = 384 bits
    96: ["SHA-384", "SHA3-384"],
    # 128 caracteres hex = 64 bytes = 512 bits
    128: ["SHA-512", "SHA3-512", "BLAKE2b-512", "Whirlpool"],
}

# =============================================================================
# Auxiliares
# =============================================================================


def _is_hex(text: str) -> bool:
    """
    Retorna True se cada caractere no texto for um dígito hex e o texto não estiver vazio.

    Um hash como "5f4dcc..." passa; uma string vazia ou qualquer coisa com
    um caractere não-hex falha. Usamos o frozenset HEX_CHARSET para testes
    de pertinência porque `c in frozenset` é uma busca O(1).
    """
    return bool(text) and all(c in HEX_CHARSET for c in text)


# Layout MySQL5: `*` seguido por 40 caracteres hex maiúsculos.
_MYSQL5_HEX_BODY_LENGTH = 40
_MYSQL5_TOTAL_LENGTH = _MYSQL5_HEX_BODY_LENGTH + 1


def _is_mysql5(text: str) -> bool:
    """
    Retorna True para o formato de senha MySQL5: `*` e 40 caracteres hex MAIÚSCULOS.

    O MySQL5 armazena SHA-1(SHA-1(senha)) impresso em hex maiúsculo com um `*` inicial.
    Rejeitamos minúsculas aqui para não retornar um veredito de ALTA confiança
    em uma string editada manualmente ou digitada incorretamente.
    """
    if len(text) != _MYSQL5_TOTAL_LENGTH or not text.startswith("*"):
        return False
    body = text[1:]
    return all(c in _HEX_UPPER_CHARSET for c in body)


# DES crypt tradicional — hashes /etc/passwd legados de sistemas Unix pré-shadow.
# Eles não têm prefixo: apenas 13 caracteres de um alfabeto específico de 64 chars.
_DESCRYPT_CHARSET: frozenset[str] = frozenset(
    "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
_DESCRYPT_TOTAL_LENGTH = 13


def _is_descrypt(text: str) -> bool:
    """
    Retorna True para o DES crypt tradicional de 13 caracteres (legado /etc/passwd).

    Sem prefixo — apenas 13 caracteres extraídos de `./0-9A-Za-z`.
    Relatamos confiança MÉDIA (não ALTA) porque uma string de 13 caracteres
    nesse charset PODE ser outras coisas (IDs de sessão, valores codificados).
    """
    return len(text) == _DESCRYPT_TOTAL_LENGTH and all(c in _DESCRYPT_CHARSET
                                                       for c in text)


# =============================================================================
# O identificador propriamente dito
# =============================================================================
# pylint: disable=too-many-return-statements,too-many-branches


def identify(raw_input: str) -> list[HashCandidate]:
    """
    Retorna candidatos classificados para qual algoritmo produziu `raw_input`.

    Algoritmo
    ---------
    Espaços em branco são removidos de `raw_input` primeiro. Então os seis
    passos de correspondência abaixo rodam em ordem:

    1. Percorre a tabela PREFIX_RULES. O primeiro prefixo que corresponder
       vence (confiança ALTA).
    2. Verifica formatos especiais não-PHC em ordem — registros de desafio-resposta
       NetNTLMv1/v2, MySQL5 (`*<40 hex>`) e o DES crypt legado de 13 chars.
    3. Se a entrada for hex puro, procura seu comprimento em HEX_LENGTH_RULES.
       O primeiro item recebe confiança MÉDIA; o resto BAIXA.
    4. Se a entrada tiver o formato `$<algo>$...` mas nenhuma regra de prefixo
       correspondeu, recorre a uma correspondência genérica de string PHC (confiança BAIXA).
    5. Se a entrada parecer um JWT (`eyJ...`) ou um blob base64 (contém `+`, `/`, ou `=`),
       informa isso com confiança BAIXA — estes não são hashes.
    6. Se nada corresponder, retorna uma lista vazia.

    Parâmetros
    ----------
    raw_input
        A string de hash a identificar.

    Retorna
    -------
    list[HashCandidate]
        Pode estar vazia. Quando não vazia, os candidatos são ordenados por
        confiança (alta antes de média antes de baixa).
    """
    # Remove espaços em branco — hashes colados costumam vir com quebras de linha.
    text = raw_input.strip()

    if not text:
        return []

    # ----- Passo 1: regras de prefixo -----
    # Percorre a tabela de cima para baixo. A confiança ALTA é o rótulo correto
    # porque um prefixo conhecido é uma autoidentificação definitiva.
    for prefix, algorithm, note in PREFIX_RULES:
        if text.startswith(prefix):
            return [
                HashCandidate(
                    algorithm=algorithm,
                    confidence="high",
                    reason=f"prefixo `{prefix}` — {note}",
                )
            ]

    # ----- Passo 2: formatos especiais não-PHC -----
    # Formatos que não se encaixam no molde PHC `$algo$...` mas têm formas inconfundíveis.

    # NetNTLMv1 / NetNTLMv2 — saídas dominantes de ferramentas de pentest AD.
    # NÃO são hashes no sentido de "função irreversível" — são registros de
    # desafio-resposta. O literal `::` é a pista estrutural.
    if "::" in text and text.count(":") >= 4:
        parts = text.split(":")
        # Layout NetNTLMv2:
        #   usuario :: dominio : desafio : hmac(32 hex) : blob(>=32 hex)
        if len(parts) >= 6 and len(parts[4]) == 32 and _is_hex(parts[4]):
            return [
                HashCandidate(
                    algorithm="NetNTLMv2",
                    confidence="high",
                    reason="formato usuario::dominio:desafio:hmac(32 hex):blob",
                )
            ]
        # Layout NetNTLMv1:
        #   usuario :: dominio : lmhash(48 hex) : nthash(48 hex) : desafio
        if len(parts) >= 6 and len(parts[3]) == 48 and _is_hex(parts[3]):
            return [
                HashCandidate(
                    algorithm="NetNTLMv1",
                    confidence="high",
                    reason=
                    "formato usuario::dominio:lm(48 hex):nt(48 hex):desafio",
                )
            ]

    # MySQL5 — literal `*` + 40 caracteres hex maiúsculos
    if _is_mysql5(text):
        return [
            HashCandidate(
                algorithm="MySQL5",
                confidence="high",
                reason=
                "começa com `*` seguido por 40 caracteres hex maiúsculos",
            )
        ]

    # DES crypt tradicional de 13 caracteres — formato legado /etc/passwd
    if _is_descrypt(text):
        return [
            HashCandidate(
                algorithm="DES crypt",
                confidence="medium",
                reason=
                "13 caracteres em `./0-9A-Za-z` — formato legado /etc/passwd",
            )
        ]

    # ----- Passo 3: comprimento + charset hex -----
    if _is_hex(text):
        algorithms = HEX_LENGTH_RULES.get(len(text), [])
        candidates: list[HashCandidate] = []
        for index, algorithm in enumerate(algorithms):
            # O primeiro algoritmo listado para cada comprimento é o padrão moderno
            # e recebe confiança MÉDIA. O restante é BAIXA.
            confidence: Confidence = "medium" if index == 0 and len(
                text) != 24 else "low"
            label = ("candidato mais provável para este comprimento" if index
                     == 0 else "também possível para este comprimento")
            if len(text) == 24:
                label = "96 bits; o comprimento não permite determinar o algoritmo"
            candidates.append(
                HashCandidate(
                    algorithm=algorithm,
                    confidence=confidence,
                    reason=f"{len(text)} caracteres hex — {label}",
                ))
        return candidates

    # ----- Passo 4: fallback genérico para string PHC -----
    # Se a entrada começa com `$<nome>$...` e <nome> parece um identificador
    # plausível, é quase certamente uma string PHC de um algoritmo para o qual
    # não temos uma regra específica.
    if text.startswith("$"):
        rest = text[1:]
        if "$" in rest:
            algo_name = rest.split("$", 1)[0]
            # A especificação PHC restringe IDs de algoritmo a alfanuméricos
            # mais `-` e `_`.
            if algo_name and all(c.isalnum() or c in "-_" for c in algo_name):
                return [
                    HashCandidate(
                        algorithm=f"String PHC ({algo_name})",
                        confidence="low",
                        reason=
                        f"formato `${algo_name}$...` — PHC genérico, sem regra específica",
                    )
                ]

    # ----- Passo 5 e 6: pistas de outras representações, ou nenhum candidato -----
    return _identify_encoding(text)


def _identify_encoding(text: str) -> list[HashCandidate]:
    """Reconhece pistas de codificação, sem afirmar a natureza do conteúdo."""
    if text.lower().startswith(("http://", "https://")):
        return [
            HashCandidate("URL (não é um hash)", "low",
                          "prefixo HTTP ou HTTPS")
        ]
    if text.lower().startswith("0x") and _is_hex(text[2:]):
        return [
            HashCandidate(
                "Hex com prefixo 0x",
                "low",
                "representação hexadecimal; pode ser endereço, número ou hash",
            )
        ]
    if text.startswith("eyJ") and text.count(".") == 2:
        return [
            HashCandidate(
                "Possível JWT (não é um hash isolado)",
                "low",
                "três segmentos e cabeçalho aparente em Base64URL; assinatura não verificada",
            )
        ]
    # Base32 tem prioridade sobre Base58 porque seus alfabetos se sobrepõem.
    if len(text) >= 8 and all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567="
                              for c in text):
        try:
            base64.b32decode(text + "=" * (-len(text) % 8))
        except (binascii.Error, ValueError):
            pass
        else:
            return [
                HashCandidate(
                    "Possível Base32",
                    "low",
                    "codificação válida; pode conter dados ou um hash, sem algoritmo inferível",
                )
            ]
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    if len(text) >= 20 and all(c in alphabet for c in text):
        return [
            HashCandidate(
                "Possível Base58",
                "low",
                "alfabeto compatível; endereço e checksum não validados",
            )
        ]
    if len(text) > 8 and any(c in text for c in "+/="):
        try:
            base64.b64decode(text, validate=True)
        except (binascii.Error, ValueError):
            pass
        else:
            return [
                HashCandidate(
                    "Possível Base64",
                    "low",
                    "codificação válida; o conteúdo pode ser um hash ou outros dados",
                )
            ]
    return []


# =============================================================================
# CLI — argparse + uma tabela rich
# =============================================================================


def _build_argument_parser() -> argparse.ArgumentParser:
    """
    Constrói o analisador argparse usado pelo main().
    """
    parser = argparse.ArgumentParser(
        prog="hashid",
        description=(
            "Identifica uma string de hash por prefixo, comprimento e charset. "
            "Retorna candidatos classificados com confiança e raciocínio."),
    )
    parser.add_argument(
        "hash",
        nargs="?",
        help=
        "A string de hash a identificar (envolva em aspas simples se contiver $).",
    )
    parser.add_argument("--json",
                        action="store_true",
                        help="JSON; em lote, JSON Lines.")
    parser.add_argument("--file",
                        type=Path,
                        help="Arquivo UTF-8, um hash por linha; - usa stdin.")
    parser.add_argument(
        "--top",
        "-n",
        type=int,
        default=5,
        help="Mostra no máximo este número de candidatos (padrão: 5).",
    )
    return parser


def _render_table(
    raw_input: str,
    candidates: list[HashCandidate],
    console: Console,
) -> None:
    """
    Imprime uma Tabela rich mostrando os candidatos identificados.
    """
    table = Table(
        title=Text(f"Candidatos para: {raw_input.strip()}"),
        title_style="bold cyan",
        show_lines=False,
    )
    table.add_column("algoritmo", style="bold white", no_wrap=True)
    table.add_column("confiança", no_wrap=True)
    table.add_column("hashcat", no_wrap=True)
    table.add_column("motivo", style="dim")

    # Cores para os níveis de confiança.
    confidence_colors: dict[Confidence, str] = {
        "high": "green",
        "medium": "yellow",
        "low": "cyan",
    }
    for candidate in candidates:
        color = confidence_colors[candidate.confidence]
        table.add_row(
            candidate.algorithm,
            f"[{color}]{candidate.confidence}[/{color}]",
            str(candidate.hashcat_mode)
            if candidate.hashcat_mode is not None else "—",
            Text(candidate.reason),
        )
    console.print(table)


def _render_single(raw_input: str, top: int, json_output: bool) -> int:
    """JSON simples mantém o array solicitado no desafio 1.3."""
    candidates = identify(raw_input)[:top]
    if json_output:
        print(
            json.dumps([asdict(c) for c in candidates],
                       ensure_ascii=True,
                       indent=2))
    elif candidates:
        console = Console()
        _render_table(raw_input, candidates, console)
        mode = candidates[0].hashcat_mode
        if mode is not None:
            console.print(
                Text(
                    f"Modo sugerido: {mode}. Após confirmar o formato, exemplo de uso: "
                    f"hashcat -m {mode} -a 0 hashes.txt wordlist.txt\n"
                    "O arquivo hashes.txt deve conter o hash no formato exigido pelo modo. "
                    "A identificação não valida integralmente o hash."))
    else:
        Console().print("Nenhuma identificação possível.")
    return 0 if candidates else 1


def _render_batch(lines: Iterable[str], top: int, json_output: bool) -> int:
    """Processa linha a linha, com memória limitada e JSON Lines para integração."""
    count = 0
    unmatched = False
    for number, line in enumerate(lines, 1):
        raw_input = line.strip()
        if number == 1:
            raw_input = raw_input.removeprefix("\ufeff").strip()
        if not raw_input:
            continue
        count += 1
        candidates = identify(raw_input)[:top]
        unmatched = unmatched or not candidates
        if json_output:
            print(
                json.dumps(
                    {
                        "line": number,
                        "input": raw_input,
                        "candidates": [asdict(c) for c in candidates],
                    },
                    ensure_ascii=True))
        else:
            summary = "; ".join(
                f"{c.algorithm} ({c.confidence}; hashcat={c.hashcat_mode})"
                for c in candidates) or "sem identificação"
            # JSON escapa controles: cada entrada ocupa exatamente uma linha.
            print(
                f"{number}\t{json.dumps(raw_input, ensure_ascii=True)}\t{summary}"
            )
    return 1 if unmatched or count == 0 else 0


def main() -> int:
    """Retorna 0 para candidatos, 1 para desconhecidos/vazios, 2 para erro de uso."""
    parser = _build_argument_parser()
    args = parser.parse_args()
    if args.top < 1:
        parser.error("--top deve ser maior que zero")
    if args.hash is not None and args.file is not None:
        parser.error("use o hash posicional ou --file, não ambos")
    if args.hash is not None:
        return _render_single(args.hash, args.top, args.json)
    if args.file is None and sys.stdin.isatty():
        parser.error("informe um hash, --file ou envie linhas pelo stdin")
    try:
        source = (args.file.open(encoding="utf-8-sig") if args.file is not None
                  and str(args.file) != "-" else nullcontext(sys.stdin))
        with source as lines:
            return _render_batch(lines, args.top, args.json)
    except (OSError, UnicodeError) as error:
        print(f"Erro ao ler entrada: {error}", file=sys.stderr)
        return 2


# Guarda padrão "se invocado diretamente como script".
if __name__ == "__main__":
    sys.exit(main())
