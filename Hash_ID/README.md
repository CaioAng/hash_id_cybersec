# Hash_ID

![Mode](https://img.shields.io/badge/Mode-Individual-402)
![Difficulty](https://img.shields.io/badge/Difficulty-N1_Iniciante-brightgreen)
![Stack](https://img.shields.io/badge/Stack-Python-3776AB)

> Identifique o algoritmo por trás de uma string de hash por seu prefixo, comprimento e conjunto de caracteres — o primeiro passo em qualquer fluxo de trabalho de quebra de senhas.

_Esta é uma visão geral rápida — teoria de segurança, arquitetura e tutoriais completos estão em [/learn](./learn/00-Introdução.md)._

> [!NOTE]
> Esta ferramenta foi desenvolvida para alguém que nunca escreveu Python antes. O código-fonte é amplamente comentado como material de apoio ao aprendizado, a pasta `learn/` explica cada conceito do zero, e toda a ferramenta consiste em um único arquivo legível.

## 🎯 Objective

Construir uma ferramenta de linha de comando que identifica o algoritmo de hash de uma string com base em padrões observáveis (prefixo, comprimento, conjunto de caracteres), retornando candidatos classificados com níveis de confiança.

## 🧠 Learning Outcomes

- O que são hashes e por que não são criptografia reversível
- Como identificar algoritmos por formato, comprimento e prefixo
- Os três sinais de identificação: prefixo, comprimento, conjunto de caracteres
- Fundamentos de Python: funções puras, tipagem, testes, CLI
- Como estruturar um pipeline de decisão em camadas

## � Caso tenha dificuldades com a base do projeto

> [!NOTE]
> Este projeto ensina Python do zero nos módulos `learn/`. Se você empacar na base, estes recursos rápidos ajudam a recuperar o fluxo.

- [Curso em Vídeo — Python para Iniciantes](https://www.cursoemvideo.com/course/curso-python-3/) — vídeo-aula passo a passo
- [Python Tutorial for Beginners — freeCodeCamp.org](https://www.youtube.com/watch?v=rfscVS0vtbw) — introdução prática a Python
- [Hash algorithms — Computerphile](https://youtu.be/b4b8ktEV4Bg?si=4KDOBMfntwpbWxkw) — entenda hashes em 10 minutos

## 🛠️ Scope

### MVP

- **Desafios Nível 1 (1.1–1.3):** adicionar uma regra de prefixo, adicionar uma regra por comprimento hexadecimal e criar a saída `--json`.
- **Desafios Nível 2 (2.1–2.3):** entrada por arquivo/stdin, dicas de modo do hashcat e reconhecimento de entradas que não são hashes.
- Manter a identificação dos formatos existentes, os níveis de confiança e a justificativa funcionando enquanto esses desafios são implementados.
- Demonstrar cada desafio com testes automatizados e uma execução da CLI.

### Stretch

- **Nível 3 (3.1–3.3):** identificação de múltiplos hashes, pontuação de confiança e estimativa de dificuldade de quebra.
- **Nível 4 (4.1–4.3):** análise de dump real, comparação com ferramentas existentes e hook de `pre-commit`.

### Conquer

- **Nível 5 (5.1–5.2):** documentar as limitações estruturais do identificador e construir um classificador probabilístico com ML.

## ✅ Definition of Done

- [x] `just test` passa (mais de 30 testes)
- [x] `just lint` passa (ruff + mypy --strict + pylint)
- [x] `just run -- <hash>` identifica corretamente os hashes de demonstração
- [x] Códigos de saída corretos para scripts de shell

Validação em 07/10/2026: 70 testes passaram; Ruff e Mypy estrito sem erros; Pylint 10/10. CLI e encaminhamento de argumentos com `$` verificados no Windows.

## 🧪 Validation

```bash
just test       # executa o pytest (mais de 30 testes)
just lint       # ruff + mypy --strict + pylint
just run -- 5f4dcc3b5aa765d61d8327deb882cf99
# ✔ MD5 (medium) — 32 caracteres hexadecimais, candidato mais provável para este comprimento
```

Teste com os [hashes de demonstração](#hashes-de-demonstração) abaixo.

## 🎬 Demo

A entrega escrita está em [DEMO.md, na raiz do repositório](../DEMO.md).
Ela apresenta o problema, a arquitetura, resultados reproduzíveis, decisões,
limitações, conclusões e o atendimento aos cinco critérios de avaliação.

As saídas reais de testes, lint e execução estão em
[evidencias/demo-validacao.txt](evidencias/demo-validacao.txt).

Por ser um projeto individual, o autor deve gravar um vídeo de 5–10 minutos.
O roteiro foi entregue separadamente e o link será enviado no canal indicado
pela entidade, fora deste repositório. A gravação e o envio ainda dependem do autor.

## 🚀 Getting Started

### Windows / PowerShell — versão implementada

Abra o terminal na pasta `Hash_ID`. Python 3.13+ e `uv` devem estar instalados
(o desenvolvimento foi validado com Python 3.14). Não é necessário instalar `just`:

```powershell
python manage.py setup
python manage.py test
python manage.py lint
python manage.py run 5f4dcc3b5aa765d61d8327deb882cf99
python manage.py run --json --top 1 5f4dcc3b5aa765d61d8327deb882cf99
python manage.py run --file demo_hashes.txt
python manage.py run --file demo_hashes.txt --json
Get-Content demo_hashes.txt | python manage.py run --json
```

`setup` instala as versões de `uv.lock` em `.deps/`, usando o Python já instalado,
sem alterar os pacotes globais. `manage.py` encaminha os argumentos literalmente.
Essa alternativa também funciona em sistemas que bloqueiam o executável criado
por um ambiente virtual. A instalação inicial precisa de internet; o identificador
funciona offline. Se preferir um ambiente virtual convencional, use
`uv sync --all-extras` e `uv run hashid <hash>`.

Com `just` 1.33+ instalado, `just setup`, `just test`, `just lint` e
`just run -- <hash>` usam os mesmos atalhos portáveis. Execute `just setup` antes
de `just test`/`just lint` para preparar `.deps/`.

### Entrega: desafios 1.1 a 2.3

| Desafio | Implementação | Demonstração após `python manage.py` |
| --- | --- | --- |
| 1.1 | Prefixo Solaris `$md5,` | `run '$md5,rounds=5000$salt$digest'` |
| 1.2 | 24 hex / 96 bits, confiança baixa | `run a1a1a1a1a1a1a1a1a1a1a1a1` |
| 1.3 | Array JSON de candidatos | `run --json 5f4dcc3b5aa765d61d8327deb882cf99` |
| 2.1 | Arquivo UTF-8 ou stdin, leitura linha a linha | `run --file demo_hashes.txt --json` |
| 2.2 | Campo e coluna `hashcat_mode`, com sugestão | `run 5f4dcc3b5aa765d61d8327deb882cf99` |
| 2.3 | URL, `0x`, Base32, Base58 e Base64 | `run https://example.org/` |

O enunciado original atribuía incorretamente 24 hex a Tiger-128: 24 × 4 = 96 bits,
enquanto 128 bits precisam de 32 hex. A implementação informa a ambiguidade,
e a correção está registrada em `learn/04-Desafios.md`.

### Contrato de saída e erros

- Entrada única com `--json`: array com `algorithm`, `confidence`, `reason` e
  `hashcat_mode` (inteiro ou `null`). Sem candidatos, retorna `[]`.
- Lote com `--json`: JSON Lines, um objeto por linha, com `line`, `input` e
  `candidates`. A numeração corresponde às linhas do arquivo original.
- Lote em texto: uma linha por entrada, com os candidatos separados por `;`.
- Linhas vazias são ignoradas; duplicatas são preservadas. Arquivos UTF-8 com BOM
  são aceitos. `--file -` lê stdin. Nenhum arquivo é carregado inteiro na memória.
- Código **0**: todas as entradas não vazias receberam algum candidato ou pista.
  Isso não certifica que sejam hashes: uma URL reconhecida também retorna 0.
- Código **1**: alguma entrada desconhecida, entrada única vazia ou lote vazio.
- Código **2**: argumentos inválidos, fontes conflitantes, arquivo inacessível
  ou erro de codificação. Diagnósticos de leitura vão para stderr.
- Em falha durante a leitura de um lote, resultados anteriores podem já ter sido
  escritos. Confira também o código de saída (`$LASTEXITCODE` no PowerShell).


Os modos foram conferidos no [catálogo oficial do hashcat v7.1.2](https://github.com/hashcat/hashcat/blob/v7.1.2/docs/hashcat-example-hashes.md).
Nem todos os candidatos têm modo mapeado, e alguns modos exigem adaptar o formato
da entrada (por exemplo, a representação MySQL). Não escolha um modo apenas pelo
primeiro candidato sem conhecer a origem do hash.

### Limitações

MD5, NTLM, MD4 e saídas truncadas podem compartilhar 32 hex. Hexadecimal também
pode ser um identificador aleatório. Prefixos conhecidos são reconhecidos mesmo
em exemplos didáticos incompletos. Base58 é apenas uma verificação de alfabeto e
comprimento mínimo, sem checksum; há sobreposição com Base32. A pista de JWT
verifica a forma aparente e não valida o token ou sua assinatura. Strings PHC
desconhecidas continuam sendo pistas genéricas. Nenhuma confiança é prova de origem.

### Instalação alternativa em Linux/macOS

Dentro da pasta `Hash_ID`:

```bash
sudo apt update
wget -qO- https://astral.sh/uv/install.sh | sh
uv venv --python 3.14
source .venv/bin/activate
./install.sh
just run -- 5f4dcc3b5aa765d61d8327deb882cf99
```

> [!TIP]
> Este projeto utiliza o [`just`](https://github.com/casey/just) como executor de comandos. Digite `just` para ver todos os comandos disponíveis.
>
> Instalação: `curl -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin`

## Hashes de Demonstração

| Hash                                                                          | Detectado como   | Motivo                             |
| ----------------------------------------------------------------------------- | ---------------- | ---------------------------------- |
| `5f4dcc3b5aa765d61d8327deb882cf99`                                            | MD5              | 32 caracteres hexadecimais         |
| `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`            | SHA-256          | 64 caracteres hexadecimais         |
| `$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G.VHvgvWK`              | bcrypt           | prefixo `$2b$`                     |
| `$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG` | Argon2id         | prefixo `$argon2id$`               |
| `$apr1$JlOdSlVe$ipa1mTAv3LFRBHHzqaIaH/`                                       | Apache MD5-crypt | prefixo `$apr1$`                   |
| `*A4B6157319038724E3560894F7F932C8886EBFCF`                                   | MySQL5           | começa com `*` + 40 hex maiúsculos |
| `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgN...`  | JWT (não é hash) | prefixo `eyJ` = base64 de `{"`     |

> [!IMPORTANT]
> Sempre envolva hashes que começam com `$` em **aspas simples**. Sem as aspas, seu shell tentará expandir `$2`, `$P$`, `$1$` etc. como variáveis de shell.

## Ferramentas

```bash
just            # lista os comandos disponíveis
just test       # executa o pytest
just lint       # ruff + mypy --strict + pylint
just format     # yapf
just run -- <h> # identifica um hash
```

## Requisitos

- **Python 3.13+** — conforme `pyproject.toml`; validado com 3.14.
- [`uv`](https://github.com/astral-sh/uv) — gerenciador moderno de pacotes para Python.
- [`just`](https://github.com/casey/just) — executor de comandos.

Nenhum compilador é necessário. A instalação das dependências requer rede;
a identificação funciona offline.

## 📚 Learning Resources

| Módulo                                          | Tópico                                                             |
| ----------------------------------------------- | ------------------------------------------------------------------ |
| [00 - Introdução](learn/00-Introdução.md)       | Início rápido, pré-requisitos, problemas comuns                    |
| [01 - Conceitos](learn/01-Conceitos.md)         | O que são hashes, violações reais, os três sinais de identificação |
| [02 - Arquitetura](learn/02-Arquitetura.md)     | Arquitetura em três camadas, pipeline de decisão em seis etapas    |
| [03 - Implementação](learn/03-Implementação.md) | Explicação linha por linha — cada recurso do Python explicado      |
| [04 - Desafios](learn/04-Desafios.md)           | Cinco níveis de ideias para extensão                               |

## 🔗 Referências externas

- [hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) — catálogo de formatos de hash reais
- [Name That Hash](https://nth.skerritt.blog/) — ferramenta online de identificação de hashes
- [Crypto 101](https://www.crypto101.io/) — introdução a criptografia aplicada

## 🧭 Next Step

Após concluir `Hash_ID`, você pode avançar para o projeto em equipe do mesmo ramo: [`Hash_Cracker`](../../Team/Hash_Cracker/README.md) — quebra de hashes com ataques de dicionário, brute force e regras.

> [!NOTE]
> **Não é obrigatório** avançar para o próximo projeto imediatamente. Você pode fazer múltiplos projetos primários em paralelo, respeitando as janelas de entrega do calendário.

---

@CarterPerez-dev | Copyright (C) 2026 Murilo Miacci
