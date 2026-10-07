# Demo — Hash_ID

**Modalidade:** individual · **Escopo:** MVP, desafios 1.1–2.3.

Este arquivo apresenta a demonstração escrita e as evidências reproduzíveis do
projeto. O vídeo individual de 5–10 minutos será gravado e seu link
será enviado separadamente no canal de entrega da entidade. Não há vídeo ou link
de vídeo armazenado neste repositório.

## Parte 1 — Projeto, resultados e conclusões

### Problema e relevância em segurança

Uma string como `5f4dcc3b5aa765d61d8327deb882cf99` não informa diretamente qual
algoritmo a produziu. Identificar candidatos ajuda a interpretar dados de um
laboratório e escolher verificações compatíveis com o formato observado.

O Hash_ID inspeciona **prefixo, comprimento e conjunto de caracteres** e retorna
candidatos com justificativa e confiança (`high`, `medium`, `low`). A ferramenta
não recupera senhas nem confirma a origem da entrada. MD5 e NTLM, por exemplo,
podem compartilhar a representação de 32 caracteres hexadecimais.

### O que foi construído

A base fornecida já continha o identificador, regras e testes. A entrega estende
essa base com os seis desafios obrigatórios. A implementação contou com auxílio
de IA; a demonstração oral deve explicar e conferir as decisões no código.

| Desafio | Implementação | Evidência prática |
| --- | --- | --- |
| 1.1 | Prefixo `$md5,` para Solaris MD5 crypt | Entrada didática reconhecida com confiança alta |
| 1.2 | Regra de 24 hex / 96 bits | Saída genérica de possível truncamento, confiança baixa |
| 1.3 | `--json` e `--top` | Array JSON com campos estruturados e limite de candidatos |
| 2.1 | `--file`, stdin e leitura linha a linha | Lote em texto ou JSON Lines, preservando a linha original |
| 2.2 | `hashcat_mode` opcional | MD5 apresenta modo `0`; modos ausentes ficam como `null` |
| 2.3 | URL, hexadecimal `0x`, Base32 e Base58 | Pistas de formato com baixa confiança; Base64 também é verificado |

**Correção do desafio 1.2:** 24 caracteres hexadecimais representam 96 bits
(`24 × 4`). Tiger-128 exige 32 caracteres hexadecimais. Por isso, a regra não
atribui um algoritmo específico a uma entrada de 24 hex. A correção também está
documentada em [Desafios](Hash_ID/learn/04-Desafios.md).

### Stack e fluxo de dados

- Python 3.13+; execução validada com Python 3.14.
- `argparse`, `dataclasses`, `json` e outras bibliotecas padrão.
- Rich para a tabela no terminal; pytest para testes.
- Ruff, Mypy estrito e Pylint para verificação; uv para dependências; just para atalhos.

```text
Posicional / arquivo UTF-8 / stdin
                 ↓
     CLI valida argumentos e normaliza a entrada
                 ↓
 identify(): prefixos → formatos especiais → tamanho hexadecimal
                 → formato genérico → pistas de codificação
                 ↓
 lista de HashCandidate (algoritmo, confiança, motivo, modo)
                 ↓
 tabela / texto em lote / JSON / JSON Lines + código de saída
```

A função `identify()` concentra a classificação, sem abrir arquivos nem imprimir
resultados. A CLI escolhe a entrada e a apresentação. O auxiliar `manage.py`
executa tarefas de desenvolvimento e não contém regras de identificação.

### Reprodução no Windows / PowerShell

Na raiz do repositório, entre na pasta da ferramenta:

```powershell
cd Hash_ID
python manage.py setup
```

O setup instala as versões de `uv.lock` em `.deps`, sem alterar os pacotes
globais. A instalação precisa de rede; os comandos da demonstração funcionam
offline após o preparo.

Se `just --version` já funcionar, use o executável instalado. Caso contrário,
prepare uma cópia local (não versionada) e adicione-a ao PATH desta sessão:

```powershell
uv pip install --python python --target .demo-tools rust-just==1.58.0
$env:Path = "$(Join-Path (Get-Location) '.demo-tools\bin');$env:Path"
just --version
```

Na máquina em que esta entrega foi preparada, a cópia local já foi provisionada.
Em um terminal novo, basta repetir a linha de ajuste de PATH. Isso não altera
permanentemente o PATH do Windows.

### Caso real controlado: SHA-256 calculado localmente

Gere o hash de uma frase pública de laboratório, sem usar senha ou dado de outra pessoa:

```powershell
$hash = python -c "import hashlib; print(hashlib.sha256(b'demo-hash-id').hexdigest())"
$hash
just run -- --top 2 $hash
```

Resultado observado: `SHA-256` como primeiro candidato (`medium`) e `SHA3-256`
como segundo (`low`). Sabemos que a origem é SHA-256 porque acabamos de calculá-lo;
o identificador, isoladamente, só vê 64 caracteres hexadecimais. Esse contraste
mostra a diferença entre conhecimento da origem e inferência por formato.

### Demonstrações do MVP

Execute dentro de `Hash_ID`:

```powershell
# Caso solicitado na seção Validation do README: MD5 primeiro, mas não exclusivo.
just run -- 5f4dcc3b5aa765d61d8327deb882cf99

# 1.1: exemplo de prefixo; o corpo é didático, não um hash integralmente validado.
just run -- '$md5,rounds=5000$salt$digest'

# 1.2: 96 bits, sem algoritmo determinado.
just run -- a1a1a1a1a1a1a1a1a1a1a1a1

# 1.3 e 2.2: JSON com um candidato e hashcat_mode igual a 0.
just run -- --json --top 1 5f4dcc3b5aa765d61d8327deb882cf99

# 2.1: arquivo e stdin; no lote, cada linha JSON é um registro independente.
just run -- --file demo_hashes.txt --top 1
Get-Content demo_hashes.txt | python manage.py run --json --top 1

# 2.3: apenas classifica a string; não acessa a URL.
just run -- https://example.org/
just run -- 0x1234abcd
just run -- JBSWY3DPEHPK3PXP
just run -- 1BoatSLRHtKNngkdXEeobR76b53LETtpyT

# Saídas para automação: desconhecido = 1; uso inválido = 2.
python manage.py run --json '???'
$LASTEXITCODE
python manage.py run --top 0 5f4dcc3b5aa765d61d8327deb882cf99
$LASTEXITCODE
```

Base32/Base58/Base64 são codificações: podem conter um hash ou outros dados.
O projeto informa pistas de baixa confiança, não um veredito sobre seu conteúdo.
Aspas simples preservam os caracteres `$` dos exemplos ao passar pelo terminal.

### Decisões técnicas e compromissos

1. **Regras em tabelas, em vez de ML.** São explicáveis e fáceis de estender e
   testar, adequadas ao MVP. Em contrapartida, não resolvem a ambiguidade entre
   algoritmos de mesmo formato nem aprendem padrões automaticamente.
2. **Identificação separada de entrada e saída.** Uma função pura pode ser
   testada diretamente e reutilizada. A CLI tem testes adicionais em subprocessos
   reais para conferir argumentos, JSON e códigos de saída.
3. **JSON Lines e leitura incremental para lotes.** Não é preciso manter o
   arquivo inteiro na memória. O consumidor deve ler um objeto por linha, em vez
   de esperar um grande array. Se a leitura falhar no meio, pode já haver saída
   parcial; é necessário verificar o código de saída.
4. **Confiança qualitativa.** `high` significa uma pista específica, não uma
   probabilidade medida. Prefixos conhecidos não validam integralmente o corpo
   do hash. Uma melhoria futura seria acrescentar validadores por formato.

### Validação executada

Os comandos abaixo correspondem à seção `Validation` do README:

```powershell
just test
just lint
just run -- 5f4dcc3b5aa765d61d8327deb882cf99
```

| Verificação | Resultado |
| --- | --- |
| pytest | 70 testes aprovados |
| Ruff | Sem erros |
| Mypy `--strict` | Sem erros em 2 arquivos de código |
| Pylint | 10/10 |
| Exemplo do README | MD5 primeiro, confiança média; NTLM e outros como alternativas |
| SHA-256 calculado localmente | SHA-256 primeiro, confiança média |
| Erros da CLI | Código 1 para desconhecido; código 2 para `--top 0` |

A execução desta revisão está registrada em
[evidencias/demo-validacao.txt](Hash_ID/evidencias/demo-validacao.txt), com
comandos, saídas e códigos de retorno. Não são resultados simulados.

Os testes cobrem regras existentes e novas, entrada vazia, formatos inválidos,
JSON, arquivos UTF-8 com BOM, duplicatas, stdin, limites e erros de leitura.
Testes aprovados não provam identificação correta de todos os algoritmos existentes.

### Atendimento aos critérios de avaliação

| Critério | Evidência escrita e prática |
| --- | --- |
| Funcionalidade | Casos reproduzíveis, saídas e códigos registrados no log |
| Compreensão | Fluxo de dados, ambiguidade MD5/NTLM e caso SHA-256 de origem conhecida |
| Validação | Testes, lint e comando de Validation executados e registrados |
| Comunicação | Explicação por etapas, exemplos copiáveis e limites explícitos; clareza oral será demonstrada no vídeo |
| Segurança | Ambiente local do autor, frase pública de teste e exemplos didáticos; sem acesso a serviços ou dados de terceiros |

O hashcat não foi executado. Os seus modos são sugestões de correspondência,
não validação do conteúdo nem autorização para testar credenciais.

### Conclusões e próximos passos

O MVP funciona como identificador heurístico: os resultados são justificáveis
pelas regras, mas não revelam a senha nem garantem o algoritmo. O projeto permite
compartilhar a aprendizagem sobre representação hexadecimal, funções puras,
interfaces de linha de comando, testes e limites de inferência.

As próximas melhorias possíveis são validação completa de formatos e análise
de registros compostos. Os níveis 3–5 não fazem parte desta entrega. O `Next Step`
do README aponta para o projeto Hash_Cracker, que é uma atividade posterior,
separada deste identificador.


Referências internas: [README](Hash_ID/README.md),
[implementação](Hash_ID/hash_identifier.py), [testes do MVP](Hash_ID/test_mvp.py).
