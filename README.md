# Prove No Knowledge — UTCTF 2021

> Desafio de criptografia baseado na **quebra de _soundness_** de um Protocolo Sigma
> (prova de conhecimento zero para logaritmo discreto).

Este repositório reúne o material de estudo, a reprodução local e a análise
matemática do desafio **"Prove No Knowledge"** da UTCTF 2021. A ideia é mostrar,
de ponta a ponta, **por que o servidor é vulnerável**, **como o exploit engana a
verificação sem conhecer o segredo** e **como o protocolo deveria ser corrigido**.

```
nc crypto.utctf.live 4354        (serviço original)
```

---

## Visão geral

| Item | Valor |
|---|---|
| **Competição** | UTCTF 2021 |
| **Categoria** | Criptografia |
| **Autor original** | Soham Roy (_Sohamster_) |
| **Serviço** | `nc crypto.utctf.live 4354` |
| **Objetivo** | Autenticar-se provando conhecimento de `x` tal que `y = g^x mod p` |
| **Flag** | `utflag{questions_not_random}` |

O servidor implementa um protocolo interativo de **prova de conhecimento zero**: o
cliente precisa convencer o servidor de que conhece um expoente secreto `x`, sem
nunca enviar `x` pela rede. O nome do desafio ("prove **no** knowledge") já é a
pista: o exploit consegue passar na verificação **sem conhecer nada**, porque o
servidor faz as perguntas na ordem errada.

---

## Estrutura do repositório

```
cybersec-desafio1/
├── README.md                        ← este arquivo
├── relatórios/
│   ├── Resumo_Introdução_Descomplicada.md   ← explicação com analogias
│   ├── Resumo_Introdução_Técnica.md         ← fundamentação matemática
│   └── Resumo_Reprodução_Local.md           ← passo a passo para rodar em casa
└── crypto-prove-no-knowledge/
    ├── src/                         ← servidor vulnerável (Rust)
    │   ├── main.rs                  ← bootstrap TCP / healthcheck
    │   ├── lib.rs                   ← protocolo: test_a, test_b, process
    │   ├── env/                     ← leitura de variáveis de ambiente
    │   └── globals/                 ← constantes e defaults
    ├── solution.py                  ← exploit original (transcrição maliciosa)
    ├── protocol_comparison.py       ← verificador CORRETO + demonstração
    ├── test_protocol_comparison.py  ← testes automatizados da análise
    ├── PROTOCOL_ANALYSIS.md         ← análise formal (soundness, extração)
    ├── explicacao.md                ← passo a passo didático do ataque
    ├── Dockerfile / docker-compose.yml  ← infraestrutura do serviço
    └── Cargo.toml
```

---

## Fundamentação: Protocolo Sigma / Schnorr

Variáveis públicas combinadas entre **Provador** (cliente) e **Verificador** (servidor):

| Símbolo | Significado |
|---|---|
| `p` | Primo grande usado como módulo (o "relógio" matemático). |
| `g` | Gerador público do grupo. |
| `x` | **Segredo** (a chave privada / logaritmo discreto). |
| `y` | Chave pública: `y = g^x mod p`. |
| `r` | Nonce aleatório temporário, escolhido pelo cliente. |
| `t` | **Compromisso**: `t = g^r mod p`. |
| `e` | **Desafio** do servidor, `0` ou `1`. |
| `s` | **Resposta** do cliente. |

Uma rodada **correta** de um protocolo Sigma tem sempre esta ordem (`t → e → s`):

```
Cliente                          Servidor
   |                                |
   |------- compromisso t --------->|   t = g^r mod p
   |                                |
   |<------ desafio e ∈ {0,1} ------|   sorteado AGORA, imprevisível
   |                                |
   |------- resposta s ----------->|   s = r + e·x
   |                                |
   |             verifica: g^s == t · y^e mod p
```

- Se `e = 0` → `s = r` e a checagem vira `g^s == t`.
- Se `e = 1` → `s = r + x` e a checagem vira `g^s == t · y`.

**Por que é seguro:** o cliente tem que fixar `t` **antes** de saber `e`. Um
provador honesto (que conhece `x`) responde a qualquer um dos dois desafios. Um
farsante só consegue se preparar para um deles → acerta com probabilidade `1/2`
por rodada. Em `n` rodadas independentes, a chance de trapaça cai para `2⁻ⁿ`.

> **Extração (special soundness):** se alguém responde aos **dois** desafios
> para o **mesmo** `t`, dá para recuperar o segredo:
> `g^s0 = t` e `g^s1 = t·y` ⟹ `g^{s1−s0} = y = g^x` ⟹ `x = s1 − s0 mod q`.
> É isso que significa "provar conhecimento de `x`".

---

## Como o servidor funciona

Código em [`crypto-prove-no-knowledge/src/lib.rs`](crypto-prove-no-knowledge/src/lib.rs).

Ao conectar, o servidor envia os parâmetros e pede **256 verificações** (um laço de
`128` iterações, cada uma com duas checagens):

```
Please authenticate with the service for 256 rounds
Prove knowledge of x such that g^x mod p = y
g: <...>
p: <...>
y: <...>
```

Cada iteração do laço chama, **nesta ordem fixa**:

### `test_a` — sempre o caso `e = 0`
```
1. "Pick a random r. Send g^r mod p."   → cliente envia  C
2. "Send r."                             → cliente envia  r
3. servidor verifica:  g^r == C  (mod p)
```

### `test_b` — sempre o caso `e = 1`
```
1. "Pick a random r. Send g^r mod p."          → cliente envia  C'
2. "Send (x + r) mod (p - 1)."                  → cliente envia  s
3. servidor verifica:  g^s == C' · y  (mod p)
```

Se todas as 256 checagens passarem:

```
Authentication succeeded!
utflag{questions_not_random}
```

---

## A vulnerabilidade (quebra de _soundness_)

A segurança de um protocolo Sigma depende de **uma única regra**:

> O compromisso `t` precisa ser enviado **antes** de o desafio `e` ser conhecido.

O servidor **quebra essa regra**. Ele roda `test_a` e depois `test_b` como duas
provas separadas, e em cada uma **anuncia qual desafio vai verificar antes de
pedir o compromisso**:

- `test_a` = "vou checar `e = 0`, agora me mande um compromisso"
- `test_b` = "vou checar `e = 1`, agora me mande outro compromisso"

Com isso o cliente:

1. **já sabe** qual equação será verificada;
2. pode escolher um **compromisso diferente** para cada caso;
3. monta a resposta primeiro e **fabrica o compromisso de trás para frente**.

Isso é literalmente o comportamento de um **Simulador** — uma ferramenta que, na
teoria de ZK, serve para provar segurança, mas que aqui derruba a autenticação.
Daí a flag: `questions_not_random` (as perguntas não são aleatórias).

| Propriedade | Prova honesta | Ataque |
|---|---|---|
| Conhece `x`? | Sim | Não |
| Fixa `t` antes do desafio? | Sim | Não, escolhe depois |
| Usa o mesmo `t` para `e=0` e `e=1`? | Sim | Não, `t` diferente em cada caso |
| Passa no servidor vulnerável? | Sim | Sim |
| Passa no protocolo corrigido? | Sim | Não (só `1/2` por rodada) |

---

## O exploit (`solution.py`)

Código em [`crypto-prove-no-knowledge/solution.py`](crypto-prove-no-knowledge/solution.py).
Usa [`pwntools`](https://docs.pwntools.com/) para a comunicação de rede.

Para cada iteração, o script envia **4 linhas** — duas para `test_a`, duas para `test_b`:

```python
for _ in range(128):
    conn.sendline(b"1")                       # test_a  → compromisso  t0 = 1
    conn.sendline(b"0")                       # test_a  → resposta     s0 = 0
    conn.sendline(str(pow(y, -1, p)).encode())# test_b  → compromisso  t1 = y⁻¹ mod p
    conn.sendline(b"0")                       # test_b  → resposta     s1 = 0
```

### Por que funciona

**`test_a` (`e = 0`), verificação `g^s == t`:**
escolhe `s = 0`, então `g^0 = 1`; basta mandar `t = 1` → `1 == 1`.

**`test_b` (`e = 1`), verificação `g^s == t · y`:**
escolhe `s = 0`, então `g^0 = 1`; precisa de `t · y ≡ 1`, ou seja
`t = y⁻¹ mod p` (o inverso modular de `y`) → `1 == y⁻¹ · y = 1`.

As duas "transcrições" maliciosas são:

```
test_a:  (t, e, s) = (1,      0, 0)
test_b:  (t, e, s) = (y⁻¹,    1, 0)
```

Ambas passam, mas usam **compromissos diferentes** (`1 ≠ y⁻¹`) — por isso não é
possível extrair `x` delas, e por isso o protocolo corrigido as rejeita.

> Explicação linha a linha com números pequenos em
> [`crypto-prove-no-knowledge/explicacao.md`](crypto-prove-no-knowledge/explicacao.md).

---

## O protocolo corrigido (`protocol_comparison.py`)

Código em [`crypto-prove-no-knowledge/protocol_comparison.py`](crypto-prove-no-knowledge/protocol_comparison.py)
— **não altera o servidor**; é uma reimplementação independente, sem rede, que
coloca lado a lado o verificador vulnerável e um verificador Schnorr binário
correto.

O que ele demonstra (usando o subgrupo de ordem prima `q = 11` de `Z₂₃*`, com
`g = 2`, `x = 7`, `r = 3`):

1. **Transcrição honesta** — `(8,0,3)` e `(8,1,10)`, ambas com o **mesmo** `t = 8`,
   aceitas pelo verificador correto.
2. **Falsificação** — reproduz `(1,0,0)` e `(16,1,0)`; ambas passam no verificador
   **vulnerável**, mas têm compromissos diferentes.
3. **Correção** — se o compromisso for fixado antes do desafio, `t = 1` só serve
   para `e = 0` e `t = y⁻¹` só serve para `e = 1`; o ataque falha.
4. **Extração do testemunho** — de duas respostas honestas para o mesmo `t`,
   recupera `x = s1 − s0 = 10 − 3 = 7`.

### Como corrigir de verdade

- **Um único compromisso por rodada**, fixado **antes** do desafio; as respostas
  para `e = 0` e `e = 1` têm que se referir ao mesmo `t`.
- **Desafio uniforme e imprevisível** (idealmente `e` sorteado pelo servidor após
  receber `t`).
- **Compromisso fresco entre rodadas** (novo `r` aleatório a cada rodada — nunca
  reutilizar).
- Na versão não interativa, usar **Fiat–Shamir**: `e = H(declaração ‖ t)`, de modo
  que mudar o compromisso muda o desafio.

> Análise formal completa (soundness especial, relação com Schnorr e OR-proofs) em
> [`crypto-prove-no-knowledge/PROTOCOL_ANALYSIS.md`](crypto-prove-no-knowledge/PROTOCOL_ANALYSIS.md).

---

## Como reproduzir localmente

Guia detalhado, com todas as adaptações e justificativas, em
[`relatórios/Resumo_Reprodução_Local.md`](relatórios/Resumo_Reprodução_Local.md)
(inclui [vídeo demonstração](https://youtube.com/shorts/01DkGjKlT1g?feature=share)).

Resumo:

### 1. Subir o servidor (Docker)

```bash
git clone https://github.com/utisss/UTCTF-21.git
cd UTCTF-21/crypto-prove-no-knowledge

# no docker-compose.yml: no-new-privileges:true  →  false
docker-compose up -d --build
docker ps        # confirme que o container está de pé (porta 4354)
```

### 2. Preparar o cliente (exploit)

```bash
# dependências de sistema (só se o pip falhar ao compilar o unicorn)
sudo apt install pkg-config libglib2.0-dev python3-dev

python3 -m venv venv
source venv/bin/activate
pip install pwntools
```

### 3. Rodar o ataque

```bash
# em solution.py: ADDRESS = 'localhost'  /  PORT = 4354
python3 solution.py
# → Authentication succeeded!
# → utflag{questions_not_random}
```

---

## Como rodar a comparação e os testes

Não precisa de rede nem de Docker — só Python 3:

```bash
cd crypto-prove-no-knowledge

python3 protocol_comparison.py            # demonstração legível
python3 protocol_comparison.py --json     # mesma coisa em JSON
python3 -m unittest -v test_protocol_comparison.py   # testes automatizados
```

Os testes confirmam que:

- as transcrições honestas passam e permitem extrair `x`;
- o ataque passa nas duas checagens vulneráveis;
- o mesmo ataque **falha** quando o compromisso é fixado antes do desafio;
- não é possível extrair `x` de compromissos diferentes;
- o verificador corrigido rejeita entradas fora do domínio (`e ∉ {0,1}`, `s ∉ [0,q)`, `t ∉ [1,p)`).



