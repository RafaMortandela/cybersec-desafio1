Para oq serve todo esse protocolo: o servidor quer que alguém prove que conhece um número secreto `x`, mas sem enviar esse número secreto pela rede.

O problema do desafio é que o servidor tenta fazer essa verificação, mas envia as perguntas na ordem errada. Isso permite que a `solution.py` invente respostas válidas sem conhecer `x`.

## 1. O que significam as letras

| Símbolo | Significado |
|---|---|
| `p` | Número usado como módulo. Pense nele como o tamanho de um “relógio” matemático. |
| `g` | Número público usado como base. |
| `x` | Segredo que o cliente deveria conhecer. |
| `y` | Valor público calculado como `y = g^x mod p`. |
| `r` | Número aleatório temporário escolhido pelo cliente. |
| `t` | Compromisso: `t = g^r mod p`. |
| `e` | Pergunta/desafio do servidor, que pode ser `0` ou `1`. |
| `s` | Resposta enviada pelo cliente. |

`mod p` significa “pegar o resto da divisão por `p`”.

Por exemplo:

```text
27 mod 23 = 4
```

porque `27 = 23 + 4`.

## 2. Qual é o objetivo do servidor

O servidor escolhe um segredo `x` e publica:

```text
y = g^x mod p
```

Ele então diz para o cliente:

> Prove que você conhece o `x` que foi usado para produzir `y`.

O cliente não pode simplesmente mandar `x`, porque isso revelaria o segredo. Por isso é usado um protocolo de prova de conhecimento.

## 3. Como deveria funcionar corretamente

Uma rodada correta deveria acontecer nesta ordem:

```text
Cliente                         Servidor
   |                               |
   |---- compromisso t ----------->|
   |                               |
   |<--- desafio aleatório e ------|
   |                               |
   |---- resposta s -------------->|
```

O ponto mais importante é:

> O cliente precisa enviar `t` antes de saber se o desafio será `0` ou `1`.

O cliente honesto escolhe um número aleatório `r` e calcula:

```text
t = g^r mod p
```

Depois o servidor escolhe aleatoriamente `e`.

Se `e=0`, a resposta é:

```text
s = r
```

Se `e=1`, a resposta é:

```text
s = r + x
```

De forma compacta:

```text
s = r + e*x
```

O servidor verifica:

```text
g^s = t * y^e mod p
```

## 4. O que é uma transcrição

Uma transcrição é simplesmente o registro de uma rodada do protocolo.

Ela contém:

```text
(t, e, s)
```

Ou seja:

```text
(compromisso, desafio, resposta)
```

Não é uma coisa nova ou misteriosa. É apenas o histórico das três mensagens importantes.

Exemplo:

```text
t = 8
e = 0
s = 3
```

A transcrição é:

```text
(8, 0, 3)
```

## 5. Exemplo de uma transcrição honesta

No comparador que criei, usei números pequenos para ser possível acompanhar as contas:

```text
p = 23
g = 2
x = 7
r = 3
```

O segredo é:

```text
x = 7
```

O valor público é:

```text
y = g^x mod p
y = 2^7 mod 23
y = 128 mod 23
y = 13
```

Portanto:

```text
y = 13
```

O cliente escolhe `r=3` e cria o compromisso:

```text
t = g^r mod p
t = 2^3 mod 23
t = 8
```

Agora existem duas perguntas que o servidor poderia fazer.

### Se o desafio for `e=0`

A resposta é:

```text
s = r + 0*x
s = 3
```

A transcrição fica:

```text
(t,e,s) = (8,0,3)
```

O servidor verifica:

```text
g^s = t * y^e mod p
2^3 = 8 * 13^0 mod 23
8 = 8 * 1
8 = 8
```

Passou.

### Se o desafio for `e=1`

A resposta é:

```text
s = r + 1*x
s = 3 + 7
s = 10
```

A transcrição fica:

```text
(t,e,s) = (8,1,10)
```

O servidor verifica:

```text
g^s = t * y^e mod p
2^10 mod 23 = 8 * 13 mod 23
```

Calculando os lados:

```text
2^10 mod 23 = 12
8 * 13 = 104
104 mod 23 = 12
```

Logo:

```text
12 = 12
```

Também passou.

Observe que as duas transcrições usam o mesmo compromisso:

```text
(8,0,3)
(8,1,10)
 ^
 mesmo t
```

Elas representam as duas possíveis respostas que o cliente honesto poderia dar para uma mesma primeira mensagem.

Em uma execução real, o servidor enviaria apenas um dos desafios. Mostramos os dois somente para entender e provar a segurança.

## 6. O problema no servidor original

O servidor não faz a sequência correta.

Ele executa primeiro `test_a`, que equivale a avisar:

> Agora vou verificar o caso `e=0`. Escolha um compromisso.

Depois executa `test_b`, que equivale a avisar:

> Agora vou verificar o caso `e=1`. Escolha outro compromisso.

Isso está em [src/lib.rs](/home/borgescaua/UTCTF-21/crypto-prove-no-knowledge/src/lib.rs:93):

```text
test_a:
    cliente envia um compromisso
    cliente envia a resposta para e=0

test_b:
    cliente envia outro compromisso
    cliente envia a resposta para e=1
```

O cliente já sabe qual pergunta será verificada antes de escolher o compromisso.

Esse é o erro central.

## 7. Como a resposta maliciosa para `e=0` funciona

Quando `e=0`, o servidor verifica:

```text
g^s = t
```

O atacante escolhe:

```text
s = 0
```

Qualquer número diferente de zero elevado a zero resulta em `1`:

```text
g^0 = 1
```

Para fazer a igualdade passar, basta escolher:

```text
t = 1
```

A verificação vira:

```text
g^0 = 1
1 = 1
```

Passou sem usar `x`.

Essa é a transcrição maliciosa:

```text
(t,e,s) = (1,0,0)
```

O nome `t0` que usei significa apenas:

```text
t0 = compromisso criado para o desafio 0
```

Portanto:

```text
t0 = 1
```

## 8. Como a resposta maliciosa para `e=1` funciona

Quando `e=1`, o servidor verifica:

```text
g^s = t * y mod p
```

Novamente o atacante escolhe:

```text
s = 0
```

Assim, o lado esquerdo vale:

```text
g^0 = 1
```

Agora precisamos escolher um `t` que faça:

```text
t * y mod p = 1
```

Esse `t` é o inverso modular de `y`, escrito:

```text
t = y^-1 mod p
```

`y^-1` não significa necessariamente `1/y` como em números reais. Significa:

> O número que, multiplicado por `y`, deixa resto `1` na divisão por `p`.

No exemplo:

```text
y = 13
p = 23
```

O inverso de `13` módulo `23` é `16`, porque:

```text
13 * 16 = 208
208 mod 23 = 1
```

Então o atacante envia:

```text
t = 16
s = 0
```

O servidor verifica:

```text
g^0 = 16 * 13 mod 23
1 = 208 mod 23
1 = 1
```

Passou sem usar `x`.

A transcrição maliciosa é:

```text
(t,e,s) = (16,1,0)
```

O nome `t1` significa:

```text
t1 = compromisso criado para o desafio 1
```

Portanto:

```text
t1 = y^-1 mod p
```

## 9. O que a `solution.py` está enviando

Este trecho da [solution.py](/home/borgescaua/UTCTF-21/crypto-prove-no-knowledge/solution.py:20) faz exatamente o ataque descrito:

```python
conn.sendline(str(1).encode(ENCODING))
conn.sendline(str(0).encode(ENCODING))
conn.sendline(str(pow(y, -1, p)).encode(ENCODING))
conn.sendline(str(0).encode(ENCODING))
```

As quatro mensagens são:

```text
1. compromisso para test_a: 1
2. resposta para test_a:     0
3. compromisso para test_b:  y^-1 mod p
4. resposta para test_b:     0
```

Em forma de transcrições:

```text
test_a: (1, 0, 0)
test_b: (y^-1, 1, 0)
```

O ataque funciona porque o servidor permite compromissos diferentes:

```text
t0 = 1
t1 = y^-1
```

## 10. Diferença entre transcrição honesta e maliciosa

| Propriedade | Honesta | Maliciosa |
|---|---|---|
| Conhece `x`? | Sim | Não |
| Escolhe `t` antes do desafio? | Sim | Não, aproveita que já sabe o desafio |
| Usa o mesmo `t` nas duas possibilidades? | Sim | Não |
| Resposta depende de `x`? | Sim, quando `e=1` | Não |
| Passa no servidor vulnerável? | Sim | Sim |
| Passa no protocolo corrigido para qualquer desafio? | Sim | Não |

No exemplo:

```text
Honestas:
(8,0,3)
(8,1,10)
```

Elas têm o mesmo `t=8`.

As maliciosas são:

```text
(1,0,0)
(16,1,0)
```

Elas têm compromissos diferentes:

```text
1 != 16
```

## 11. Por que um único compromisso corrige o problema

Imagine que o atacante seja obrigado a mandar `t` antes de conhecer `e`.

Se ele mandar:

```text
t = 1
```

e o servidor escolher `e=0`, ele consegue responder `s=0`:

```text
g^0 = 1
```

Mas, se o servidor escolher `e=1`, a verificação será:

```text
g^0 = 1 * y
1 = y
```

Normalmente `y` não é `1`, então falha.

Agora imagine que ele mande:

```text
t = y^-1
```

Se o servidor escolher `e=1`, a resposta `s=0` passa:

```text
g^0 = y^-1 * y
1 = 1
```

Mas, se o servidor escolher `e=0`, a verificação será:

```text
g^0 = y^-1
1 = y^-1
```

Isso normalmente é falso.

Portanto:

- `t=1` prepara o ataque apenas para `e=0`;
- `t=y^-1` prepara o ataque apenas para `e=1`;
- o atacante não consegue escolher um desses depois de descobrir `e`;
- com desafio aleatório, ele só consegue adivinhar uma das duas possibilidades.

A chance é `1/2` por rodada. Em 128 rodadas independentes:

```text
(1/2)^128 = 2^-128
```

Isso é uma probabilidade extremamente pequena.

## 12. Por que isso prova conhecimento de `x`

Considere duas respostas válidas para o mesmo compromisso:

```text
g^s0 = t
g^s1 = t * y
```

Como o mesmo `t` aparece nas duas equações, podemos eliminar esse valor.

Como:

```text
y = g^x
```

temos:

```text
g^s1 = t * g^x
```

E da primeira equação:

```text
t = g^s0
```

Substituindo:

```text
g^s1 = g^s0 * g^x
g^s1 = g^(s0+x)
```

Logo:

```text
s1 = s0 + x mod q
```

Então:

```text
x = s1 - s0 mod q
```

No exemplo honesto:

```text
s0 = 3
s1 = 10
```

Portanto:

```text
x = 10 - 3
x = 7
```

Recuperamos exatamente o segredo.

Essa é a ideia da prova de conhecimento:

> Se alguém consegue responder aos dois desafios para o mesmo compromisso, então é possível extrair dessa pessoa o segredo `x`.

No ataque, isso não funciona:

```text
transcrição 0 usa t=1
transcrição 1 usa t=16
```

Como os compromissos são diferentes, não podemos eliminar `t` das equações.

## 13. “Único” não significa reutilizar sempre o mesmo compromisso

Existem duas regras:

1. Dentro de uma rodada, deve existir somente um compromisso, enviado antes do desafio.
2. Entre rodadas diferentes, deve ser criado um compromisso novo usando um `r` aleatório novo.

Portanto:

```text
Rodada 1: escolhe r1 -> cria t1
Rodada 2: escolhe r2 -> cria t2
Rodada 3: escolhe r3 -> cria t3
```

Reutilizar o mesmo `r` em várias rodadas pode revelar `x`.

A frase mais precisa é:

> O compromisso deve ser fixado antes do desafio e deve ser fresco em cada nova rodada.

## 14. Relação simples com Schnorr

Esse protocolo é uma versão de desafio binário do protocolo de Schnorr.

Schnorr possui três etapas:

```text
1. compromisso
2. desafio
3. resposta
```

Por isso ele é chamado de Sigma-protocolo:

```text
t -> e -> s
```

A vulnerabilidade aconteceu porque a ordem foi quebrada:

```text
servidor praticamente revela e -> cliente escolhe t -> cliente escolhe s
```

Quando o cliente pode escolher `t` depois de conhecer `e`, ele consegue montar uma equação verdadeira artificialmente.

## 15. Relação simples com OR-proofs

Uma OR-proof serve para provar algo como:

> Eu conheço a senha da porta A ou da porta B, mas não vou revelar qual delas.

Nela, o provador:

- responde honestamente para a porta cujo segredo conhece;
- cria uma transcrição simulada para a outra porta;
- usa um desafio global para amarrar as duas partes.

Criar uma transcrição simulada não é automaticamente um problema. Simulações fazem parte das provas de zero knowledge.

O problema do servidor deste desafio é:

> Ele aceita duas simulações separadas sem criar um desafio global que obrigue as duas a pertencerem à mesma prova.

A `solution.py` simula:

```text
uma resposta preparada para e=0
outra resposta preparada para e=1
```

O servidor aceita as duas, embora elas usem compromissos diferentes e não demonstrem conhecimento de `x`.

## 16. Exatamente o que eu acrescentei

Não alterei o servidor vulnerável. Ele continua disponível para demonstrar o ataque.

Acrescentei [protocol_comparison.py](/home/borgescaua/UTCTF-21/crypto-prove-no-knowledge/protocol_comparison.py:27), que contém:

- o verificador corrigido;
- a criação das transcrições honestas;
- a criação das transcrições maliciosas;
- a reprodução das verificações vulneráveis;
- a tentativa do ataque contra o verificador corrigido;
- a extração de `x` usando duas respostas para o mesmo compromisso.

Acrescentei [test_protocol_comparison.py](/home/borgescaua/UTCTF-21/crypto-prove-no-knowledge/test_protocol_comparison.py:23), que confirma automaticamente que:

- as respostas honestas passam;
- o ataque passa no verificador vulnerável;
- o mesmo ataque falha quando o compromisso é fixado;
- `x` pode ser extraído das respostas honestas;
- não é possível aplicar a extração usando compromissos diferentes.

E escrevi a explicação matemática em [PROTOCOL_ANALYSIS.md](/home/borgescaua/UTCTF-21/crypto-prove-no-knowledge/PROTOCOL_ANALYSIS.md:3).

Para visualizar a comparação diretamente:

```bash
python3 protocol_comparison.py
```

O ponto principal de tudo é:

> A `solution.py` não descobre o segredo `x`. Ela apenas cria uma resposta falsa diferente para cada pergunta, porque o servidor informa implicitamente a pergunta antes de exigir o compromisso.
