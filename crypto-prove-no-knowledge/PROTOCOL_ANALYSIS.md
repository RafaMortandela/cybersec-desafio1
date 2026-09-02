# Verificador vulnerável e correção Schnorr

## Para que serve esta comparação

O serviço pretende verificar se o cliente conhece um expoente `x` tal que
`y = g^x mod p`. O problema não está nas duas equações isoladamente, mas na
ordem das mensagens: o cliente descobre qual equação será verificada antes de
escolher o compromisso correspondente.

`protocol_comparison.py` mantém o desafio original intacto e fornece uma
comparação executável entre:

1. as duas verificações vulneráveis de `src/lib.rs`;
2. a falsificação usada por `solution.py`;
3. um verificador Schnorr binário corrigido;
4. a extração do testemunho que demonstra a propriedade de conhecimento.

Execute:

```bash
python3 protocol_comparison.py
python3 protocol_comparison.py --json
python3 -m unittest -v test_protocol_comparison.py
```

## O protocolo Schnorr correto

Considere um grupo cíclico de ordem `q`, gerado por `g`, e a chave pública
`y = g^x`, na qual `x` é o segredo.

Uma rodada correta tem esta ordem:

1. O provador sorteia um nonce novo `r` e envia um único compromisso
   `t = g^r`.
2. Somente depois disso, o verificador sorteia um desafio imprevisível
   `e in {0, 1}`.
3. O provador envia `s = r + e*x mod q`.
4. O verificador aceita se `g^s = t * y^e`.

Para `e=0`, a equação vira `g^s=t`. Para `e=1`, vira `g^s=t*y`. As duas
equações vistas no desafio são, portanto, equações Schnorr válidas. A falha é
que o servidor executa cada uma como uma prova separada e deixa o provador
escolher um novo `t` depois de saber qual delas será usada.

## Transcrição honesta

A demonstração usa o subgrupo de ordem `q=11` de `Z_23*`, com `g=2`, segredo
`x=7` e nonce `r=3`:

```text
y = 2^7 mod 23 = 13
t = 2^3 mod 23 = 8

e=0: (t,e,s) = (8,0,3)
e=1: (t,e,s) = (8,1,10)
```

Verificações:

```text
2^3  = 8       = 8 * 13^0 mod 23
2^10 = 12      = 8 * 13^1 mod 23
```

As duas transcrições possuem o mesmo compromisso porque representam as duas
respostas possíveis para a mesma primeira mensagem. Em uma execução real,
apenas uma delas é enviada, conforme o desafio sorteado.

## Transcrição maliciosa

A solução não conhece `x`. Ela prepara separadamente uma transcrição que passa
em cada desafio:

```text
e=0: t0=1,      s0=0  -> g^0 = 1
e=1: t1=y^(-1), s1=0  -> g^0 = y^(-1) * y = 1
```

No exemplo, `y^(-1) mod 23 = 16`, portanto as transcrições são `(1,0,0)` e
`(16,1,0)`. Ambas passam no servidor vulnerável, mas usam compromissos
diferentes. Se `t=1` for fixado antes do desafio, a resposta falsa passa apenas
para `e=0`. Se `t=y^(-1)` for fixado, ela passa apenas para `e=1`. Um desafio
uniforme e imprevisível limita essa estratégia a probabilidade `1/2` por
rodada, ou `2^-128` depois de 128 rodadas independentes.

## Em que sentido o compromisso deve ser único

"Único" possui duas exigências diferentes que não devem ser confundidas:

- **Um só compromisso dentro da rodada:** `t` precisa ser enviado e fixado
  antes do desafio. As respostas para desafios diferentes devem se referir a
  esse mesmo `t`. É isso que está ausente no serviço vulnerável.
- **Um compromisso fresco entre rodadas:** o nonce `r` não deve ser reutilizado
  em autenticações reais. Reutilizar `r` e obter desafios diferentes revela o
  segredo.

O compromisso não precisa ser um valor globalmente exclusivo ou determinístico.
Ele precisa ser vinculante antes do desafio e derivado de aleatoriedade fresca.

## Prova de conhecimento por extração

Suponha que existam duas transcrições aceitas com o mesmo `t` e desafios
diferentes:

```text
g^s0 = t * y^e0
g^s1 = t * y^e1
```

Dividindo a segunda equação pela primeira, o compromisso cancela:

```text
g^(s1-s0) = y^(e1-e0) = g^(x*(e1-e0))
```

Logo:

```text
x = (s1-s0) * (e1-e0)^(-1) mod q
```

Para `e0=0` e `e1=1`, temos simplesmente `x=s1-s0 mod q`. No exemplo,
`x=10-3=7 mod 11`.

Essa é a propriedade de **soundness especial** de um Sigma-protocolo: qualquer
máquina capaz de responder corretamente aos dois desafios para o mesmo
compromisso permite extrair o testemunho. Com os compromissos maliciosos
`t0 != t1`, a divisão deixa o fator extra `t1/t0`; o cancelamento falha e não há
extração. Isso prova por que a primeira mensagem precisa ser a mesma.

## Relação com Schnorr e OR-proofs

Schnorr é o Sigma-protocolo formado por compromisso, desafio e resposta. Uma
OR-proof de Schnorr prova conhecimento de `x0` ou `x1`, para
`y0=g^x0` e `y1=g^x1`, sem revelar qual testemunho é conhecido.

Na composição OR padrão, o provador:

1. simula a ramificação cujo segredo não conhece, escolhendo `e_j` e `s_j` e
   calculando `t_j = g^s_j * y_j^(-e_j)`;
2. cria honestamente o compromisso da ramificação conhecida;
3. recebe um único desafio global `e`;
4. escolhe o desafio restante para satisfazer `e = e0 + e1 mod q`;
5. o verificador confere a soma dos desafios e as duas equações Schnorr.

A falsificação do desafio se parece com a simulação de uma ramificação:
escolhe-se antecipadamente a resposta e calcula-se um compromisso que torna a
equação verdadeira. Simular uma ramificação não é uma quebra de Schnorr; é uma
propriedade usada legitimamente em OR-proofs e em zero knowledge. A quebra
acontece porque o servidor aceita duas simulações independentes sem um desafio
global que as vincule e sem exigir que o compromisso anteceda o desafio.

Na versão não interativa por Fiat-Shamir, esse vínculo normalmente é obtido
calculando o desafio como hash da declaração e de todos os compromissos. Assim,
alterar um compromisso também altera o desafio.

## Observação sobre os parâmetros do desafio

A demonstração usa deliberadamente um subgrupo de ordem prima, que é o cenário
usual para Schnorr. O serviço calcula respostas módulo `p-1`, o que pressupõe
que o grupo relevante e a ordem de `g` foram escolhidos corretamente. Em uma
implementação de produção, o verificador deve validar os parâmetros, trabalhar
em um subgrupo de ordem prima conhecida e rejeitar elementos fora dele.
