# Resumo Completo e Técnico: Desafio "Prove No Knowledge" (UTCTF 2021)

Este documento detalha a fundamentação matemática, a mecânica da vulnerabilidade e a resolução do desafio focado na quebra de *soundness* de um Protocolo Sigma interativo.

---

## 1. Fundamentação Teórica: Prova de Conhecimento Zero para Logaritmo Discreto

O desafio baseia-se em um protocolo interativo para provar o conhecimento de um segredo $x$ (o logaritmo discreto) sem revelá-lo. As variáveis públicas estabelecidas entre o Provador e o Verificador (servidor) são:
*   $p$: Um número primo grande (módulo).
*   $g$: O gerador do grupo multiplicativo.
*   $y$: A chave pública, calculada como $y \equiv g^x \pmod p$.
*   $x$: A chave privada (o segredo que queremos provar que conhecemos).

O protocolo segue três passos clássicos de um Protocolo Sigma:
1.  **Compromisso (Commitment):** O provador gera um número aleatório $r$ e envia o compromisso $C \equiv g^r \pmod p$.
2.  **Desafio (Challenge):** O servidor solicita um de dois cenários possíveis (0 ou 1).
3.  **Resposta (Response):** O provador calcula e envia a resposta com base no desafio.

---

## 2. A Mecânica do Servidor (Verificador)

No desafio do UTCTF, o servidor exige 256 rodadas de autenticação. Em cada rodada, ocorre um dos seguintes cenários:

**Cenário 0 (Verificação do Compromisso):**
*   **Desafio:** O servidor pede o valor original de $r$.
*   **Resposta do Provador:** Envia $r$.
*   **Checagem do Servidor:** Verifica se $g^r \equiv C \pmod p$.

**Cenário 1 (Verificação do Conhecimento):**
*   **Desafio:** O servidor pede o valor de $s = (x + r) \pmod{p-1}$.
*   **Resposta do Provador:** Envia $s$.
*   **Checagem do Servidor:** Verifica se $g^s \equiv y \cdot C \pmod p$.
    *   *A matemática por trás:* $g^{x+r} = g^x \cdot g^r$. Como $g^x = y$ e $g^r = C$, então $g^{x+r} \equiv y \cdot C \pmod p$. O mod $(p-1)$ no expoente ocorre pelo Pequeno Teorema de Fermat.

---

## 3. A Vulnerabilidade: Quebra de *Soundness*

A integridade (*soundness*) de uma Prova de Conhecimento Zero depende da **imprevisibilidade do desafio**. O provador deve enviar o compromisso $C$ **antes** de saber qual será a pergunta.

A falha do desafio "Prove No Knowledge" reside na **previsibilidade do servidor**. Os desafios (Cenário 0 e Cenário 1) simplesmente se alternam sequencialmente ou podem ser previstos. Como o atacante sabe a pergunta *antes* de enviar $C$, ele pode atuar como um **Simulador**, forjando compromissos de trás para frente.

### O Exploit (Transcrição Maliciosa)

Como enganamos o servidor em cada cenário sem conhecer $x$?

*   **Para o Cenário 0 (Sabemos que o servidor pedirá $r$):**
    Apenas agimos honestamente, pois $x$ não é necessário.
    1. Escolhemos um $r$ aleatório.
    2. Enviamos $C = g^r \pmod p$.
    3. Quando solicitado, enviamos $r$.

*   **Para o Cenário 1 (Sabemos que o servidor pedirá $x+r$):**
    Aqui ocorre a falsificação matemática.
    1. Escolhemos um valor aleatório $r'$ que atuará como nossa resposta falsa.
    2. Precisamos que o servidor valide $g^{r'} \equiv y \cdot C \pmod p$.
    3. Isolamos $C$ para fabricar o compromisso perfeito: $C \equiv g^{r'} \cdot y^{-1} \pmod p$.
    4. Enviamos esse $C$ forjado na primeira etapa.
    5. Quando o servidor pedir $(x+r)$, enviamos simplesmente $r'$. A equação do servidor baterá perfeitamente.

O *solver* implementa um loop de 256 iterações que intercala as duas estratégias acima de acordo com o padrão do servidor.

---

## 4. Relação com OR-Proofs e Compromissos Independentes

O roteiro exige que a solução seja relacionada com provas OR. 

Em uma Prova de Conhecimento Zero do tipo "OR" (ex: provar que conheço $x_1$ OU $x_2$), o protocolo exige intencionalmente que você utilize a técnica do Simulador (a falsificação descrita acima) para o segredo que você **não** possui, e aja honestamente no segredo que possui.

**Por que o compromisso deve ser único/vinculado?**
Para que a prova OR seja segura, o protocolo força que o *desafio total* seja uma soma (ou hash, via heurística de Fiat-Shamir) atrelada aos dois compromissos simultaneamente.
Se o sistema permitir que compromissos sejam enviados e validados de forma totalmente **independente** (como no erro deste CTF), o atacante pode aplicar o Simulador em *todas* as instâncias. A independência dos compromissos quebra a amarração lógica que garante que o usuário sabe pelo menos um dos segredos, permitindo a autenticação com zero conhecimento real.
