# Resumo Descomplicado: Desafio "Prove No Knowledge" (UTCTF 2021)

Este documento apresenta uma visão geral do desafio focado em **Provas de Conhecimento Zero (Zero-Knowledge Proofs - ZKP)** e **Protocolos Sigma**, utilizando analogias simples para facilitar a compreensão antes de mergulhar na matemática.

---

## 1. O Conceito Base: A Prova de Conhecimento Zero

O objetivo principal de uma Prova de Conhecimento Zero é simples: **Provar que você sabe um segredo (como uma senha), mas sem revelar qual é esse segredo.**

Para resolver isso, a criptografia utiliza os **Protocolos Sigma** (como o de Schnorr). Eles funcionam em 3 etapas, que podem ser comparadas a um truque de mágica:

1. **O Compromisso (Commitment):** O provador coloca uma "caixa trancada" em cima da mesa. 
2. **O Desafio (Challenge):** O verificador joga uma moeda para o alto e faz um de dois pedidos:
   * *Cara (Desafio 0):* "Abra a caixa e mostre que ela é normal e está vazia."
   * *Coroa (Desafio 1):* "Faça um coelho sair de dentro da caixa fechada." (Isso só é possível se o provador souber o "segredo" da mágica).
3. **A Resposta (Response):** O provador atende ao pedido.

**Por que isso funciona?**
Se o provador for honesto (realmente sabe o segredo), ele consegue responder a **qualquer um** dos dois desafios. Mas se for um farsante, ele só consegue se preparar para um deles. Sem saber qual será o pedido do verificador, a chance de enganá-lo é de 50%. Se repetirmos o processo dezenas de vezes, a chance de o farsante acertar todas é praticamente nula.

---

## 2. O Defeito no Desafio (A Quebra de "Soundness")

Em segurança, chamamos de **Soundness (Integridade/Validade)** a garantia de que um mentiroso não consegue vencer o jogo. O desafio "Prove No Knowledge" possui uma falha crítica de implementação que destrói essa garantia.

O erro acontece porque **o verificador é previsível ou permite que o provador trapaceie na ordem das etapas.**

Imagine se o farsante soubesse a pergunta do verificador *antes* de colocar a caixa na mesa:
* Se ele sabe que pedirão a "caixa normal", ele traz uma caixa normal.
* Se ele sabe que pedirão o "coelho", ele traz uma caixa falsa já com um coelho dentro.

**Trazendo para a criptografia:** O que o ataque (exploit) faz é uma **engenharia reversa**. O atacante descobre ou manipula qual será o "Desafio", gera a "Resposta" primeiro e usa a matemática de trás para frente para fabricar um "Compromisso" falso que se encaixe perfeitamente. O servidor confere a matemática, vê que tudo bate, e libera o acesso sem que o atacante tenha a senha.

---

## 3. Conexão com a sua Apresentação

Para o trabalho da faculdade, os conceitos acima se traduzem nas seguintes etapas práticas:

* **Transcrição Honesta:** Demonstrar a matemática de um usuário legítimo (Gera Compromisso -> Recebe Desafio -> Calcula Resposta).
* **Transcrição Maliciosa (O Exploit):** Demonstrar a matemática do atacante. Mostrar como ele pega o desafio primeiro, inventa uma resposta e falsifica o compromisso. (Na teoria criptográfica, chamamos essa capacidade de falsificação de **Simulador**).
* **Relação com OR-Proofs:** Em provas avançadas onde se quer provar que sabe o Segredo A **OU** o Segredo B, o protocolo exige que o usuário "falsifique" (simule) a prova do segredo que ele não tem, e faça honestamente a do segredo que tem.
* **Por que o compromisso deve ser único (Independentes vs Vinculados):** O erro fatal desse CTF é permitir que compromissos sejam enviados de forma totalmente independente. Se as "caixas" não estiverem matematicamente amarradas (vinculadas), o atacante falsifica todas elas e invade o sistema.
