# Divisão de Tarefas

Este documento registra, de forma resumida, quem ficou responsável por cada
frente do trabalho.

---

## Código Rust (servidor / simulação)

**Carol, Cauã, Eduardo**

Responsáveis pelo servidor vulnerável em Rust (`crypto-prove-no-knowledge/src/`):
protocolo Sigma (`test_a`, `test_b`, `process`), infraestrutura Docker e ajuste
dos parâmetros do desafio. São também as pessoas que vão **rodar a simulação ao
vivo durante a apresentação** (subir o serviço e executar o ataque).

## Testes

**Rafaela, Rafael, Gabriel**

Responsáveis pela suíte de testes automatizados (`test_protocol_comparison.py`) e
pela validação do verificador corrigido: transcrições honestas aceitas, ataque
passando no verificador vulnerável, ataque falhando quando o compromisso é
fixado, extração do testemunho e rejeição de entradas fora do domínio.

## Slides e roteiro

**Yuki, Laura, Antonio**

Responsáveis pela apresentação: slides, roteiro e explicação dos conceitos
(prova de conhecimento zero, protocolo Schnorr / Sigma, quebra de _soundness_,
relação com OR-proofs). São as pessoas que vão **explicar o desafio e a teoria
durante a apresentação**.

## Documentação no GitHub

**Ronan, Ayla**

Responsáveis pela documentação do repositório: `README.md`, organização dos
relatórios (`relatórios/`), `PROTOCOL_ANALYSIS.md` e `explicacao.md`, além de
manter o histórico do projeto no GitHub.
