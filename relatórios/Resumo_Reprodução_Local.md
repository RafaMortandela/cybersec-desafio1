# Relatório de Reprodução Local: Desafio "Prove No Knowledge" (UTCTF 2021)

Este documento descreve o procedimento passo a passo para a reprodução funcional e isolada do desafio de criptografia "Prove No Knowledge", incluindo as adaptações necessárias na infraestrutura original e no script de resolução, com as respectivas justificativas técnicas.

---

## 1. Obtenção dos Artefatos
O primeiro passo consistiu em clonar o repositório contendo os artefatos originais e acessar o diretório específico do desafio (acesse o github caso prefira clonar por ssh). 

```bash
git clone https://github.com/utisss/UTCTF-21.git
cd UTCTF-21/crypto-prove-no-knowledge
```

---

## 2. Adaptação do Ambiente Docker (O Servidor)

Ao tentar inicializar a infraestrutura utilizando o `docker-compose` fornecido, foram identificadas falhas de execução que impediam o contêiner de se manter ativo (`Exited`) ou geravam erros de permissão (`operation not permitted`). As seguintes alterações foram necessárias:


### Ajuste de Privilégios no `docker-compose.yml`
*   **O que mudou:** No arquivo `docker-compose.yml`, a flag de segurança `no-new-privileges: true` foi alterada para `no-new-privileges: false`.
*   **Por quê:** O servidor utiliza ferramentas internas de *sandboxing* para isolar as sessões dos jogadores. A política estrita do Docker, combinada com as regras do sistema operacional hospedeiro, estava bloqueando a tentativa do script interno de gerenciar esses privilégios. Desativar essa trava permitiu que a infraestrutura alocasse a sessão corretamente.
*   **Limitações que permanecem:** O contêiner está rodando localmente com uma superfície de permissões ligeiramente maior do que o configurado pelos organizadores originalmente, reduzindo o grau de isolamento (o que é aceitável para um ambiente de teste fechado).

**Comando executado para subir o servidor:**
```bash
docker-compose up -d --build
```

**Atenção:** rode `docker ps` para verificar se o container realmente inicializou sem erros.

---

## 3. Configuração do Ambiente do Exploit (O Cliente)

Para isolar a execução do script Python de solução, foi criado um ambiente virtual (`venv`). No entanto, a instalação da biblioteca exigida (`pwntools`) apresentou falhas de compilação.

### Instalação de dependências do sistema operacional
*   **O que mudou:** Foi necessário instalar os pacotes `pkg-config`, `libglib2.0-dev` e `python3-dev` diretamente no sistema hospedeiro.
*   **Por quê:** O instalador do pacote Python tentou compilar o módulo C da biblioteca `unicorn` do zero (pois não havia uma versão pré-compilada disponível para a versão mais recente do Python utilizada no ambiente local). A compilação falhou pela falta de bibliotecas base do C e das configurações de ponteiros no sistema. A instalação desses pacotes resolveu o erro de compilação do GCC.

**Comandos executados para o ambiente do solver:**
```bash
sudo apt update
sudo apt install pkg-config libglib2.0-dev python3-dev
python3 -m venv venv
source venv/bin/activate
pip install pwntools
```

**Observação:** tudo isso só foi realizado porque meu pc (Rafaela) com a versão mais atualizada do SO não apresentava compatibilidade com as versões do pwntools. Você pode tentar só rodar diretamente `pip install pwntools` dentro do venv e verificar se realmente é necessário instalar esses outros pacotes.

---

## 4. Execução da Transcrição Maliciosa

Com os dois ambientes (servidor e cliente) configurados, o passo final foi direcionar o ataque para o ambiente isolado.

### Alteração do alvo no `solution.py`
*   **O que mudou:** A URL original de conexão no script Python (apontando para o servidor do campeonato) foi substituída por `localhost` e a porta configurada no Docker (`4354`).
*   **Por quê:** Para validar a falha de *soundness* no ambiente localmente isolado que construímos. 

**Comando executado:**
```bash
python3 solution.py
```
**Resultado:** A comunicação interativa foi concluída com sucesso e a flag local foi impressa no console, validando a reprodução de ponta a ponta.

---

## 5. Vídeo de demonstração

Para facilitar a execução em outros computadores, gravei esse vídeo como passo a passo para rodar o sistema e resolver o desafio de acordo com a resolução do github.

[Clique aqui](https://youtube.com/shorts/01DkGjKlT1g?feature=share)
