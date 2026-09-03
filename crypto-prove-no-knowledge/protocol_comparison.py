#!/usr/bin/env python3
"""Compare o verificador vulneravel com um protocolo de Schnorr binario correto.

Este arquivo e independente do servidor Rust. Ele permite reproduzir, sem rede,
uma transcricao honesta, a falsificacao usada por ``solution.py`` e a extracao
do testemunho a partir de duas transcricoes aceitas com o mesmo compromisso.
"""

# Permite usar recursos mais modernos de anotações de tipos sem que elas
# precisem ser avaliadas imediatamente durante a execução.
from __future__ import annotations

# argparse: interpreta argumentos da linha de comando, como --json.
# json: permite imprimir o resultado no formato JSON.
import argparse
import json

# dataclass facilita a criação da estrutura Transcript.
# asdict converte uma dataclass em um dicionário.
from dataclasses import asdict, dataclass

# gcd calcula o máximo divisor comum e será usado para verificar
# se determinado número possui inverso modular.
from math import gcd

# Tipos utilizados nas anotações das funções.
from typing import Dict, Tuple


# frozen=True torna os objetos imutáveis depois de criados.
# Isso representa bem uma transcrição já concluída.
@dataclass(frozen=True)
class Transcript:
    """Uma transcricao Schnorr (t, e, s)."""

    # t: compromisso enviado pelo provador antes do desafio.
    commitment: int

    # e: desafio enviado pelo verificador; neste exemplo, 0 ou 1.
    challenge: int

    # s: resposta fornecida pelo provador.
    response: int


def verify_corrected(
    *, g: int, p: int, q: int, public_key: int, transcript: Transcript
) -> bool:
    """Verifica g^s = t * y^e (mod p), com e pertencendo a {0, 1}."""

    # O protocolo desta demonstração utiliza somente desafios binários.
    if transcript.challenge not in (0, 1):
        return False

    # A resposta é um expoente pertencente ao grupo de ordem q.
    # Por isso, deve estar no intervalo [0, q-1].
    if not 0 <= transcript.response < q:
        return False

    # O compromisso precisa representar um elemento válido de Z_p*.
    # O valor zero não pertence ao grupo multiplicativo.
    if not 1 <= transcript.commitment < p:
        return False

    # Calcula o lado esquerdo da equação de verificação:
    #
    #     g^s mod p
    lhs = pow(g, transcript.response, p)

    # Calcula o lado direito:
    #
    #     t * y^e mod p
    #
    # Quando e=0, y^e=1 e a verificação se reduz a g^s=t.
    # Quando e=1, a verificação se torna g^s=t*y.
    rhs = transcript.commitment * pow(public_key, transcript.challenge, p) % p

    # A transcrição é aceita somente se os dois lados forem iguais.
    return lhs == rhs


def make_honest_transcript(
    *, g: int, p: int, q: int, witness: int, nonce: int, challenge: int
) -> Tuple[int, Transcript]:
    """Cria y=g^x e uma transcricao honesta com t=g^r e s=r+e*x."""

    # Impede a criação de uma transcrição com desafio inválido.
    if challenge not in (0, 1):
        raise ValueError("o desafio binario deve ser 0 ou 1")

    # Reduz o segredo x e o nonce r módulo q, pois os expoentes
    # pertencem ao grupo de ordem q.
    witness %= q
    nonce %= q

    # Cria a chave pública:
    #
    #     y = g^x mod p
    #
    # O segredo x é chamado de "testemunho" no contexto de provas
    # de conhecimento zero.
    public_key = pow(g, witness, p)

    # Cria uma transcrição honesta do protocolo de Schnorr.
    transcript = Transcript(
        # Compromisso:
        #
        #     t = g^r mod p
        commitment=pow(g, nonce, p),

        # Desafio e recebido do verificador.
        challenge=challenge,

        # Resposta:
        #
        #     s = r + e*x mod q
        #
        # Se e=0, então s=r.
        # Se e=1, então s=r+x.
        response=(nonce + challenge * witness) % q,
    )

    # Retorna a chave pública e a transcrição criada.
    return public_key, transcript


def verify_vulnerable_a(*, g: int, p: int, commitment: int, response: int) -> bool:
    """Equacao de test_a: o provador ja sabe que o desafio e zero."""

    # Verifica a equação correspondente ao desafio e=0:
    #
    #     g^s = t mod p
    #
    # O problema é que o provador já sabe antecipadamente que
    # essa será a equação verificada.
    return pow(g, response, p) == commitment % p


def verify_vulnerable_b(
    *, g: int, p: int, public_key: int, commitment: int, response: int
) -> bool:
    """Equacao de test_b: o provador ja sabe que o desafio e um."""

    # Verifica a equação correspondente ao desafio e=1:
    #
    #     g^s = t*y mod p
    #
    # Novamente, o provador conhece antecipadamente a equação
    # que deverá satisfazer.
    return pow(g, response, p) == commitment * public_key % p


def make_malicious_transcripts(*, p: int, public_key: int) -> Tuple[Transcript, Transcript]:
    """Reproduz a falsificacao: t0=1 e t1=y^-1, ambas com resposta zero."""

    # Para o desafio e=0, o atacante escolhe:
    #
    #     t0 = 1
    #     s  = 0
    #
    # A verificação passa porque:
    #
    #     g^0 = 1 = t0
    challenge_zero = Transcript(commitment=1, challenge=0, response=0)

    # Para o desafio e=1, o atacante utiliza como compromisso
    # o inverso modular da chave pública:
    #
    #     t1 = y^-1 mod p
    #     s  = 0
    #
    # A verificação passa porque:
    #
    #     t1*y = y^-1*y = 1 = g^0 mod p
    #
    # Assim, o atacante responde corretamente sem conhecer x.
    challenge_one = Transcript(
        commitment=pow(public_key, -1, p), challenge=1, response=0
    )

    # Os dois compromissos são diferentes. Isso só funciona porque
    # o atacante sabe qual será o desafio antes de escolher t.
    return challenge_zero, challenge_one


def extract_witness(
    *,
    g: int,
    p: int,
    q: int,
    public_key: int,
    first: Transcript,
    second: Transcript,
) -> int:
    """Extrai x de duas transcricoes aceitas com o mesmo compromisso.

    De g^s0=t*y^e0 e g^s1=t*y^e1 obtemos
    x=(s1-s0)/(e1-e0) mod q. Para desafios 0 e 1, a divisao e trivial.
    """

    # A propriedade de extração exige duas respostas relacionadas ao
    # mesmo compromisso t. Com compromissos diferentes, não é possível
    # cancelar t ao comparar as equações.
    if first.commitment != second.commitment:
        raise ValueError("a extracao exige o mesmo compromisso nas duas transcricoes")

    # Os desafios precisam ser diferentes. Caso contrário, as duas
    # transcrições não fornecem informações independentes.
    if first.challenge == second.challenge:
        raise ValueError("a extracao exige desafios diferentes")

    # Antes da extração, confirma que ambas as transcrições são válidas
    # segundo o protocolo corrigido.
    if not verify_corrected(
        g=g, p=p, q=q, public_key=public_key, transcript=first
    ) or not verify_corrected(
        g=g, p=p, q=q, public_key=public_key, transcript=second
    ):
        raise ValueError("as duas transcricoes precisam ser aceitas")

    # Calcula:
    #
    #     e1 - e0 mod q
    #
    # Para desafios 0 e 1, essa diferença normalmente será 1 ou -1.
    challenge_delta = (second.challenge - first.challenge) % q

    # Uma divisão modular é realizada multiplicando pelo inverso modular.
    # Esse inverso só existe quando gcd(challenge_delta, q) = 1.
    if gcd(challenge_delta, q) != 1:
        raise ValueError("a diferenca dos desafios nao e invertivel modulo q")

    # As transcrições honestas seguem:
    #
    #     s0 = r + e0*x mod q
    #     s1 = r + e1*x mod q
    #
    # Subtraindo as respostas:
    #
    #     s1 - s0 = (e1 - e0)*x mod q
    #
    # Portanto:
    #
    #     x = (s1-s0)*(e1-e0)^-1 mod q
    witness = (
        (second.response - first.response)
        * pow(challenge_delta, -1, q)
    ) % q

    # Confirma que o valor extraído realmente corresponde à chave pública:
    #
    #     g^x mod p = y
    if pow(g, witness, p) != public_key:
        raise ValueError("a extracao nao produziu um testemunho para a chave publica")

    # Retorna o segredo x recuperado.
    return witness


def build_demo() -> Dict[str, object]:
    """Constroi uma demonstracao deterministica em um subgrupo de ordem prima."""

    # Em Z_23*, g=2 gera um subgrupo de ordem prima q=11.
    #
    # Embora Z_23* tenha 22 elementos, o elemento g=2 possui ordem 11.
    # Portanto, os expoentes do protocolo são calculados módulo q=11.
    p, q, g = 23, 11, 2

    # x=7 é o segredo conhecido pelo provador honesto.
    # r=3 é o nonce usado para construir o compromisso.
    witness, nonce = 7, 3

    # Cria a primeira transcrição honesta com desafio e=0.
    #
    # Como o nonce é 3:
    #     t = 2^3 mod 23 = 8
    #
    # Como e=0:
    #     s = 3 + 0*7 = 3 mod 11
    public_key, honest_zero = make_honest_transcript(
        g=g, p=p, q=q, witness=witness, nonce=nonce, challenge=0
    )

    # Cria uma segunda transcrição honesta com desafio e=1.
    #
    # O mesmo nonce produz o mesmo compromisso t=8.
    # A resposta agora será:
    #
    #     s = 3 + 1*7 = 10 mod 11
    _, honest_one = make_honest_transcript(
        g=g, p=p, q=q, witness=witness, nonce=nonce, challenge=1
    )

    # Cria as duas transcrições falsas:
    #
    #     e=0: t0=1 e s=0
    #     e=1: t1=y^-1 e s=0
    #
    # Elas utilizam compromissos diferentes.
    malicious_zero, malicious_one = make_malicious_transcripts(
        p=p, public_key=public_key
    )

    # Verifica se a transcrição honesta com e=0 é aceita.
    honest_zero_ok = verify_corrected(
        g=g, p=p, q=q, public_key=public_key, transcript=honest_zero
    )

    # Verifica se a transcrição honesta com e=1 também é aceita.
    honest_one_ok = verify_corrected(
        g=g, p=p, q=q, public_key=public_key, transcript=honest_one
    )

    # Testa a primeira falsificação contra a parte vulnerável
    # correspondente ao desafio e=0.
    vulnerable_zero_ok = verify_vulnerable_a(
        g=g,
        p=p,
        commitment=malicious_zero.commitment,
        response=malicious_zero.response,
    )

    # Testa a segunda falsificação contra a parte vulnerável
    # correspondente ao desafio e=1.
    vulnerable_one_ok = verify_vulnerable_b(
        g=g,
        p=p,
        public_key=public_key,
        commitment=malicious_one.commitment,
        response=malicious_one.response,
    )

    # O ataque nao consegue manter um unico compromisso ao trocar o desafio.

    # Pega o compromisso malicioso t0=1, preparado para e=0,
    # e tenta utilizá-lo contra o desafio e=1.
    #
    # Isso deverá falhar no verificador corrigido.
    fixed_zero_against_one = verify_corrected(
        g=g,
        p=p,
        q=q,
        public_key=public_key,
        transcript=Transcript(
            commitment=malicious_zero.commitment, challenge=1, response=0
        ),
    )

    # Pega o compromisso malicioso t1=y^-1, preparado para e=1,
    # e tenta utilizá-lo contra o desafio e=0.
    #
    # Isso também deverá falhar.
    fixed_one_against_zero = verify_corrected(
        g=g,
        p=p,
        q=q,
        public_key=public_key,
        transcript=Transcript(
            commitment=malicious_one.commitment, challenge=0, response=0
        ),
    )

    # Como as duas transcrições honestas possuem o mesmo compromisso,
    # desafios diferentes e são válidas, podemos recuperar o segredo x.
    extracted = extract_witness(
        g=g,
        p=p,
        q=q,
        public_key=public_key,
        first=honest_zero,
        second=honest_one,
    )

    # Organiza todos os resultados da demonstração em um dicionário.
    return {
        # Parâmetros públicos utilizados pelo protocolo.
        "parameters": {"p": p, "q": q, "g": g, "public_key": public_key},

        # O segredo x aparece aqui apenas para permitir a comparação
        # com o valor posteriormente extraído.
        "secret_used_only_by_honest_prover": witness,

        # Resultados relacionados ao comportamento honesto.
        "honest": {
            # asdict transforma cada Transcript em um dicionário.
            "challenge_zero": asdict(honest_zero),
            "challenge_one": asdict(honest_one),

            # True somente se as duas transcrições forem aceitas.
            "both_accepted": honest_zero_ok and honest_one_ok,

            # Segredo recuperado a partir das duas transcrições.
            "extracted_witness": extracted,
        },

        # Resultados relacionados ao ataque.
        "malicious": {
            "challenge_zero": asdict(malicious_zero),
            "challenge_one": asdict(malicious_one),

            # Demonstra que cada verificador vulnerável aceita a
            # transcrição especificamente preparada para ele.
            "vulnerable_verifier_accepts_both": vulnerable_zero_ok
            and vulnerable_one_ok,

            # Evidencia o ponto central da falha: o atacante utiliza
            # um compromisso diferente para cada desafio previsível.
            "commitments_are_different": (
                malicious_zero.commitment != malicious_one.commitment
            ),

            # Estes campos devem ser False, mostrando que um compromisso
            # preparado para um desafio não responde ao outro.
            "corrected_verifier_accepts_fixed_t0_for_e1": fixed_zero_against_one,
            "corrected_verifier_accepts_fixed_t1_for_e0": fixed_one_against_zero,
        },
    }


def print_demo(result: Dict[str, object]) -> None:
    """Mostra a comparacao em uma forma curta e legivel."""

    # Separa as partes do dicionário para facilitar o acesso.
    parameters = result["parameters"]
    honest = result["honest"]
    malicious = result["malicious"]

    # Mostra os parâmetros públicos do grupo.
    print("Parametros:", parameters)

    # Mostra as duas transcrições honestas.
    print("\nTranscricoes honestas com o mesmo compromisso:")
    print("  e=0:", honest["challenge_zero"])
    print("  e=1:", honest["challenge_one"])
    print("  ambas aceitas:", honest["both_accepted"])

    # O valor extraído deve ser igual ao segredo original x=7.
    print("  testemunho extraido:", honest["extracted_witness"])

    # Mostra as transcrições construídas pelo atacante.
    print("\nTranscricoes maliciosas usadas contra o verificador vulneravel:")
    print("  e=0:", malicious["challenge_zero"])
    print("  e=1:", malicious["challenge_one"])
    print(
        "  o verificador vulneravel aceita ambas:",
        malicious["vulnerable_verifier_accepts_both"],
    )

    # Apesar de ambas serem aceitas separadamente, seus compromissos
    # não são iguais.
    print("  os compromissos sao diferentes:", malicious["commitments_are_different"])

    # Mostra o resultado ao impedir que o atacante escolha um novo
    # compromisso depois de saber o desafio.
    print("\nQuando o compromisso e fixado antes do desafio:")
    print(
        "  t0=1 tambem responde e=1:",
        malicious["corrected_verifier_accepts_fixed_t0_for_e1"],
    )
    print(
        "  t1=y^-1 tambem responde e=0:",
        malicious["corrected_verifier_accepts_fixed_t1_for_e0"],
    )

    # Conclusão da demonstração: sem conhecer x, o atacante consegue
    # preparar uma resposta para apenas um dos dois desafios possíveis.
    print("  logo, sem conhecer x, essa estrategia cobre no maximo um desafio.")


def main() -> None:
    # Cria o interpretador dos argumentos da linha de comando.
    # O texto principal do arquivo é usado como descrição.
    parser = argparse.ArgumentParser(description=__doc__)

    # Permite executar:
    #
    #     python3 protocol_comparison.py --json
    #
    # para receber o resultado estruturado em JSON.
    parser.add_argument(
        "--json", action="store_true", help="imprime as transcricoes como JSON"
    )

    # Lê os argumentos fornecidos pelo usuário.
    args = parser.parse_args()

    # Executa toda a demonstração e reúne os resultados.
    result = build_demo()

    # Seleciona a forma de exibição.
    if args.json:
        # indent=2 deixa o JSON legível.
        # sort_keys=True ordena alfabeticamente as chaves.
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        # Exibe a explicação textual padrão.
        print_demo(result)


# Executa main() somente quando este arquivo é chamado diretamente.
# Isso evita a execução automática caso ele seja importado como módulo.
if __name__ == "__main__":
    main()
