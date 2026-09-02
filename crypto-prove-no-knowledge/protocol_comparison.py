#!/usr/bin/env python3
"""Compare o verificador vulneravel com um protocolo de Schnorr binario correto.

Este arquivo e independente do servidor Rust. Ele permite reproduzir, sem rede,
uma transcricao honesta, a falsificacao usada por ``solution.py`` e a extracao
do testemunho a partir de duas transcricoes aceitas com o mesmo compromisso.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from math import gcd
from typing import Dict, Tuple


@dataclass(frozen=True)
class Transcript:
    """Uma transcricao Schnorr (t, e, s)."""

    commitment: int
    challenge: int
    response: int


def verify_corrected(
    *, g: int, p: int, q: int, public_key: int, transcript: Transcript
) -> bool:
    """Verifica g^s = t * y^e (mod p), com e pertencendo a {0, 1}."""

    if transcript.challenge not in (0, 1):
        return False
    if not 0 <= transcript.response < q:
        return False
    if not 1 <= transcript.commitment < p:
        return False

    lhs = pow(g, transcript.response, p)
    rhs = transcript.commitment * pow(public_key, transcript.challenge, p) % p
    return lhs == rhs


def make_honest_transcript(
    *, g: int, p: int, q: int, witness: int, nonce: int, challenge: int
) -> Tuple[int, Transcript]:
    """Cria y=g^x e uma transcricao honesta com t=g^r e s=r+e*x."""

    if challenge not in (0, 1):
        raise ValueError("o desafio binario deve ser 0 ou 1")

    witness %= q
    nonce %= q
    public_key = pow(g, witness, p)
    transcript = Transcript(
        commitment=pow(g, nonce, p),
        challenge=challenge,
        response=(nonce + challenge * witness) % q,
    )
    return public_key, transcript


def verify_vulnerable_a(*, g: int, p: int, commitment: int, response: int) -> bool:
    """Equacao de test_a: o provador ja sabe que o desafio e zero."""

    return pow(g, response, p) == commitment % p


def verify_vulnerable_b(
    *, g: int, p: int, public_key: int, commitment: int, response: int
) -> bool:
    """Equacao de test_b: o provador ja sabe que o desafio e um."""

    return pow(g, response, p) == commitment * public_key % p


def make_malicious_transcripts(*, p: int, public_key: int) -> Tuple[Transcript, Transcript]:
    """Reproduz a falsificacao: t0=1 e t1=y^-1, ambas com resposta zero."""

    challenge_zero = Transcript(commitment=1, challenge=0, response=0)
    challenge_one = Transcript(
        commitment=pow(public_key, -1, p), challenge=1, response=0
    )
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

    if first.commitment != second.commitment:
        raise ValueError("a extracao exige o mesmo compromisso nas duas transcricoes")
    if first.challenge == second.challenge:
        raise ValueError("a extracao exige desafios diferentes")
    if not verify_corrected(
        g=g, p=p, q=q, public_key=public_key, transcript=first
    ) or not verify_corrected(
        g=g, p=p, q=q, public_key=public_key, transcript=second
    ):
        raise ValueError("as duas transcricoes precisam ser aceitas")

    challenge_delta = (second.challenge - first.challenge) % q
    if gcd(challenge_delta, q) != 1:
        raise ValueError("a diferenca dos desafios nao e invertivel modulo q")

    witness = (
        (second.response - first.response)
        * pow(challenge_delta, -1, q)
    ) % q
    if pow(g, witness, p) != public_key:
        raise ValueError("a extracao nao produziu um testemunho para a chave publica")
    return witness


def build_demo() -> Dict[str, object]:
    """Constroi uma demonstracao deterministica em um subgrupo de ordem prima."""

    # Em Z_23*, g=2 gera um subgrupo de ordem prima q=11.
    p, q, g = 23, 11, 2
    witness, nonce = 7, 3

    public_key, honest_zero = make_honest_transcript(
        g=g, p=p, q=q, witness=witness, nonce=nonce, challenge=0
    )
    _, honest_one = make_honest_transcript(
        g=g, p=p, q=q, witness=witness, nonce=nonce, challenge=1
    )
    malicious_zero, malicious_one = make_malicious_transcripts(
        p=p, public_key=public_key
    )

    honest_zero_ok = verify_corrected(
        g=g, p=p, q=q, public_key=public_key, transcript=honest_zero
    )
    honest_one_ok = verify_corrected(
        g=g, p=p, q=q, public_key=public_key, transcript=honest_one
    )
    vulnerable_zero_ok = verify_vulnerable_a(
        g=g,
        p=p,
        commitment=malicious_zero.commitment,
        response=malicious_zero.response,
    )
    vulnerable_one_ok = verify_vulnerable_b(
        g=g,
        p=p,
        public_key=public_key,
        commitment=malicious_one.commitment,
        response=malicious_one.response,
    )

    # O ataque nao consegue manter um unico compromisso ao trocar o desafio.
    fixed_zero_against_one = verify_corrected(
        g=g,
        p=p,
        q=q,
        public_key=public_key,
        transcript=Transcript(
            commitment=malicious_zero.commitment, challenge=1, response=0
        ),
    )
    fixed_one_against_zero = verify_corrected(
        g=g,
        p=p,
        q=q,
        public_key=public_key,
        transcript=Transcript(
            commitment=malicious_one.commitment, challenge=0, response=0
        ),
    )

    extracted = extract_witness(
        g=g,
        p=p,
        q=q,
        public_key=public_key,
        first=honest_zero,
        second=honest_one,
    )

    return {
        "parameters": {"p": p, "q": q, "g": g, "public_key": public_key},
        "secret_used_only_by_honest_prover": witness,
        "honest": {
            "challenge_zero": asdict(honest_zero),
            "challenge_one": asdict(honest_one),
            "both_accepted": honest_zero_ok and honest_one_ok,
            "extracted_witness": extracted,
        },
        "malicious": {
            "challenge_zero": asdict(malicious_zero),
            "challenge_one": asdict(malicious_one),
            "vulnerable_verifier_accepts_both": vulnerable_zero_ok
            and vulnerable_one_ok,
            "commitments_are_different": (
                malicious_zero.commitment != malicious_one.commitment
            ),
            "corrected_verifier_accepts_fixed_t0_for_e1": fixed_zero_against_one,
            "corrected_verifier_accepts_fixed_t1_for_e0": fixed_one_against_zero,
        },
    }


def print_demo(result: Dict[str, object]) -> None:
    """Mostra a comparacao em uma forma curta e legivel."""

    parameters = result["parameters"]
    honest = result["honest"]
    malicious = result["malicious"]

    print("Parametros:", parameters)
    print("\nTranscricoes honestas com o mesmo compromisso:")
    print("  e=0:", honest["challenge_zero"])
    print("  e=1:", honest["challenge_one"])
    print("  ambas aceitas:", honest["both_accepted"])
    print("  testemunho extraido:", honest["extracted_witness"])

    print("\nTranscricoes maliciosas usadas contra o verificador vulneravel:")
    print("  e=0:", malicious["challenge_zero"])
    print("  e=1:", malicious["challenge_one"])
    print(
        "  o verificador vulneravel aceita ambas:",
        malicious["vulnerable_verifier_accepts_both"],
    )
    print("  os compromissos sao diferentes:", malicious["commitments_are_different"])

    print("\nQuando o compromisso e fixado antes do desafio:")
    print(
        "  t0=1 tambem responde e=1:",
        malicious["corrected_verifier_accepts_fixed_t0_for_e1"],
    )
    print(
        "  t1=y^-1 tambem responde e=0:",
        malicious["corrected_verifier_accepts_fixed_t1_for_e0"],
    )
    print("  logo, sem conhecer x, essa estrategia cobre no maximo um desafio.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json", action="store_true", help="imprime as transcricoes como JSON"
    )
    args = parser.parse_args()

    result = build_demo()
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print_demo(result)


if __name__ == "__main__":
    main()
