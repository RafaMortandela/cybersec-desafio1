import unittest

from protocol_comparison import (
    Transcript,
    build_demo,
    extract_witness,
    make_honest_transcript,
    make_malicious_transcripts,
    verify_corrected,
    verify_vulnerable_a,
    verify_vulnerable_b,
)


class ProtocolComparisonTests(unittest.TestCase):

    # Define os parametros matematicos basicos que serao usados nos testes

    def setUp(self):
        self.p = 23
        self.q = 11
        self.g = 2
        self.x = 7
        self.y = pow(self.g, self.x, self.p)

    # Valida o fluxo de um provador honesto e o soundness, gerando duas transcricoes honestas:
    # (para e=0, e=1), utilizando o mesmo nonce inicial.
    # O resultado esperado é aceitar ambas as transcicoes de forma independente. A funcao de
    # extracao tambem deve conseguir deduzir a chave privada x = 7 cruzando as respostas.

    def test_honest_transcripts_are_accepted_and_extract_the_witness(self):
        _, transcript_zero = make_honest_transcript(
            g=self.g,
            p=self.p,
            q=self.q,
            witness=self.x,
            nonce=3,
            challenge=0,
        )
        _, transcript_one = make_honest_transcript(
            g=self.g,
            p=self.p,
            q=self.q,
            witness=self.x,
            nonce=3,
            challenge=1,
        )

        self.assertTrue(
            verify_corrected(
                g=self.g,
                p=self.p,
                q=self.q,
                public_key=self.y,
                transcript=transcript_zero,
            )
        )
        self.assertTrue(
            verify_corrected(
                g=self.g,
                p=self.p,
                q=self.q,
                public_key=self.y,
                transcript=transcript_one,
            )
        )
        self.assertEqual(
            self.x,
            extract_witness(
                g=self.g,
                p=self.p,
                q=self.q,
                public_key=self.y,
                first=transcript_zero,
                second=transcript_one,
            ),
        )

    # Comprova matematicamente a falha do servidor, criando transicoes maliciosas onde o
    # provador forja o compromisso de tras para frente, sem conhecer a chave privada.
    # Resultado esperado: ambas as transcricoes falsas devem passar pelas funcoes verify,
    # confirmando que o sistema original é falho.

    def test_malicious_transcripts_pass_the_two_vulnerable_checks(self):
        malicious_zero, malicious_one = make_malicious_transcripts(
            p=self.p, public_key=self.y
        )

        self.assertTrue(
            verify_vulnerable_a(
                g=self.g,
                p=self.p,
                commitment=malicious_zero.commitment,
                response=malicious_zero.response,
            )
        )
        self.assertTrue(
            verify_vulnerable_b(
                g=self.g,
                p=self.p,
                public_key=self.y,
                commitment=malicious_one.commitment,
                response=malicious_one.response,
            )
        )

    # Prova que a correcao do protocolo neutraliza o ataque, utilizando o 
    # verificador corrigido para tentar burlar o desafio 0, mas respondendo ao
    # desafio 1 e vice-versa.
    # O resultado esperado é o verificador corrigido rejeitar as duas tentativas,
    # retornando False, pois a falsificacao so sobrevive se prever o desafio exato.

    def test_malicious_strategy_fails_when_one_commitment_is_fixed(self):
        malicious_zero, malicious_one = make_malicious_transcripts(
            p=self.p, public_key=self.y
        )

        self.assertFalse(
            verify_corrected(
                g=self.g,
                p=self.p,
                q=self.q,
                public_key=self.y,
                transcript=Transcript(malicious_zero.commitment, 1, 0),
            )
        )
        self.assertFalse(
            verify_corrected(
                g=self.g,
                p=self.p,
                q=self.q,
                public_key=self.y,
                transcript=Transcript(malicious_one.commitment, 0, 0),
            )
        )

    # Garante a integridade da funcao matematica de extracao, tentando extrair a chave privada
    # fornecendo dias transcricoes maliciosas que possuem compromissos diferentes.
    # Resultado esperado: a funcao deve abortar a operacao e levantar um erro "ValueError" com
    # a mensagem, provando que a quebra algebrica é impossível sem um compromisso único.

    def test_extractor_rejects_two_different_commitments(self):
        malicious_zero, malicious_one = make_malicious_transcripts(
            p=self.p, public_key=self.y
        )

        with self.assertRaisesRegex(ValueError, "mesmo compromisso"):
            extract_witness(
                g=self.g,
                p=self.p,
                q=self.q,
                public_key=self.y,
                first=malicious_zero,
                second=malicious_one,
            )

    # Realiza um teste de integração completo do fluxo contido em protocol_comparison.py,
    # chamando a função build_demo() e analisando o dicionário de resultados gerado.
    # Resultado esperado: transcrições honestas são aceitas, o servidor vulnerável é enganado,
    # os compromissos maliciosos divergem e o verificador corrigido bloqueia os ataques.  

    def test_full_demo_keeps_expected_security_properties(self):
        demo = build_demo()

        self.assertTrue(demo["honest"]["both_accepted"])
        self.assertTrue(demo["malicious"]["vulnerable_verifier_accepts_both"])
        self.assertTrue(demo["malicious"]["commitments_are_different"])
        self.assertFalse(
            demo["malicious"]["corrected_verifier_accepts_fixed_t0_for_e1"]
        )
        self.assertFalse(
            demo["malicious"]["corrected_verifier_accepts_fixed_t1_for_e0"]
        )

    # Testa as defesas do verificador corrigido contra entradas fora do domínio matemático 
    # esperado, injetando propositalmente desafios que não são binários, respostas iguais
    # ou maiores que a ordem q, e compromissos fora do intervalo modular [1, p).
    # Resultado esperado: o verificador corrigido deve detectar anomalias e rejeitar todas
    # as transcrições, retornando False.

    def test_invalid_inputs_are_rejected(self):
        """O verificador corrigido deve rejeitar entradas fora do domínio esperado."""
        public_key = self.y

        # Desafio fora de {0, 1}: montamos o Transcript direto no construtor,
        # pois make_honest_transcript já valida e barraria isso antes da hora.
        for bad_challenge in (-1, 2, 5):
            transcript = Transcript(commitment=1, challenge=bad_challenge, response=0)
            self.assertFalse(
                verify_corrected(
                    g=self.g, p=self.p, q=self.q,
                    public_key=public_key, transcript=transcript,
                )
            )

        # Resposta fora do intervalo [0, q)
        transcript_bad_response = Transcript(commitment=1, challenge=0, response=self.q)
        self.assertFalse(
            verify_corrected(
                g=self.g, p=self.p, q=self.q,
                public_key=public_key, transcript=transcript_bad_response,
            )
        )

        # Compromisso fora do intervalo [1, p)
        for bad_commitment in (0, self.p):
            transcript_bad_commitment = Transcript(
                commitment=bad_commitment, challenge=0, response=0
            )
            self.assertFalse(
                verify_corrected(
                    g=self.g, p=self.p, q=self.q,
                    public_key=public_key, transcript=transcript_bad_commitment,
                )
            )

    # Prova que a lógica do protocolo não funciona apenas para os número do setUp, mas 
    # para qualquer grupo válido, executando o fluxo honesto e de extração contra três 
    # conjuntos distintos de parâmetros (p, q, g), validando antes que o gerador realmente
    # possui ordem q.
    # Resultado esperado: para todos os subgrupos, as transcrições devem ser validadas e a
    # extração da chave privada deve ser precisa.

    def test_random_parameters(self):
        """Roda os mesmos checks honestos com alguns primos pequenos diferentes."""
        # Cada tripla (p, q, g) abaixo é fixa e pré-validada: g tem ordem q
        # dentro do grupo mod p. Isso evita "testes instáveis" que passariam
        # ou falhariam dependendo de um sorteio aleatório de g.
        casos = [
            (23, 11, 2),
            (23, 11, 4),
            (47, 23, 2),
        ]

        for p, q, g in casos:
            with self.subTest(p=p, q=q, g=g):
                self.assertEqual(pow(g, q, p), 1, "g precisa ter ordem q mod p")

                witness = 3
                nonce = 4

                public_key, honest_zero = make_honest_transcript(
                    g=g, p=p, q=q, witness=witness, nonce=nonce, challenge=0
                )
                _, honest_one = make_honest_transcript(
                    g=g, p=p, q=q, witness=witness, nonce=nonce, challenge=1
                )

                self.assertTrue(
                    verify_corrected(
                        g=g, p=p, q=q, public_key=public_key, transcript=honest_zero
                    )
                )
                self.assertTrue(
                    verify_corrected(
                        g=g, p=p, q=q, public_key=public_key, transcript=honest_one
                    )
                )

                extracted = extract_witness(
                    g=g, p=p, q=q, public_key=public_key,
                    first=honest_zero, second=honest_one,
                )
                self.assertEqual(witness, extracted)

        # Protege a matemática da extração contra dados corrompidos, fornecendo uma 
        # transcrição honesta e uma transcrição corrompida (resposta igual a q).
        # Resultado esperado: identifica que uma das transcrições não é matematicamente válida
        # e levanta um ValueError antes de tentar resolver as equações.

    def test_extractor_fails_on_invalid_transcript(self):
        """O extrator deve levantar erro se uma das transcrições não é aceita."""
        _, honest_zero = make_honest_transcript(
            g=self.g, p=self.p, q=self.q, witness=self.x, nonce=3, challenge=0
        )
        # Segunda transcrição corrompida: resposta fora do intervalo válido,
        # construída direto (Transcript é imutável, não dá pra "quebrar" depois).
        bad_second = Transcript(
            commitment=honest_zero.commitment, challenge=1, response=self.q
        )

        with self.assertRaises(ValueError):
            extract_witness(
                g=self.g, p=self.p, q=self.q, public_key=self.y,
                first=honest_zero, second=bad_second,
            )


if __name__ == "__main__":
    unittest.main()
