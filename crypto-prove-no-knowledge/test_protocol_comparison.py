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
    def setUp(self):
        self.p = 23
        self.q = 11
        self.g = 2
        self.x = 7
        self.y = pow(self.g, self.x, self.p)

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


if __name__ == "__main__":
    unittest.main()
