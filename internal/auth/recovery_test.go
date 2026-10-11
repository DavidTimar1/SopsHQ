package auth

import (
	"strings"
	"testing"
)

func TestGenerateRecoveryCodesShapeAndUniqueness(t *testing.T) {
	plain, hashes, err := GenerateRecoveryCodes()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(plain) != recoveryCount || len(hashes) != recoveryCount {
		t.Fatalf("got %d plain / %d hashes, want %d each", len(plain), len(hashes), recoveryCount)
	}
	seen := map[string]bool{}
	for i, code := range plain {
		// Shape: groups of recoveryGroupLen joined by hyphens, alphabet only.
		groups := strings.Split(code, "-")
		if len(groups) != recoveryGroups {
			t.Fatalf("code %q has %d groups, want %d", code, len(groups), recoveryGroups)
		}
		for _, g := range groups {
			if len(g) != recoveryGroupLen {
				t.Fatalf("code %q group %q wrong length", code, g)
			}
			for _, r := range g {
				if !strings.ContainsRune(recoveryAlphabet, r) {
					t.Fatalf("code %q contains out-of-alphabet rune %q", code, r)
				}
			}
		}
		if seen[code] {
			t.Fatalf("duplicate code generated: %q", code)
		}
		seen[code] = true

		// The stored hash must verify the code and must not be the plaintext.
		if strings.Contains(hashes[i], code) {
			t.Fatalf("hash %q contains the plaintext code", hashes[i])
		}
		ok, err := MatchRecoveryCode(hashes[i], code)
		if err != nil || !ok {
			t.Fatalf("hash %d does not match its code: ok=%v err=%v", i, ok, err)
		}
	}
}

func TestHashRecoveryCodeIsSalted(t *testing.T) {
	a, err := HashRecoveryCode("abcd-2345-wxyz")
	if err != nil {
		t.Fatalf("hash a: %v", err)
	}
	b, err := HashRecoveryCode("abcd-2345-wxyz")
	if err != nil {
		t.Fatalf("hash b: %v", err)
	}
	if a == b {
		t.Fatalf("two hashes of the same code are identical -> not salted")
	}
	if !strings.HasPrefix(a, recoveryScheme+"$") {
		t.Fatalf("hash %q missing scheme prefix", a)
	}
}

func TestMatchRecoveryCodeNormalization(t *testing.T) {
	h, err := HashRecoveryCode("abcd-2345-wxyz")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	// Different display formatting of the same code must still match.
	for _, in := range []string{"abcd-2345-wxyz", "ABCD2345WXYZ", "abcd 2345 wxyz", "  AbCd-2345-WxYz  "} {
		ok, err := MatchRecoveryCode(h, in)
		if err != nil || !ok {
			t.Fatalf("variant %q: ok=%v err=%v, want match", in, ok, err)
		}
	}
	// A different code must not match.
	ok, _ := MatchRecoveryCode(h, "wxyz-2345-abcd")
	if ok {
		t.Fatalf("unrelated code matched")
	}
}

func TestMatchRecoveryCodeMalformed(t *testing.T) {
	if _, err := MatchRecoveryCode("not$a$valid", "x"); err != ErrMalformedHash {
		t.Fatalf("want ErrMalformedHash, got %v", err)
	}
	// A password hash must not be accepted as a recovery-code hash (different scheme).
	pw, _ := HashPassword("password123")
	if _, err := MatchRecoveryCode(pw, "anything"); err != ErrMalformedHash {
		t.Fatalf("password-scheme hash should be malformed for recovery, got %v", err)
	}
}

func TestConsumeRecoveryCodeSingleUse(t *testing.T) {
	plain, hashes, err := GenerateRecoveryCodes()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	target := plain[3]

	remaining, ok := ConsumeRecoveryCode(hashes, target)
	if !ok {
		t.Fatalf("first use of a valid code should succeed")
	}
	if len(remaining) != len(hashes)-1 {
		t.Fatalf("consume should drop exactly one hash: got %d, want %d", len(remaining), len(hashes)-1)
	}
	// The consumed code must no longer match in the remaining set.
	if _, ok := ConsumeRecoveryCode(remaining, target); ok {
		t.Fatalf("second use of the same code must fail")
	}
	// A different, still-present code must still work against the remaining set.
	other := plain[7]
	if _, ok := ConsumeRecoveryCode(remaining, other); !ok {
		t.Fatalf("an unused code should still be accepted")
	}
}

func TestConsumeRecoveryCodeRejectsEmptyAndUnknown(t *testing.T) {
	_, hashes, err := GenerateRecoveryCodes()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if _, ok := ConsumeRecoveryCode(hashes, ""); ok {
		t.Fatalf("empty code must not match")
	}
	if _, ok := ConsumeRecoveryCode(hashes, "zzzz-zzzz-zzzz"); ok {
		t.Fatalf("unknown code must not match")
	}
	if _, ok := ConsumeRecoveryCode(nil, "abcd-2345-wxyz"); ok {
		t.Fatalf("empty set must not match anything")
	}
}
