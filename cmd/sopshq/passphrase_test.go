package main

import "testing"

// TestEnvPassphraseTrimsTrailingWhitespace guards the unlock bug where a vault key
// supplied via SOPSHQ_VAULT_KEY (e.g. from a pasted value or a CRLF source) carried
// a trailing carriage return / newline / space. An untrimmed
// value derives a different vault key than the same key typed at the prompt (which
// the interactive readers trim), so unlock failed with "wrong passphrase" for the
// correct key. envVaultKey must trim trailing whitespace to match the typed path.
func TestEnvPassphraseTrimsTrailingWhitespace(t *testing.T) {
	cases := []struct {
		name string
		set  string
		want string
		ok   bool
	}{
		{"plain", "swordfish", "swordfish", true},
		{"trailing CR", "swordfish\r", "swordfish", true},
		{"trailing CRLF", "swordfish\r\n", "swordfish", true},
		{"trailing LF", "swordfish\n", "swordfish", true},
		{"trailing spaces and tabs", "swordfish \t", "swordfish", true},
		{"interior spaces kept", "two words", "two words", true},
		{"only whitespace -> unset", "\r\n", "", false},
		{"empty -> unset", "", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("SOPSHQ_VAULT_KEY", c.set)
			got, ok := envVaultKey()
			if ok != c.ok || got != c.want {
				t.Fatalf("envVaultKey() = %q,%v; want %q,%v", got, ok, c.want, c.ok)
			}
		})
	}
}
