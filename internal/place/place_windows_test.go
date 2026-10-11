//go:build windows

package place

import "testing"

// TestParseRegQueryValue exercises the `reg query` value parser with constructed
// output strings only. It NEVER runs reg.exe or reads the real registry, so it stays
// hermetic: the parser is a pure function of the text it is given.
func TestParseRegQueryValue(t *testing.T) {
	const name = "SOPS_AGE_KEY_FILE"
	cases := []struct {
		name string
		out  string
		want string
	}{
		{
			name: "reg-sz",
			out: "\r\nHKEY_CURRENT_USER\\Environment\r\n" +
				"    SOPS_AGE_KEY_FILE    REG_SZ    Z:\\keys\\alice\\sops\\keys.txt\r\n",
			want: `Z:\keys\alice\sops\keys.txt`,
		},
		{
			name: "reg-expand-sz",
			out:  "    SOPS_AGE_KEY_FILE    REG_EXPAND_SZ    C:\\keys\\sops\\keys.txt\r\n",
			want: `C:\keys\sops\keys.txt`,
		},
		{
			name: "value-with-spaces",
			out:  "    SOPS_AGE_KEY_FILE    REG_SZ    C:\\secure keys\\sops\\keys.txt\r\n",
			want: `C:\secure keys\sops\keys.txt`,
		},
		{
			name: "absent",
			out:  "\r\nHKEY_CURRENT_USER\\Environment\r\n    OTHER_VAR    REG_SZ    x\r\n",
			want: "",
		},
		{
			name: "not-a-string-type",
			out:  "    SOPS_AGE_KEY_FILE    REG_DWORD    0x1\r\n",
			want: "",
		},
		{
			name: "empty-output",
			out:  "",
			want: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := parseRegQueryValue(c.out, name); got != c.want {
				t.Fatalf("parseRegQueryValue = %q, want %q", got, c.want)
			}
		})
	}
}

// TestCurrentEnvKeyFileHermetic proves that with effectsDisabled set (the test
// regime established in main_test.go) currentEnvKeyFile reads the PROCESS env, never
// the registry, so the Windows discovery tests cannot touch the host's User-scope
// value.
func TestCurrentEnvKeyFileHermetic(t *testing.T) {
	t.Setenv(envName, `C:\injected\keys.txt`)
	if got := currentEnvKeyFile(); got != `C:\injected\keys.txt` {
		t.Fatalf("currentEnvKeyFile (effectsDisabled) = %q, want the injected env value", got)
	}
}
