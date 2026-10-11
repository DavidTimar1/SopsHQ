package place

import "testing"

// The discovery deciders are PURE: they take observed facts as plain structs and
// return a plan. These tests exercise every case with constructed facts and NEVER
// touch the real environment, home directory, or any filesystem link - the risky
// setx/mklink/symlink effects live behind EnsureDiscovery and are not run here.

func TestDecideEnv(t *testing.T) {
	const want = "/keys/keys.txt"
	cases := []struct {
		name string
		f    envFacts
		plan discoveryPlan
	}{
		{"unset", envFacts{current: "", want: want}, planSet},
		{"correct", envFacts{current: want, currentExists: true, want: want}, planLeave},
		{"dangling", envFacts{current: "/gone/keys.txt", currentExists: false, want: want}, planSet},
		{"elsewhere-real", envFacts{current: "/other/keys.txt", currentExists: true, want: want}, planConflict},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got, _ := decideEnv(c.f); got != c.plan {
				t.Fatalf("decideEnv(%+v) = %v, want %v", c.f, got, c.plan)
			}
		})
	}
}

func TestDecideLink(t *testing.T) {
	const want = "/keys/keys.txt"
	cases := []struct {
		name string
		f    linkFacts
		plan discoveryPlan
	}{
		{"self-same", linkFacts{selfSame: true, want: want}, planLeave},
		{"absent", linkFacts{exists: false, want: want, path: "/home/.config/sops/age/keys.txt"}, planSet},
		{"correct", linkFacts{exists: true, target: want, targetExists: true, want: want}, planLeave},
		{"dangling", linkFacts{exists: true, target: "/gone/keys.txt", targetExists: false, want: want}, planSet},
		{"elsewhere-real", linkFacts{exists: true, target: "/other/keys.txt", targetExists: true, want: want}, planConflict},
		{"unreadable-target", linkFacts{exists: true, target: "", targetExists: true, want: want}, planLeave},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got, _ := decideLink(c.f); got != c.plan {
				t.Fatalf("decideLink(%+v) = %v, want %v", c.f, got, c.plan)
			}
		})
	}
}

// TestFillStatusVerdict checks the read-only verdict mapping used by the panel: the
// three operator-facing outcomes derived from the same deciders EnsureDiscovery uses.
func TestFillStatusVerdict(t *testing.T) {
	const want = "/keys/keys.txt"
	base := DiscoveryStatus{EnvName: envNameForTest, LinkKind: "symlink"}

	cases := []struct {
		name    string
		env     envFacts
		link    linkFacts
		verdict string
	}{
		{
			name:    "env-here",
			env:     envFacts{current: want, currentExists: true, want: want},
			link:    linkFacts{exists: false, want: want},
			verdict: VerdictFound,
		},
		{
			name:    "link-here-env-unset",
			env:     envFacts{current: "", want: want},
			link:    linkFacts{exists: true, target: want, targetExists: true, want: want},
			verdict: VerdictFound,
		},
		{
			name:    "nothing-wired",
			env:     envFacts{current: "", want: want},
			link:    linkFacts{exists: false, want: want},
			verdict: VerdictNotWired,
		},
		{
			name:    "env-conflict",
			env:     envFacts{current: "/other/keys.txt", currentExists: true, want: want},
			link:    linkFacts{exists: false, want: want},
			verdict: VerdictConflict,
		},
		{
			name:    "self-same-found",
			env:     envFacts{current: "", want: want},
			link:    linkFacts{selfSame: true, want: want},
			verdict: VerdictFound,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st := fillStatus(base, c.env, c.link)
			if st.Verdict != c.verdict {
				t.Fatalf("verdict = %q, want %q (%+v / %+v)", st.Verdict, c.verdict, c.env, c.link)
			}
		})
	}
}

// TestApplyEnsureRepairOnly proves the orchestration only runs an effect for a "set"
// plan: a correct env and a conflicting link both leave the effect UN-called, so a
// deliberate custom setup is never overwritten. The effects here are fakes; no real
// setx/mklink runs.
func TestApplyEnsureRepairOnly(t *testing.T) {
	const want = "/keys/keys.txt"
	envSet, linkSet := 0, 0
	eff := discoveryEffects{
		envName:  envNameForTest,
		linkKind: "symlink",
		setEnv:   func(string) error { envSet++; return nil },
		setLink:  func() error { linkSet++; return nil },
	}
	// env already correct -> leave; link points elsewhere -> conflict (leave).
	env := envFacts{current: want, currentExists: true, want: want}
	link := linkFacts{exists: true, target: "/other/keys.txt", targetExists: true, want: want}
	rep := applyEnsure(env, link, eff)
	if envSet != 0 || linkSet != 0 {
		t.Fatalf("repair-only violated: envSet=%d linkSet=%d", envSet, linkSet)
	}
	if rep.HasError() {
		t.Fatalf("unexpected error item: %+v", rep.Items)
	}
	if !rep.HasConflict() {
		t.Fatalf("expected a conflict item for the link: %+v", rep.Items)
	}
	if rep.Items[0].State != DiscoveryAlready {
		t.Fatalf("env item state = %q, want %q", rep.Items[0].State, DiscoveryAlready)
	}
	if rep.Items[1].State != DiscoveryConflict {
		t.Fatalf("link item state = %q, want %q", rep.Items[1].State, DiscoveryConflict)
	}

	// A missing env + absent link both get set exactly once.
	env = envFacts{current: "", want: want}
	link = linkFacts{exists: false, want: want, path: "/home/.config/sops/age/keys.txt"}
	rep = applyEnsure(env, link, eff)
	if envSet != 1 || linkSet != 1 {
		t.Fatalf("expected one set each: envSet=%d linkSet=%d", envSet, linkSet)
	}
	if rep.Items[0].State != DiscoveryCreated || rep.Items[1].State != DiscoveryCreated {
		t.Fatalf("expected both created: %+v", rep.Items)
	}
}

// envNameForTest is the fixed env label; it must match the per-OS envName constant
// but is defined here so the shared test does not depend on a build-tagged file.
const envNameForTest = "SOPS_AGE_KEY_FILE"

// TestDiscoveryBaseOK checks the effect-boundary validator directly: unsafe bases
// (shell metacharacters, cmd.exe specials `%`/`^`, empty) are refused; ordinary
// Windows and Linux keystore paths pass.
func TestDiscoveryBaseOK(t *testing.T) {
	bad := []string{
		"", "   ",
		`C:\k&calc.exe`, `C:\x&powershell -c bad`, `C:\k|calc`,
		`C:\k%USERPROFILE%\x`, `C:\k^x`, "/a$(reboot)", "/a`b`", "-rf/keys",
	}
	for _, b := range bad {
		if err := discoveryBaseOK(b); err == nil {
			t.Errorf("discoveryBaseOK(%q) = nil, want error", b)
		}
	}
	good := []string{`Z:\alice\personal\keys\alice\sops`, `C:\keys\sops`, "/etc/svc/keys", "/srv/secure keys"}
	for _, b := range good {
		if err := discoveryBaseOK(b); err != nil {
			t.Errorf("discoveryBaseOK(%q) = %v, want nil", b, err)
		}
	}
}

// TestEnsureDiscoveryRefusesUnsafeBase proves the SECURITY guarantee end to end: for
// an injectable KeyBase, EnsureDiscovery returns early with a single error item and
// therefore never reaches the setx / mklink / bashrc effects. It is isolation-safe
// precisely because the reject path runs no side effect (and touches no real env or
// home). The guard is identical on every OS, so this shared test asserts it wherever
// it runs.
func TestEnsureDiscoveryRefusesUnsafeBase(t *testing.T) {
	for _, b := range []string{`C:\k&calc.exe`, `C:\x&powershell`, `C:\k%USERPROFILE%`, `C:\k^x`} {
		rep := EnsureDiscovery(Opts{Base: b, Username: ""})
		if !rep.HasError() {
			t.Errorf("EnsureDiscovery(%q) did not report an error: %+v", b, rep.Items)
		}
		if len(rep.Items) != 1 || rep.Items[0].State != DiscoveryError {
			t.Errorf("EnsureDiscovery(%q) = %+v, want exactly one error item (no effects run)", b, rep.Items)
		}
	}
}
