package main

import (
	"bytes"
	"runtime"
	"strings"
	"testing"
)

// TestValidateSetupPaths covers the pure path-validation rules: absolute paths, a
// non-empty service account, distinct data base and keybase root, and the /home/*
// refusal (bypassable with --force-home).
func TestValidateSetupPaths(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("exercises Linux absolute-path semantics; host filepath must be Linux")
	}
	tests := []struct {
		name      string
		prefix    string
		data      string
		keybase   string
		user      string
		forceHome bool
		wantErr   string // lowercased substring; "" means no error
	}{
		{"defaults ok", "/opt/sopshq", "/srv/sopshq", "/srv/sopshq-keys", "sopshq", false, ""},
		{"blank keybase ok", "/opt/sopshq", "/srv/sopshq", "", "sopshq", false, ""},
		{"relative prefix", "opt/sopshq", "/srv/sopshq", "/srv/sopshq-keys", "sopshq", false, "prefix must be an absolute"},
		{"relative data", "/opt/sopshq", "mnt/data", "/srv/sopshq-keys", "sopshq", false, "data directory must be an absolute"},
		{"relative keybase", "/opt/sopshq", "/srv/sopshq", "keys", "sopshq", false, "keybase root must be an absolute"},
		{"empty user", "/opt/sopshq", "/srv/sopshq", "/srv/sopshq-keys", "  ", false, "service account name must not be empty"},
		{"data equals keybase", "/opt/sopshq", "/srv/x", "/srv/x", "sopshq", false, "different"},
		{"data under home refused", "/opt/sopshq", "/home/carol/sopshq", "/srv/sopshq-keys", "sopshq", false, "refusing a data directory under /home"},
		{"keybase under home refused", "/opt/sopshq", "/srv/sopshq", "/home/carol/keys", "sopshq", false, "refusing a keybase root under /home"},
		{"home allowed with force", "/opt/sopshq", "/home/carol/sopshq", "/home/carol/keys", "sopshq", true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSetupPaths(tt.prefix, tt.data, tt.keybase, tt.user, tt.forceHome)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected an error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(strings.ToLower(err.Error()), tt.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

// TestDetectPackageManager checks the ordered selection and the install argv, using an
// injected lookup so it needs no real package manager present.
func TestDetectPackageManager(t *testing.T) {
	have := func(present ...string) func(string) bool {
		set := map[string]bool{}
		for _, p := range present {
			set[p] = true
		}
		return func(cmd string) bool { return set[cmd] }
	}
	tests := []struct {
		name     string
		have     func(string) bool
		wantName string
		wantArgv string // space-joined; "" means ok=false
	}{
		{"apt", have("apt-get"), "apt-get", "apt-get install -y acl"},
		{"dnf", have("dnf"), "dnf", "dnf install -y acl"},
		{"zypper", have("zypper"), "zypper", "zypper --non-interactive install acl"},
		{"pacman", have("pacman"), "pacman", "pacman -Sy --noconfirm acl"},
		{"yum", have("yum"), "yum", "yum install -y acl"},
		{"apt wins over dnf", have("dnf", "apt-get"), "apt-get", "apt-get install -y acl"},
		{"none", have(), "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm, ok := detectPackageManager(tt.have)
			if tt.wantArgv == "" {
				if ok {
					t.Fatalf("expected ok=false, got %+v", pm)
				}
				return
			}
			if !ok {
				t.Fatalf("expected a package manager, got none")
			}
			if pm.Name != tt.wantName {
				t.Fatalf("name = %q, want %q", pm.Name, tt.wantName)
			}
			if got := strings.Join(pm.Install, " "); got != tt.wantArgv {
				t.Fatalf("install argv = %q, want %q", got, tt.wantArgv)
			}
		})
	}
}

// TestRenderUnit verifies the embedded systemd unit renders with the plan's values and
// leaves NO placeholder behind.
func TestRenderUnit(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("exercises Linux absolute-path semantics; host filepath must be Linux")
	}
	plan := resolvePlan(setupOptions{
		Prefix: "/opt/sopshq", Data: "/srv/sopshq", Keybase: "/srv/sopshq-keys", User: "sopshq",
	})
	unit, err := renderUnit(plan)
	if err != nil {
		t.Fatalf("renderUnit: %v", err)
	}
	if strings.Contains(unit, "{{") || strings.Contains(unit, "@@") {
		t.Fatalf("rendered unit still has a placeholder:\n%s", unit)
	}
	for _, want := range []string{
		"Type=notify",
		"NotifyAccess=main",
		"RuntimeDirectory=sopshq",
		"RuntimeDirectoryMode=0700",
		"User=sopshq",
		"Group=sopshq",
		"ExecStart=/opt/sopshq/sopshq serve -config /srv/sopshq/config.jsonc",
		"WorkingDirectory=/srv/sopshq",
		"Environment=HOME=/srv/sopshq",
		"ProtectHome=yes",
		"ReadWritePaths=/srv/sopshq /srv/sopshq-keys",
	} {
		if !strings.Contains(unit, want) {
			t.Fatalf("unit missing %q:\n%s", want, unit)
		}
	}
}

// TestResolvePlanProtectHome checks the derived ProtectHome and ReadWritePaths values,
// including the --force-home (data/keys under a home) case that flips ProtectHome off.
func TestResolvePlanProtectHome(t *testing.T) {
	tests := []struct {
		name            string
		data            string
		keybase         string
		wantProtectHome string
		wantReadWrite   string
	}{
		{"neutral mount", "/srv/sopshq", "/srv/sopshq-keys", "yes", "/srv/sopshq /srv/sopshq-keys"},
		{"no keybase", "/srv/sopshq", "", "yes", "/srv/sopshq"},
		{"data under home", "/home/carol/sopshq", "/srv/sopshq-keys", "no", "/home/carol/sopshq /srv/sopshq-keys"},
		{"keybase under home", "/srv/sopshq", "/home/carol/keys", "no", "/srv/sopshq /home/carol/keys"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan := resolvePlan(setupOptions{Prefix: "/opt/sopshq", Data: tt.data, Keybase: tt.keybase, User: "sopshq"})
			if plan.ProtectHome != tt.wantProtectHome {
				t.Fatalf("ProtectHome = %q, want %q", plan.ProtectHome, tt.wantProtectHome)
			}
			if plan.ReadWrite != tt.wantReadWrite {
				t.Fatalf("ReadWrite = %q, want %q", plan.ReadWrite, tt.wantReadWrite)
			}
		})
	}
}

// TestSetKeybaseRootInConfig covers the idempotent config wiring: fill an empty value,
// leave a matching value, and flag (never change) a different existing value.
func TestSetKeybaseRootInConfig(t *testing.T) {
	const kb = "/srv/sopshq-keys"

	t.Run("fills empty", func(t *testing.T) {
		body := `{"keybase_root": "", "data_dir": "/x"}`
		out, changed, conflict := setKeybaseRootInConfig(body, kb)
		if !changed || conflict {
			t.Fatalf("changed=%v conflict=%v, want changed", changed, conflict)
		}
		if !strings.Contains(out, `"keybase_root": "`+kb+`"`) {
			t.Fatalf("keybase_root not set: %s", out)
		}
	})

	t.Run("already matching is a no-op", func(t *testing.T) {
		body := `{"keybase_root": "` + kb + `"}`
		out, changed, conflict := setKeybaseRootInConfig(body, kb)
		if changed || conflict {
			t.Fatalf("changed=%v conflict=%v, want no-op", changed, conflict)
		}
		if out != body {
			t.Fatalf("body changed: %s", out)
		}
	})

	t.Run("different value conflicts", func(t *testing.T) {
		body := `{"keybase_root": "/other/keys"}`
		out, changed, conflict := setKeybaseRootInConfig(body, kb)
		if changed || !conflict {
			t.Fatalf("changed=%v conflict=%v, want conflict", changed, conflict)
		}
		if out != body {
			t.Fatalf("conflict must not modify the body: %s", out)
		}
	})

	t.Run("empty keybase does nothing", func(t *testing.T) {
		body := `{"keybase_root": ""}`
		out, changed, conflict := setKeybaseRootInConfig(body, "")
		if changed || conflict || out != body {
			t.Fatalf("empty keybase should be a no-op")
		}
	})
}

// TestPrintFootprint verifies the footprint names every path setup created (the whole
// install prefix, the optional scan account and its sudoers file included) and points at
// uninstall.sh for removal instead of printing removal commands.
func TestPrintFootprint(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("exercises Linux absolute-path semantics; host filepath must be Linux")
	}
	plan := resolvePlan(setupOptions{
		Prefix: "/opt/sopshq", Data: "/srv/sopshq", Keybase: "/srv/sopshq-keys", User: "sopshq",
	})
	var buf bytes.Buffer
	printFootprint(&buf, plan)
	out := buf.String()

	for _, want := range []string{
		"/opt/sopshq (install prefix",
		"/srv/sopshq (data base",
		"/srv/sopshq-keys (keybase root)",
		"sopshq-scan",
		"/etc/sudoers.d/sopshq-permmap",
		"sudo ./uninstall.sh --dry-run",
		"sudo ./uninstall.sh\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("printFootprint output missing %q\n%s", want, out)
		}
	}
	for _, unwanted := range []string{"rm -rf", "userdel", "groupdel", "setfacl"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("printFootprint prints removal command %q; removal belongs to uninstall.sh\n%s", unwanted, out)
		}
	}

	plan.Keybase = ""
	buf.Reset()
	printFootprint(&buf, plan)
	if strings.Contains(buf.String(), "(keybase root)") {
		t.Errorf("printFootprint without a keybase root still names one\n%s", buf.String())
	}
}
