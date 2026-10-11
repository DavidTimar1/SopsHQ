package main

import (
	"bytes"
	"crypto/mldsa"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sopshq/internal/update"
)

// fakeRelease sets up a fake gh and the state folder it serves: the draft's description
// (view.json), its SHA256SUMS, and records of what publish did (log, uploaded.sig,
// published).
type fakeRelease struct {
	state string
	seed  string
	key   *mldsa.PrivateKey
}

const fakeGHScript = `#!/bin/sh
echo "$*" >> "$FAKE_GH_STATE/log"
case "$1 $2" in
"release view") cat "$FAKE_GH_STATE/view.json" ;;
"release download")
  dir=
  while [ $# -gt 0 ]; do [ "$1" = "--dir" ] && dir="$2"; shift; done
  cp "$FAKE_GH_STATE/SHA256SUMS" "$dir/SHA256SUMS" ;;
"release upload") cp "$4" "$FAKE_GH_STATE/uploaded.sig"; [ "$(basename "$4")" = "SHA256SUMS.sig" ] || exit 7 ;;
"release edit") echo published > "$FAKE_GH_STATE/published" ;;
*) exit 9 ;;
esac
`

// newFakeRelease builds a draft with the given SHA256SUMS version, draft flag and assets.
func newFakeRelease(t *testing.T, sumsVersion string, draft bool, assets []string) *fakeRelease {
	t.Helper()
	sk, err := update.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	gh := filepath.Join(state, "gh")
	if err := os.WriteFile(gh, []byte(fakeGHScript), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_GH_STATE", state)
	oldGH, oldKeys := ghBinary, embeddedKeys
	ghBinary = func() string { return gh }
	embeddedKeys = func() (update.Keys, error) { return update.Keys{Primary: sk.PublicKey()}, nil }
	t.Cleanup(func() { ghBinary, embeddedKeys = oldGH, oldKeys })

	sums := update.FormatSums(sumsVersion, map[string]string{
		"sopshq-linux-amd64":       strings.Repeat("a", 64),
		"sopshq-windows-amd64.exe": strings.Repeat("b", 64),
	})
	if err := os.WriteFile(filepath.Join(state, "SHA256SUMS"), sums, 0o644); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, a := range assets {
		names = append(names, `{"name":"`+a+`"}`)
	}
	view := `{"tagName":"v0.83.0","isDraft":` + map[bool]string{true: "true", false: "false"}[draft] + `,"assets":[` + strings.Join(names, ",") + `]}`
	if err := os.WriteFile(filepath.Join(state, "view.json"), []byte(view), 0o644); err != nil {
		t.Fatal(err)
	}
	seedFile := filepath.Join(t.TempDir(), "seed.hex")
	if err := os.WriteFile(seedFile, []byte(update.SeedHex(sk)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &fakeRelease{state: state, seed: seedFile, key: sk}
}

var draftAssets = []string{"sopshq-linux-amd64", "sopshq-windows-amd64.exe", "SHA256SUMS"}

func (f *fakeRelease) publish(tag string, out *bytes.Buffer) error {
	env := func(k string) string {
		if k == update.EnvRepo {
			return "owner/repo"
		}
		return ""
	}
	return run([]string{"publish", "-tag", tag, "-seed", f.seed}, out, env)
}

func (f *fakeRelease) log() string {
	b, _ := os.ReadFile(filepath.Join(f.state, "log"))
	return string(b)
}

func (f *fakeRelease) exists(name string) bool {
	_, err := os.Stat(filepath.Join(f.state, name))
	return err == nil
}

func TestPublishSignsUploadsAndPublishesADraft(t *testing.T) {
	f := newFakeRelease(t, "0.83.0", true, draftAssets)
	var out bytes.Buffer
	if err := f.publish("v0.83.0", &out); err != nil {
		t.Fatalf("publish: %v", err)
	}
	sig, err := os.ReadFile(filepath.Join(f.state, "uploaded.sig"))
	if err != nil {
		t.Fatalf("no signature was uploaded: %v", err)
	}
	sums, _ := os.ReadFile(filepath.Join(f.state, "SHA256SUMS"))
	if s, err := update.VerifySums(update.Keys{Primary: f.key.PublicKey()}, sums, sig); err != nil || s.Version != "0.83.0" {
		t.Fatalf("the uploaded signature does not verify: %v", err)
	}
	if !f.exists("published") {
		t.Fatal("the draft was not published")
	}
	log := f.log()
	for _, want := range []string{"release view v0.83.0 --repo owner/repo", "release download v0.83.0", "release upload v0.83.0", "release edit v0.83.0 --repo owner/repo --draft=false"} {
		if !strings.Contains(log, want) {
			t.Errorf("gh was never run as %q; log:\n%s", want, log)
		}
	}
	seed, _ := os.ReadFile(f.seed)
	if strings.Contains(out.String(), strings.TrimSpace(string(seed))) || strings.Contains(log, strings.TrimSpace(string(seed))) {
		t.Fatal("the seed appeared in the output or in a gh command line")
	}
}

func TestPublishRefusesAndChangesNothing(t *testing.T) {
	cases := map[string]struct {
		sumsVersion string
		draft       bool
		assets      []string
		tag         string
		want        string
	}{
		"version in SHA256SUMS differs from the tag": {"0.83.0", true, draftAssets, "v0.83.0", ""},
		"release is not a draft":                     {"0.83.0", false, draftAssets, "v0.83.0", "not a draft"},
		"release already has a signature":            {"0.83.0", true, append([]string{"SHA256SUMS.sig"}, draftAssets...), "v0.83.0", "already has"},
		"sums lists an asset the draft lacks":        {"0.83.0", true, []string{"SHA256SUMS"}, "v0.83.0", "no such asset"},
		"no SHA256SUMS in the draft":                 {"0.83.0", true, []string{"sopshq-linux-amd64"}, "v0.83.0", "no SHA256SUMS"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFakeRelease(t, c.sumsVersion, c.draft, c.assets)
			tag := c.tag
			if strings.HasPrefix(name, "version") {
				// The draft is for v0.83.0 but the operator names another tag whose
				// SHA256SUMS says 0.83.0.
				tag = "v0.84.0"
			}
			var out bytes.Buffer
			err := f.publish(tag, &out)
			if err == nil {
				t.Fatal("publish succeeded, want a refusal")
			}
			if c.want != "" && !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want it to mention %q", err, c.want)
			}
			if f.exists("uploaded.sig") || f.exists("published") {
				t.Fatalf("something was uploaded or published despite the refusal: %v", err)
			}
		})
	}
}

func TestPublishRefusesASeedMatchingNeitherKeyBeforeAnyNetworkCall(t *testing.T) {
	f := newFakeRelease(t, "0.83.0", true, draftAssets)
	other, _ := update.GenerateKey()
	embeddedKeys = func() (update.Keys, error) {
		return update.Keys{Primary: other.PublicKey()}, nil
	}
	var out bytes.Buffer
	err := f.publish("v0.83.0", &out)
	if err == nil || !strings.Contains(err.Error(), "matches neither") {
		t.Fatalf("err = %v, want the neither-key refusal", err)
	}
	if f.exists("log") {
		t.Fatalf("gh was run before the key check:\n%s", f.log())
	}
}

func TestPublishRequiresTagSeedAndRepo(t *testing.T) {
	f := newFakeRelease(t, "0.83.0", true, draftAssets)
	var out bytes.Buffer
	none := func(string) string { return "" }
	for name, args := range map[string][]string{
		"bad tag":   {"publish", "-tag", "latest", "-seed", f.seed},
		"no seed":   {"publish", "-tag", "v0.83.0"},
		"no repo":   {"publish", "-tag", "v0.83.0", "-seed", f.seed},
		"bad repo":  {"publish", "-tag", "v0.83.0", "-seed", f.seed, "-repo", "-x/y"},
		"seed path": {"publish", "-tag", "v0.83.0", "-seed", filepath.Join(f.state, "absent"), "-repo", "o/r"},
	} {
		if err := run(args, &out, none); err == nil {
			t.Errorf("%s: publish accepted", name)
		}
	}
	if f.exists("log") {
		t.Fatal("gh ran for an invalid invocation")
	}
}
