package web

import (
	"html/template"
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// Form-field identity rules for the admin panel templates. A browser or password
// manager decides what to offer to save from the field type, its autocomplete token
// and the fields around it, so these rules keep every secret that is not the
// operator's own site login out of password-manager reach, and keep every field
// addressable (unique id, programmatic label).

var (
	// tmplAction matches a template action; it is replaced by a marker so the HTML
	// around it can be scanned as plain text.
	tmplAction = regexp.MustCompile(`(?s)\{\{.*?\}\}`)
	fieldTag   = regexp.MustCompile(`(?s)<(input|textarea|select)\b((?:[^>"']|"[^"]*"|'[^']*')*)>`)
	attrPair   = regexp.MustCompile(`([A-Za-z][A-Za-z0-9_:-]*)(?:\s*=\s*("[^"]*"|'[^']*'|[^\s>"']+))?`)
	labelFor   = regexp.MustCompile(`(?s)<label\b(?:[^>"']|"[^"]*"|'[^']*')*?\bfor="([^"]*)"`)
)

// loginPages are the only templates allowed to present a site login to a browser.
var loginPages = map[string]bool{"login.html": true, "setup.html": true}

// siteLoginTokens are the autocomplete tokens that tell a browser a field is a site login.
var siteLoginTokens = map[string]bool{"username": true, "current-password": true, "new-password": true}

type fieldAttrs map[string]string

func (a fieldAttrs) has(k string) bool { _, ok := a[k]; return ok }

func (a fieldAttrs) classes() map[string]bool {
	m := map[string]bool{}
	for _, c := range strings.Fields(a["class"]) {
		m[c] = true
	}
	return m
}

func parseAttrs(s string) fieldAttrs {
	a := fieldAttrs{}
	for _, m := range attrPair.FindAllStringSubmatch(s, -1) {
		v := strings.Trim(m[2], `"'`)
		a[strings.ToLower(m[1])] = v
	}
	return a
}

// checkFormFields returns one message per rule a template source breaks. page is the
// page file name (login.html), which decides whether a site login is allowed.
func checkFormFields(page, src string) []string {
	src = tmplAction.ReplaceAllString(src, "@@")
	var bad []string
	labels := map[string]bool{}
	for _, m := range labelFor.FindAllStringSubmatch(src, -1) {
		labels[m[1]] = true
	}
	seen := map[string]bool{}
	for _, m := range fieldTag.FindAllStringSubmatch(src, -1) {
		kind, a := m[1], parseAttrs(m[2])
		typ := strings.ToLower(a["type"])
		if kind == "input" && (typ == "hidden" || typ == "submit" || typ == "button") {
			continue
		}
		id := a["id"]
		desc := kind + " name=" + a["name"] + " id=" + id
		if id == "" {
			bad = append(bad, page+": no id on "+desc)
		} else if seen[id] {
			bad = append(bad, page+": duplicate id on "+desc)
		}
		seen[id] = true
		if !labels[id] && a["aria-label"] == "" && a["aria-labelledby"] == "" {
			bad = append(bad, page+": no label for or aria-label on "+desc)
		}
		if typ == "password" && !loginPages[page] {
			bad = append(bad, page+": type=password outside login and setup on "+desc)
		}
		for _, tok := range strings.Fields(strings.ToLower(a["autocomplete"])) {
			if siteLoginTokens[tok] && !loginPages[page] {
				bad = append(bad, page+": autocomplete "+tok+" outside login and setup on "+desc)
			}
		}
		if a.classes()["secret-field"] {
			bad = append(bad, secretFieldProblems(page, desc, kind, typ, a)...)
		}
	}
	return bad
}

// secretFieldProblems checks one field marked secret-field against the secret rules.
func secretFieldProblems(page, desc, kind, typ string, a fieldAttrs) []string {
	var bad []string
	if kind == "input" && typ != "text" {
		bad = append(bad, page+": secret field is not type=text: "+desc)
	}
	if a["autocomplete"] != "off" {
		bad = append(bad, page+": secret field without autocomplete=off: "+desc)
	}
	if a["autocapitalize"] != "off" || a["autocorrect"] != "off" || a["spellcheck"] != "false" {
		bad = append(bad, page+": secret field without autocapitalize/autocorrect off and spellcheck false: "+desc)
	}
	if !a.has("data-1p-ignore") {
		bad = append(bad, page+": secret field without data-1p-ignore: "+desc)
	}
	for _, k := range []string{"name", "id", "placeholder"} {
		v := strings.ToLower(a[k])
		if strings.Contains(v, "pass") || strings.Contains(v, "pwd") {
			bad = append(bad, page+": secret field "+k+" names a password: "+desc)
		}
	}
	return bad
}

// TestFormFieldIdentity parses every shipped page template with the layout, then scans
// the source of each page for the field rules above.
func TestFormFieldIdentity(t *testing.T) {
	layout, err := fs.ReadFile(tmplFS, "templates/layout.html")
	if err != nil {
		t.Fatalf("read layout: %v", err)
	}
	pages, err := fs.Glob(tmplFS, "templates/pages/*.html")
	if err != nil || len(pages) == 0 {
		t.Fatalf("no page templates found: %v", err)
	}
	for _, p := range pages {
		name := p[strings.LastIndex(p, "/")+1:]
		page, err := fs.ReadFile(tmplFS, p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		base, err := template.New("layout").Funcs(funcs).ParseFS(tmplFS, "templates/layout.html")
		if err != nil {
			t.Fatalf("parse layout: %v", err)
		}
		if _, err := template.Must(base.Clone()).ParseFS(tmplFS, p); err != nil {
			t.Errorf("%s does not parse: %v", name, err)
			continue
		}
		for _, msg := range checkFormFields(name, string(layout)+"\n"+string(page)) {
			t.Error(msg)
		}
	}
}

// TestFormFieldRulesCatchRegressions proves the checker fails on each rule it enforces.
func TestFormFieldRulesCatchRegressions(t *testing.T) {
	secret := ` autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" data-1p-ignore`
	cases := []struct {
		name, page, src, want string
	}{
		{"duplicate id", "x.html", `<input id="a" aria-label="a"><input id="a" aria-label="b">`, "duplicate id"},
		{"missing id", "x.html", `<input aria-label="a">`, "no id"},
		{"missing label", "x.html", `<input id="a" placeholder="only a placeholder">`, "no label"},
		{"password outside login", "x.html", `<input id="a" type="password" aria-label="a">`, "type=password"},
		{"new-password outside login", "x.html", `<input id="a" type="text" autocomplete="new-password" aria-label="a">`, "autocomplete new-password"},
		{"username token outside login", "x.html", `<input id="a" autocomplete="username" aria-label="a">`, "autocomplete username"},
		{"secret as password type", "x.html", `<input id="a" type="password" class="secret-field"` + secret + ` aria-label="a">`, "not type=text"},
		{"secret without data-1p-ignore", "x.html", `<input id="a" type="text" class="secret-field" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" aria-label="a">`, "data-1p-ignore"},
		{"secret named password", "x.html", `<input id="a" name="password" type="text" class="secret-field"` + secret + ` aria-label="a">`, "names a password"},
		{"dynamic duplicate id", "x.html", `<input id="a-{{.X}}" aria-label="a"><input id="a-{{.Y}}" aria-label="b">`, "duplicate id"},
	}
	for _, c := range cases {
		got := strings.Join(checkFormFields(c.page, c.src), "\n")
		if !strings.Contains(got, c.want) {
			t.Errorf("%s: want a problem containing %q, got %q", c.name, c.want, got)
		}
	}
	good := `<label for="u">U</label><input id="u" type="text" autocomplete="username"><input id="p" type="password" autocomplete="current-password" aria-label="p">`
	if got := checkFormFields("login.html", good); len(got) != 0 {
		t.Errorf("a clean login form was flagged: %v", got)
	}
}

// TestSecretFieldClassMasksText guards the stylesheet half of the secret-field rule:
// without it a type=text secret would be shown in the clear.
func TestSecretFieldClassMasksText(t *testing.T) {
	css, err := fs.ReadFile(staticFS, "static/app.css")
	if err != nil {
		t.Fatalf("read app.css: %v", err)
	}
	re := regexp.MustCompile(`\.secret-field\s*\{[^}]*-webkit-text-security:\s*disc`)
	if !re.Match(css) {
		t.Error("app.css has no .secret-field rule with -webkit-text-security: disc")
	}
}
