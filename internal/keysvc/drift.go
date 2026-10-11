package keysvc

import (
	"os"
	"path/filepath"
	"strings"

	"sopshq/internal/agent"
	"sopshq/internal/keys"
	"sopshq/internal/model"
	"sopshq/internal/place"
)

// DriftItem is one discrepancy between desired state and what is on disk.
type DriftItem struct {
	Kind   string // "placement" or "sops.yaml"
	Target string // user or project name
	Detail string // what is wrong, in plain language (names public keys, never a private value)

	// ProjectID is set for a local ".sops.yaml" item so the drift view can offer
	// per-row resolve actions (Adopt readers / Re-key to desired / Apply). It is
	// empty for placement items and for remote items (which are resolved on the
	// machine that owns them), so those rows show no local action.
	ProjectID string

	// Missing is true when the item is a local project whose .sops.yaml has not
	// been written yet (the resolve action is "Apply", which writes it). When false
	// with a non-empty ProjectID the item is a public-key mismatch (the resolve
	// actions are "Adopt readers" or "Re-key to desired").
	Missing bool

	// ExtraOnDisk lists the age public keys the on-disk .sops.yaml carries that the
	// project's desired set does not include. "Re-key to desired" drops these, so the
	// view names them in its warning. Public keys only, never a private value.
	ExtraOnDisk []string

	// DesiredOnly names the project's assigned public keys that are NOT on disk - keys
	// the operator added to the project but has not applied yet. "Match to the on-disk
	// keys" REMOVES these from the project (they protect nothing on disk, so no reader is
	// dropped), so the Match action names them. Described by key name where SopsHQ knows
	// one; empty when every assigned key is already on disk.
	DesiredOnly []string
}

// PendingState summarizes the work an Apply would still do: drift between the
// desired state and disk, on this machine (Local) and on reachable peers (Remote).
// Unreachable lists peers that have desired state but could not be probed (offline
// or not enrolled), so the operator knows the picture is incomplete rather than
// clean. The panel uses this to drive the header alert and red Apply buttons.
type PendingState struct {
	Local       []DriftItem
	Remote      []DriftItem
	Unreachable []string
}

// Count is the number of confirmed discrepancies (local + remote). It does not
// count Unreachable peers, which are an uncertainty, not a confirmed change.
func (p PendingState) Count() int { return len(p.Local) + len(p.Remote) }

// Any reports whether there is anything for the operator to act on - confirmed
// drift OR a peer that could not be verified.
func (p PendingState) Any() bool { return p.Count() > 0 || len(p.Unreachable) > 0 }

// Pending computes the cross-machine pending state. It runs DriftLocal for this
// machine and probes every other machine's agent with a secret-free inspection.
// A probe that fails (peer offline, not enrolled) marks that peer Unreachable
// rather than failing the whole call. This can block on network I/O (one agent
// timeout per peer), so callers run it off the request path and cache the result.
func (s *Service) Pending() PendingState {
	var ps PendingState
	if s.localMachineID == "" {
		return ps
	}
	if items, err := s.DriftLocal(); err == nil {
		ps.Local = items
	}
	for _, mc := range s.store.Machines.List() {
		if mc.M.UUID == s.localMachineID {
			continue
		}
		req, has := s.inspectRequestFor(mc.M.UUID)
		if !has {
			continue // nothing assigned to that machine - nothing to verify
		}
		cli, ok := s.dialRemote(mc)
		if !ok {
			ps.Unreachable = append(ps.Unreachable, mc.Name)
			continue
		}
		resp, err := cli.Inspect(req)
		if err != nil {
			ps.Unreachable = append(ps.Unreachable, mc.Name)
			continue
		}
		for _, d := range resp.Drifts {
			ps.Remote = append(ps.Remote, DriftItem{Kind: d.Kind, Target: mc.Name + ": " + d.Target, Detail: d.Detail})
		}
	}
	return ps
}

// inspectRequestFor builds the secret-free drift checks for one machine from the
// desired state: each assignment becomes a placement check (expected public
// recipient at the user's key base) and each project path becomes a .sops.yaml
// recipient check. The bool is false when that machine has nothing assigned.
func (s *Service) inspectRequestFor(machineID string) (agent.InspectRequest, bool) {
	var req agent.InspectRequest
	for _, a := range s.store.Assignments.List() {
		if a.MachineID != machineID {
			continue
		}
		k, err := s.store.Keys.Get(a.KeyID)
		if err != nil || k.Recipient == "" {
			continue
		}
		u, err := s.store.OSUsers.Get(a.OSUserID)
		if err != nil {
			continue
		}
		base := s.userKeyBase(u)
		if base == "" {
			continue
		}
		req.Placements = append(req.Placements, agent.PlacementCheck{
			Target: u.Username, Base: base, Recipient: k.Recipient,
		})
	}
	for _, p := range s.store.Projects.List() {
		recips, _ := s.projectRecipients(p)
		if len(recips) == 0 {
			continue
		}
		ages := make([]string, len(recips))
		for i, r := range recips {
			ages[i] = r.Age
		}
		for _, pp := range p.Paths {
			if pp.MachineID != machineID {
				continue
			}
			req.Projects = append(req.Projects, agent.ProjectCheck{
				Target: p.Name, Dir: pp.Path, Recipients: ages,
			})
		}
	}
	return req, len(req.Placements)+len(req.Projects) > 0
}

// DriftLocal compares the desired state (assignments + project recipients) with
// the actual files on THIS machine and returns the discrepancies. It is
// read-only; the operator fixes drift by running Apply. Useful for catching
// manual edits or a key that was never placed.
func (s *Service) DriftLocal() ([]DriftItem, error) {
	if s.localMachineID == "" {
		return nil, ErrNoLocalMachine
	}
	var items []DriftItem

	// Placement drift: each local assignment's key should be present and current.
	for _, a := range s.store.Assignments.List() {
		if a.MachineID != s.localMachineID {
			continue
		}
		k, err := s.store.Keys.Get(a.KeyID)
		if err != nil || k.Recipient == "" {
			continue
		}
		u, err := s.store.OSUsers.Get(a.OSUserID)
		if err != nil {
			continue
		}
		base := s.userKeyBase(u)
		if base == "" {
			continue
		}
		onDisk, err := os.ReadFile(place.KeyFile(base))
		if err != nil {
			items = append(items, DriftItem{Kind: "placement", Target: u.Username, Detail: "key " + k.Name + " is not placed"})
			continue
		}
		priv, err := s.unsealPriv(k)
		if err != nil {
			continue
		}
		// A user's keys.txt may hold several keys (one per project); placement is
		// satisfied when this key is AMONG them, not when it is the only one.
		if !keyInStore(onDisk, priv) {
			items = append(items, DriftItem{Kind: "placement", Target: u.Username, Detail: "key " + k.Name + " is not in " + u.Username + "'s key store (run Apply)"})
		}
		// For a root-derived key store the user reaches their key through POSIX ACLs;
		// verify the shared root is owned by SopsHQ and the grant is intact, so Apply
		// never trusts an unreachable key. Reported (never silently ignored) when broken.
		if opts := s.rootDerivedOpts(u); opts != nil {
			if aerr := place.VerifyKeystoreACL(*opts); aerr != nil {
				items = append(items, DriftItem{Kind: "placement", Target: u.Username, Detail: "shared keybase root ACL for " + u.Username + " is not in place: " + aerr.Error()})
			}
		}
	}

	// .sops.yaml drift: each local project path should list exactly the desired
	// public keys. Messages name the exact difference (by key name where SopsHQ knows
	// one, else a short age1... prefix) so the operator sees WHAT to fix, not a vague
	// "differs".
	nameByPub := s.keyNamesByPublic()
	acctByPub := s.accountByPublic()
	for _, p := range s.store.Projects.List() {
		dir := s.localProjectPath(p)
		if dir == "" {
			continue
		}
		want, _ := s.projectRecipients(p)
		if len(want) == 0 {
			continue
		}
		sopsPath := filepath.Join(dir, ".sops.yaml")
		got, err := os.ReadFile(sopsPath)
		if err != nil {
			items = append(items, DriftItem{
				Kind:      "sops.yaml",
				Target:    p.Name,
				Detail:    "no .sops.yaml at " + sopsPath + " yet",
				ProjectID: p.M.UUID,
				Missing:   true,
			})
			continue
		}
		onDiskPubs := parseAgeLine(string(got))
		if !sameRecipients(want, onDiskPubs) {
			detail, extra := describeSopsDrift(want, onDiskPubs, nameByPub, acctByPub)
			items = append(items, DriftItem{
				Kind:        "sops.yaml",
				Target:      p.Name,
				Detail:      detail,
				ProjectID:   p.M.UUID,
				ExtraOnDisk: extra,
				DesiredOnly: s.projectDesiredOnly(p, dir, nameByPub),
			})
		}
	}
	return items, nil
}

// ProjectSopsDrift returns the local .sops.yaml drift for ONE project, if any, so the
// project page can show a targeted call to action instead of a bare Apply. drift is
// false when the project's on-disk .sops.yaml already matches its desired public keys
// (or the project is not local, has no folder, or no key assigned). The returned item
// carries Missing (the file has not been written - Apply writes it) or, when the file
// exists but its public keys differ, the account-aware detail plus the extra on-disk
// public keys a re-key would drop. Read-only.
func (s *Service) ProjectSopsDrift(projectID string) (item DriftItem, drift bool) {
	if s.localMachineID == "" {
		return DriftItem{}, false
	}
	p, err := s.store.Projects.Get(projectID)
	if err != nil {
		return DriftItem{}, false
	}
	dir := s.localProjectPath(p)
	if dir == "" {
		return DriftItem{}, false
	}
	want, _ := s.projectRecipients(p)
	if len(want) == 0 {
		return DriftItem{}, false
	}
	sopsPath := filepath.Join(dir, ".sops.yaml")
	got, err := os.ReadFile(sopsPath)
	if err != nil {
		return DriftItem{Kind: "sops.yaml", Target: p.Name, Detail: "no .sops.yaml at " + sopsPath + " yet", ProjectID: p.M.UUID, Missing: true}, true
	}
	onDiskPubs := parseAgeLine(string(got))
	if sameRecipients(want, onDiskPubs) {
		return DriftItem{}, false
	}
	nameByPub := s.keyNamesByPublic()
	detail, extra := describeSopsDrift(want, onDiskPubs, nameByPub, s.accountByPublic())
	return DriftItem{Kind: "sops.yaml", Target: p.Name, Detail: detail, ProjectID: p.M.UUID, ExtraOnDisk: extra, DesiredOnly: s.projectDesiredOnly(p, dir, nameByPub)}, true
}

// projectDesiredOnly names the project's assigned public keys that are NOT among the
// public keys currently on disk (existingReaders: .sops.yaml + encrypted secrets
// metadata) - the desired-only keys the operator added but has not applied, which "Match
// to the on-disk keys" removes from the project. It mirrors MatchProjectToDisk's removal
// set exactly (that action drops project assignments whose key is not on disk), so the
// warning is accurate. Each is described by key name where SopsHQ knows one. Read-only;
// empty when every assigned key is already on disk.
func (s *Service) projectDesiredOnly(p *model.Project, dir string, nameByPub map[string]string) []string {
	readers, _ := s.existingReaders(dir)
	onDisk := make(map[string]bool, len(readers))
	for _, r := range readers {
		onDisk[r] = true
	}
	want, _ := s.projectRecipients(p)
	var out []string
	for _, w := range want {
		if !onDisk[w.Age] {
			out = append(out, describePub(w.Age, nameByPub))
		}
	}
	return out
}

// keyNamesByPublic maps each key in custody from its age PUBLIC key to its human
// name, so drift messages can say "public key 'app-key'" instead of a bare age1
// string. Public keys are safe to expose; no private material is read.
func (s *Service) keyNamesByPublic() map[string]string {
	m := map[string]string{}
	for _, k := range s.store.Keys.List() {
		if k.Recipient != "" {
			m[k.Recipient] = k.Name
		}
	}
	return m
}

// describeSopsDrift turns a desired-vs-on-disk public-key difference into a plain,
// specific sentence and returns the on-disk public keys that are NOT in the desired
// set (the ones a re-key would drop). want is the project's desired set; got is the
// on-disk "age:" line. nameByPub names a public key where SopsHQ holds it; acctByPub
// maps a public key to the ONE OS account it belongs to (when unambiguous).
//
// When every extra and every missing public key belongs to the SAME single account,
// the difference is one account switching between its OWN identities - both of which
// decrypt - not a lost reader. The message says so plainly instead of "missing/extra",
// which would read like a loss of access. The precise "missing/extra" wording is kept
// for genuinely different accounts.
func describeSopsDrift(want []keys.Recipient, got []string, nameByPub, acctByPub map[string]string) (detail string, extra []string) {
	wantSet := map[string]bool{}
	for _, w := range want {
		wantSet[w.Age] = true
	}
	gotSet := map[string]bool{}
	for _, g := range got {
		gotSet[g] = true
	}
	var missing []string // desired public keys absent from disk
	for _, w := range want {
		if !gotSet[w.Age] {
			missing = append(missing, w.Age)
		}
	}
	for _, g := range got {
		if !wantSet[g] {
			extra = append(extra, g)
		}
	}
	if acct, ok := sameAccountSwap(missing, extra, acctByPub); ok {
		detail = "the secrets config uses " + joinList(describePubs(extra, nameByPub)) +
			"; this project is set to " + joinList(describePubs(missing, nameByPub)) +
			" - the same account '" + acct + "', which can decrypt either"
		return detail, extra
	}
	missDesc := describePubs(missing, nameByPub)
	extraDesc := describePubs(extra, nameByPub)
	switch {
	case len(extraDesc) > 0 && len(missDesc) > 0:
		detail = "the secrets config lists " + joinList(extraDesc) + " that this project does not include, and is missing " + joinList(missDesc)
	case len(extraDesc) > 0:
		detail = "the secrets config lists " + joinList(extraDesc) + " that this project does not include"
	case len(missDesc) > 0:
		detail = "the project is missing " + joinList(missDesc)
	default:
		// Same set, different order/count edge case: state it plainly.
		detail = "the secrets config public keys do not match this project"
	}
	return detail, extra
}

// sameAccountSwap reports the ONE OS account name when every missing AND every extra
// public key resolves to that same single account (so the drift is one account
// switching between its own identities, both of which decrypt). It returns ok=false
// when either side is empty, when any public key has no known account, or when more
// than one account is involved - in which case the caller keeps the precise
// missing/extra wording rather than guessing "same account".
func sameAccountSwap(missing, extra []string, acctByPub map[string]string) (account string, ok bool) {
	if len(missing) == 0 || len(extra) == 0 {
		return "", false
	}
	for _, pub := range append(append([]string{}, missing...), extra...) {
		a := acctByPub[pub]
		if a == "" {
			return "", false // an unmapped key - cannot claim it is the same account
		}
		if account == "" {
			account = a
		} else if account != a {
			return "", false
		}
	}
	return account, true
}

// describePubs renders each public key for a drift message via describePub.
func describePubs(pubs []string, nameByPub map[string]string) []string {
	out := make([]string, 0, len(pubs))
	for _, pub := range pubs {
		out = append(out, describePub(pub, nameByPub))
	}
	return out
}

// accountByPublic maps each age public key SopsHQ knows to the single OS account
// (username) it belongs to, so a drift message can tell an identity switch within one
// account from a genuinely different reader. The account is taken from the assignments
// that link a key to an OS user (an adopted key is assigned to the user it was adopted
// for; a project key is assigned to the users granted it). A public key linked to MORE
// than one distinct account is left out (ambiguous), so same-account detection stays
// conservative and never guesses. Only public keys are read; no private material.
func (s *Service) accountByPublic() map[string]string {
	userByID := map[string]string{}
	for _, u := range s.store.OSUsers.List() {
		userByID[u.M.UUID] = u.Username
	}
	recByKeyID := map[string]string{}
	for _, k := range s.store.Keys.List() {
		if k.Recipient != "" {
			recByKeyID[k.M.UUID] = k.Recipient
		}
	}
	sets := map[string]map[string]bool{} // public key -> set of usernames
	for _, a := range s.store.Assignments.List() {
		rec := recByKeyID[a.KeyID]
		user := userByID[a.OSUserID]
		if rec == "" || user == "" {
			continue
		}
		if sets[rec] == nil {
			sets[rec] = map[string]bool{}
		}
		sets[rec][user] = true
	}
	out := map[string]string{}
	for rec, users := range sets {
		if len(users) == 1 {
			for u := range users {
				out[rec] = u
			}
		}
	}
	return out
}

// describePub renders one age public key for a drift message: "public key 'name'
// (age1csf...)" when SopsHQ knows the name, else "public key age1csf...". Only the
// public key is shown, never a private value.
func describePub(age string, nameByPub map[string]string) string {
	if name := nameByPub[age]; name != "" {
		return "public key '" + name + "' (" + short(age) + ")"
	}
	return "public key " + short(age)
}

// joinList renders a short human list: "a", "a and b", "a, b and c".
func joinList(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	case 2:
		return items[0] + " and " + items[1]
	default:
		return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
	}
}

// keyInStore reports whether a private key line is present in a key-store file. A
// user's keys.txt may hold several private keys (one per line, one per project key);
// a placement is satisfied when the key is among them.
func keyInStore(store []byte, priv string) bool {
	want := strings.TrimSpace(priv)
	if want == "" {
		return false
	}
	for _, line := range strings.Split(string(store), "\n") {
		if strings.TrimSpace(strings.TrimRight(line, "\r")) == want {
			return true
		}
	}
	return false
}

// parseAgeLine extracts the comma-separated recipients from the "age:" line that
// SopsHQ's writer produces.
func parseAgeLine(content string) []string {
	for _, line := range strings.Split(content, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "age:") {
			rest := strings.TrimSpace(strings.TrimPrefix(t, "age:"))
			if rest == "" {
				return nil
			}
			parts := strings.Split(rest, ",")
			for i := range parts {
				parts[i] = strings.TrimSpace(parts[i])
			}
			return parts
		}
	}
	return nil
}

// sameRecipients compares the desired recipient set with the on-disk set.
func sameRecipients(want []keys.Recipient, got []string) bool {
	if len(want) != len(got) {
		return false
	}
	set := map[string]bool{}
	for _, g := range got {
		set[g] = true
	}
	for _, w := range want {
		if !set[w.Age] {
			return false
		}
	}
	return true
}
