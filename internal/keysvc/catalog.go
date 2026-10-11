package keysvc

import (
	"fmt"
	"sort"
	"strings"

	"sopshq/internal/audit"
	"sopshq/internal/keys"
	"sopshq/internal/model"
)

// SecretUsage is one place a secret value is used: a NAMEd secret that lives
// either inside a project or inside a global (shared) set, together with the
// placement context (machine/user/key/path) that says where the encrypted file
// lives on this machine and who can decrypt it. It carries NO value - the value
// is grouped server-side then revealed on demand.
//
// For a PROJECT secret, ProjectID/Project are set and GlobalSet/SetID are empty.
// For a GLOBAL-SET secret, GlobalSet (the set name) and SetID (the set UUID, used
// to build the global reveal URL) are set and ProjectID/Project are empty.
type SecretUsage struct {
	ProjectID string
	Project   string
	GlobalSet string
	SetID     string
	Name      string
	Machine   string
	User      string
	Key       string
	Path      string
}

// SecretGroup is a set of usages that share the same plaintext value. Count is
// the number of usages. RevealProjectID/RevealName name one usage the panel can
// call RevealSecret on to show the shared value (masked until then). The group
// holds NO plaintext value.
type SecretGroup struct {
	Count           int
	RevealProjectID string
	RevealName      string
	Usages          []SecretUsage
}

// SecretsCatalog decrypts every locally-readable project's secrets IN MEMORY,
// groups the usages by plaintext value, and returns the grouped, VALUE-FREE
// structure for the cross-project Secrets page. The plaintext values are used
// only as grouping keys and are discarded when this function returns; no value is
// logged, cached to disk, or placed in the result. The whole sweep is audited
// once as a bulk reveal (by counts only, never a value).
//
// Only projects with a local path and a wired key are included - the value lives
// in a secrets.yaml this machine can read. Projects this node cannot decrypt are
// silently skipped (their values never leave their own machine).
func (s *Service) SecretsCatalog(actor string) ([]SecretGroup, error) {
	if s.localMachineID == "" {
		return nil, ErrNoLocalMachine
	}

	machineName := map[string]string{}
	for _, m := range s.store.Machines.List() {
		machineName[m.M.UUID] = m.Name
	}
	userName := map[string]string{}
	for _, u := range s.store.OSUsers.List() {
		userName[u.M.UUID] = u.Username
	}
	keyName := map[string]string{}
	for _, k := range s.store.Keys.List() {
		keyName[k.M.UUID] = k.Name
	}

	// byValue groups usages by the plaintext value. The value is only a map key,
	// held in memory for the duration of this call and never returned or logged.
	byValue := map[string]*SecretGroup{}
	readProjects := 0
	for _, p := range s.store.Projects.List() {
		dir, priv, err := s.resolveEditable(p.M.UUID)
		if err != nil {
			continue // not locally decryptable (no local path / not wired)
		}
		secrets, err := keys.ReadSecrets(dir, priv)
		if err != nil || len(secrets) == 0 {
			continue
		}
		readProjects++
		machine, user, key := s.projectPlacement(p.M.UUID, machineName, userName, keyName)
		for name, val := range secrets {
			g := byValue[val]
			if g == nil {
				g = &SecretGroup{RevealProjectID: p.M.UUID, RevealName: name}
				byValue[val] = g
			}
			g.Usages = append(g.Usages, SecretUsage{
				ProjectID: p.M.UUID,
				Project:   p.Name,
				Name:      name,
				Machine:   machine,
				User:      user,
				Key:       key,
				Path:      dir,
			})
		}
	}

	// Also sweep the local global (shared) sets, folding each set's secrets into
	// the same value grouping. A set that does not resolve locally (lives on
	// another machine, or a recipient is missing a key) is skipped, exactly like
	// an undecryptable project. The values are grouping keys only, discarded here.
	readSets := 0
	for _, set := range s.GlobalSets() {
		r, err := s.resolveSet(set.M.UUID)
		if err != nil {
			continue
		}
		secrets, err := keys.ReadSecrets(r.primaryDir, r.priv)
		if err != nil || len(secrets) == 0 {
			continue
		}
		readSets++
		machine := machineName[set.MachineID]
		user, key := s.setPlacement(set, keyName)
		for name, val := range secrets {
			g := byValue[val]
			if g == nil {
				g = &SecretGroup{}
				byValue[val] = g
			}
			g.Usages = append(g.Usages, SecretUsage{
				GlobalSet: set.Name,
				SetID:     set.M.UUID,
				Name:      name,
				Machine:   machine,
				User:      user,
				Key:       key,
				Path:      r.primaryDir,
			})
		}
	}

	groups := make([]SecretGroup, 0, len(byValue))
	for _, g := range byValue {
		g.Count = len(g.Usages)
		sort.Slice(g.Usages, func(i, j int) bool {
			if g.Usages[i].Project != g.Usages[j].Project {
				return g.Usages[i].Project < g.Usages[j].Project
			}
			return g.Usages[i].Name < g.Usages[j].Name
		})
		// The reveal representative is the first PROJECT usage (its project-reveal
		// endpoint is what RevealProjectID/RevealName name); a group with only
		// global usages has no project to reveal from, so it falls back to the
		// first usage and relies on the per-row global reveal button.
		rep := g.Usages[0]
		for _, u := range g.Usages {
			if u.ProjectID != "" {
				rep = u
				break
			}
		}
		g.RevealProjectID = rep.ProjectID
		g.RevealName = rep.Name
		groups = append(groups, *g)
	}
	// Most-shared values first, then by the representative name for stability.
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].Count != groups[j].Count {
			return groups[i].Count > groups[j].Count
		}
		return groups[i].RevealName < groups[j].RevealName
	})

	_ = s.audit.Record(actor, "secrets_catalog", "all projects", audit.OK,
		fmt.Sprintf("decrypted %d project(s) and %d global set(s); %d value group(s)", readProjects, readSets, len(groups)))
	return groups, nil
}

// ReuseItem names one secret to copy into a target project: the SOURCE secret to
// read the value from (SourceProjectID + SourceName) and the NAME to store it
// under in the target project. The value is never carried by the caller - it is
// decrypted from the source and written to the target inside BulkReuseSecrets.
type ReuseItem struct {
	SourceProjectID string
	SourceName      string
	TargetName      string
}

// BulkReuseSecrets copies each item's value from its source secret into the
// target project under the item's TargetName, reusing the on-demand decrypt
// (Path 1): the value is read from the source with GetSecretValue and written to
// the target with SetSecret. The plaintext is never logged, returned, or cached.
//
// A TargetName that is empty/invalid, or that already exists in the target, is
// SKIPPED (never overwritten). Returns the target names added and the names
// skipped, so the panel can report both. Each successful add is audited by name
// (inside SetSecret); nothing here records a value.
func (s *Service) BulkReuseSecrets(targetProjectID string, items []ReuseItem, actor string) (added, skipped []string, err error) {
	existing, err := s.ListSecrets(targetProjectID)
	if err != nil {
		return nil, nil, err
	}
	have := make(map[string]bool, len(existing))
	for _, n := range existing {
		have[n] = true
	}
	for _, it := range items {
		if it.TargetName == "" || have[it.TargetName] {
			skipped = append(skipped, it.TargetName)
			continue
		}
		val, gerr := s.GetSecretValue(it.SourceProjectID, it.SourceName)
		if gerr != nil {
			skipped = append(skipped, it.TargetName)
			continue
		}
		if serr := s.SetSecret(targetProjectID, it.TargetName, val, actor); serr != nil {
			skipped = append(skipped, it.TargetName)
			continue
		}
		added = append(added, it.TargetName)
		have[it.TargetName] = true
	}
	return added, skipped, nil
}

// projectPlacement returns the distinct machine, OS-user, and key names from the
// project's assignments, each joined with ", " for display. These describe where
// the project's encrypted file is placed and who can decrypt it.
func (s *Service) projectPlacement(projectID string, machineName, userName, keyName map[string]string) (machine, user, key string) {
	var machines, users, kkeys []string
	seenM, seenU, seenK := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, a := range s.store.Assignments.List() {
		if a.ProjectID != projectID {
			continue
		}
		if n := machineName[a.MachineID]; n != "" && !seenM[n] {
			seenM[n] = true
			machines = append(machines, n)
		}
		if n := userName[a.OSUserID]; n != "" && !seenU[n] {
			seenU[n] = true
			users = append(users, n)
		}
		if n := keyName[a.KeyID]; n != "" && !seenK[n] {
			seenK[n] = true
			kkeys = append(kkeys, n)
		}
	}
	sort.Strings(machines)
	sort.Strings(users)
	sort.Strings(kkeys)
	return strings.Join(machines, ", "), strings.Join(users, ", "), strings.Join(kkeys, ", ")
}

// setPlacement returns the distinct recipient usernames and generated-key names
// for a global set, each joined with ", " for display. These describe who can
// decrypt the set's shared file and with which key.
func (s *Service) setPlacement(set *model.GlobalSet, keyName map[string]string) (user, key string) {
	var users, kkeys []string
	seenU, seenK := map[string]bool{}, map[string]bool{}
	for _, uid := range set.RecipientUserIDs {
		u, err := s.store.OSUsers.Get(uid)
		if err == nil && u.Username != "" && !seenU[u.Username] {
			seenU[u.Username] = true
			users = append(users, u.Username)
		}
		if k := s.ownedGeneratedKey(uid); k != nil {
			if n := keyName[k.M.UUID]; n != "" && !seenK[n] {
				seenK[n] = true
				kkeys = append(kkeys, n)
			}
		}
	}
	sort.Strings(users)
	sort.Strings(kkeys)
	return strings.Join(users, ", "), strings.Join(kkeys, ", ")
}
