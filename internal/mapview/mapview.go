// Package mapview builds the SopsHQ "Map" page's nested folder tree.
//
// The Map page lets the operator drill down through SopsHQ's records - projects,
// machines, OS users, keys, paths, secret names, global sets - in whatever
// grouping order they choose. This package is the pure, dependency-light heart of
// that feature: given the current records (gathered by the web layer) and a view
// definition (an ordered list of grouping attributes plus a leaf attribute), Build
// returns a nested []Node tree ready to serialize to JSON.
//
// JOIN GRAPH. The records relate to each other through a small fixed set of
// relations, and the builder denormalizes them into flat "rows" before grouping:
//
//   - A project has a folder Path on a Machine (model.Project.Paths).
//   - An Assignment ties a Project + Machine + OSUser + Key together (it is the
//     spine that links a user and key to a project on a machine).
//   - A SecretName belongs to a project's secrets.yaml (passed in per project).
//   - A GlobalSet is encrypted to one or more recipient OSUsers on a Machine, and
//     holds its own SecretNames (passed in per set).
//
// Each row carries as many of the seven attributes as its source relation
// provides; grouping then proceeds attribute by attribute in the requested order.
// The builder is robust to ANY ordering: at each level, rows that do not carry the
// level's attribute are dropped from that branch, and if NO row under a branch
// carries the attribute (no valid join from the prefix) the level is skipped
// (collapsed) rather than failing. This means an odd ordering yields a smaller or
// flatter tree, never a crash.
//
// SECURITY. Nodes carry display names and stable record ids (UUIDs, a folder path,
// or a secret NAME) only - never a secret value, private key, passphrase, or TOTP
// secret. The resulting tree (and its JSON) is safe to log.
package mapview

import (
	"sort"

	"sopshq/internal/model"
)

// Attr is one grouping/leaf attribute key. The set is fixed (the vocabulary the
// Map editor offers and this builder understands).
type Attr string

const (
	AttrProject    Attr = "Project"
	AttrMachine    Attr = "Machine"
	AttrOSUser     Attr = "OSUser"
	AttrPath       Attr = "Path"
	AttrKey        Attr = "Key"
	AttrSecretName Attr = "SecretName"
	AttrGlobalSet  Attr = "GlobalSet"
)

// allAttrs is the fixed vocabulary, in the order the editor presents it.
var allAttrs = []Attr{
	AttrProject, AttrMachine, AttrOSUser, AttrPath, AttrKey, AttrSecretName, AttrGlobalSet,
}

// attrLabel is the human-facing label for each attribute key.
var attrLabel = map[Attr]string{
	AttrProject:    "Project",
	AttrMachine:    "Machine",
	AttrOSUser:     "OS user",
	AttrPath:       "Path",
	AttrKey:        "Key",
	AttrSecretName: "Secret name",
	AttrGlobalSet:  "Global set",
}

// AllAttrs returns the fixed attribute vocabulary in presentation order.
func AllAttrs() []Attr { return append([]Attr(nil), allAttrs...) }

// Label returns the human-facing label for an attribute key (or the raw key when
// unknown).
func Label(a Attr) string {
	if l, ok := attrLabel[a]; ok {
		return l
	}
	return string(a)
}

// Valid reports whether key names a known attribute.
func Valid(key string) bool {
	_, ok := attrLabel[Attr(key)]
	return ok
}

// Kind distinguishes a folder (grouping) node from an item (leaf) node.
type Kind string

const (
	KindGrouping Kind = "grouping"
	KindLeaf     Kind = "leaf"
)

// Node is one tree node. Children is non-nil only for grouping nodes that have
// descendants. Ref is the stable id for the node's detail (a UUID for a Project,
// Machine, OSUser, Key, or GlobalSet; the folder path for a Path; the secret NAME
// for a SecretName) - never a secret value.
type Node struct {
	Label    string `json:"label"`
	Kind     Kind   `json:"kind"`
	Attr     Attr   `json:"attr"`
	Ref      string `json:"ref,omitempty"`
	Children []Node `json:"children,omitempty"`
}

// View is a resolved view definition: an ordered sequence of attribute levels,
// outermost first, with the last entry rendered as leaves.
type View struct {
	ID     string
	Name   string
	Levels []Attr
}

// ViewFromRecord resolves a stored MapView record into a View (its grouping
// attributes followed by its leaf attribute). Unknown attribute keys are dropped
// so a malformed record still yields a usable, smaller tree.
func ViewFromRecord(v *model.MapView) View {
	levels := make([]Attr, 0, len(v.GroupBy)+1)
	for _, g := range v.GroupBy {
		if Valid(g) {
			levels = append(levels, Attr(g))
		}
	}
	if Valid(v.Leaf) {
		levels = append(levels, Attr(v.Leaf))
	}
	return View{ID: v.M.UUID, Name: v.Name, Levels: levels}
}

// DefaultViews are the built-in views seeded on the Map page (not stored records).
// They give the operator a useful tree immediately, alongside any custom views.
func DefaultViews() []View {
	return []View{
		{ID: "default-projects", Name: "Projects", Levels: []Attr{AttrProject, AttrMachine, AttrPath, AttrSecretName}},
		{ID: "default-machines", Name: "Machines", Levels: []Attr{AttrMachine, AttrOSUser, AttrProject}},
		{ID: "default-users", Name: "Users", Levels: []Attr{AttrOSUser, AttrProject, AttrSecretName}},
		{ID: "default-keys", Name: "Keys", Levels: []Attr{AttrKey, AttrProject, AttrOSUser}},
		{ID: "default-secrets", Name: "Secrets", Levels: []Attr{AttrSecretName, AttrProject, AttrMachine}},
	}
}

// Input is the value-free snapshot the builder groups. The web layer gathers it
// from the store and keysvc (secret NAMES only - never values).
type Input struct {
	Projects    []*model.Project
	Machines    []*model.Machine
	OSUsers     []*model.OSUser
	Keys        []*model.Key
	Assignments []*model.Assignment
	GlobalSets  []*model.GlobalSet
	// SecretsByProject maps a project UUID to its secret NAMES (no values).
	SecretsByProject map[string][]string
	// SecretsBySet maps a global-set UUID to its secret NAMES (no values).
	SecretsBySet map[string][]string
}

// Build groups the input records by the view's level sequence and returns the
// resulting tree.
func Build(in Input, v View) []Node {
	return group(buildRows(in), v.Levels)
}

// cell is one attribute's value on a row: a stable id plus a display label.
type cell struct {
	id    string
	label string
}

// row is a denormalized fact: a partial assignment of attributes to cells. An
// attribute absent from the map means the row does not carry that attribute (no
// join), so it does not participate in grouping at that level.
type row map[Attr]cell

// buildRows denormalizes the input relations into flat rows.
func buildRows(in Input) []row {
	machineName := map[string]string{}
	for _, m := range in.Machines {
		machineName[m.M.UUID] = m.Name
	}
	type osu struct{ machineID, username string }
	osUser := map[string]osu{}
	for _, u := range in.OSUsers {
		osUser[u.M.UUID] = osu{u.MachineID, u.Username}
	}
	keyName := map[string]string{}
	for _, k := range in.Keys {
		keyName[k.M.UUID] = k.Name
	}
	asgByProject := map[string][]*model.Assignment{}
	for _, a := range in.Assignments {
		asgByProject[a.ProjectID] = append(asgByProject[a.ProjectID], a)
	}

	var rows []row

	// Project family: the wide project-placement fact. For each project, join its
	// paths and assignments on the machine they share, then explode by secret name,
	// so a single ordering can drill Project/Machine/Path/Key/OSUser/SecretName in
	// any sequence. Missing pieces (no path, no assignment, no secret) yield partial
	// rows rather than dropping the project.
	for _, p := range in.Projects {
		secrets := in.SecretsByProject[p.M.UUID]
		pathsByMachine := map[string][]string{}
		var machineOrder []string
		seenMachine := map[string]bool{}
		addMachine := func(id string) {
			if id != "" && !seenMachine[id] {
				seenMachine[id] = true
				machineOrder = append(machineOrder, id)
			}
		}
		for _, pp := range p.Paths {
			pathsByMachine[pp.MachineID] = append(pathsByMachine[pp.MachineID], pp.Path)
			addMachine(pp.MachineID)
		}
		asgByMachine := map[string][]*model.Assignment{}
		for _, a := range asgByProject[p.M.UUID] {
			asgByMachine[a.MachineID] = append(asgByMachine[a.MachineID], a)
			addMachine(a.MachineID)
		}
		machineOpts := machineOrder
		if len(machineOpts) == 0 {
			machineOpts = []string{""} // project with no machine context
		}
		for _, mID := range machineOpts {
			for _, path := range pathOptions(pathsByMachine[mID]) {
				for _, a := range asgOptions(asgByMachine[mID]) {
					for _, name := range secretOptions(secrets) {
						r := row{AttrProject: {p.M.UUID, p.Name}}
						if mID != "" {
							r[AttrMachine] = cell{mID, machineName[mID]}
						}
						if path != "" {
							r[AttrPath] = cell{path, path}
						}
						if a != nil {
							if u, ok := osUser[a.OSUserID]; ok && u.username != "" {
								r[AttrOSUser] = cell{a.OSUserID, u.username}
							}
							if kn := keyName[a.KeyID]; kn != "" {
								r[AttrKey] = cell{a.KeyID, kn}
							}
						}
						if name != "" {
							r[AttrSecretName] = cell{name, name}
						}
						rows = append(rows, r)
					}
				}
			}
		}
	}

	// Global-set family: a set is encrypted to recipient OS users on its machine and
	// holds its own secret names. These rows carry GlobalSet (never Project), so a
	// project-keyed ordering naturally drops them and a set-keyed ordering surfaces
	// them.
	for _, set := range in.GlobalSets {
		secrets := in.SecretsBySet[set.M.UUID]
		recips := set.RecipientUserIDs
		if len(recips) == 0 {
			recips = []string{""}
		}
		for _, uid := range recips {
			for _, name := range secretOptions(secrets) {
				r := row{AttrGlobalSet: {set.M.UUID, set.Name}}
				if set.MachineID != "" {
					r[AttrMachine] = cell{set.MachineID, machineName[set.MachineID]}
				}
				if uid != "" {
					if u, ok := osUser[uid]; ok && u.username != "" {
						r[AttrOSUser] = cell{uid, u.username}
					}
				}
				if name != "" {
					r[AttrSecretName] = cell{name, name}
				}
				rows = append(rows, r)
			}
		}
	}

	return rows
}

// pathOptions returns the path values to iterate, or a single empty option when a
// machine has no path (so the rest of the row still forms).
func pathOptions(paths []string) []string {
	if len(paths) == 0 {
		return []string{""}
	}
	return paths
}

// asgOptions returns the assignments to iterate, or a single nil option when a
// machine has none.
func asgOptions(asgs []*model.Assignment) []*model.Assignment {
	if len(asgs) == 0 {
		return []*model.Assignment{nil}
	}
	return asgs
}

// secretOptions returns the secret names to iterate, or a single empty option when
// there are none.
func secretOptions(names []string) []string {
	if len(names) == 0 {
		return []string{""}
	}
	return names
}

// group recursively partitions rows by the level sequence. At each level it groups
// the rows that carry the attribute; if none do, it collapses (skips) the level and
// recurses on the rest. Children of the final level are leaf nodes.
func group(rows []row, seq []Attr) []Node {
	if len(seq) == 0 {
		return nil
	}
	a, rest := seq[0], seq[1:]

	// Bucket rows by this attribute's id, preserving a deterministic label order.
	buckets := map[string][]row{}
	labels := map[string]string{}
	var ids []string
	for _, r := range rows {
		c, ok := r[a]
		if !ok {
			continue // row does not join this level
		}
		if _, seen := buckets[c.id]; !seen {
			ids = append(ids, c.id)
			labels[c.id] = c.label
		}
		buckets[c.id] = append(buckets[c.id], r)
	}
	if len(ids) == 0 {
		// No valid join from this prefix: collapse the level rather than failing.
		return group(rows, rest)
	}
	sort.SliceStable(ids, func(i, j int) bool {
		if labels[ids[i]] != labels[ids[j]] {
			return labels[ids[i]] < labels[ids[j]]
		}
		return ids[i] < ids[j]
	})

	leaf := len(rest) == 0
	nodes := make([]Node, 0, len(ids))
	for _, id := range ids {
		n := Node{Label: labels[id], Attr: a, Ref: id}
		if leaf {
			n.Kind = KindLeaf
		} else {
			n.Kind = KindGrouping
			n.Children = group(buckets[id], rest)
		}
		nodes = append(nodes, n)
	}
	return nodes
}
