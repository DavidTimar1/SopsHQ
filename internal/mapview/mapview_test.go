package mapview

import (
	"strings"
	"testing"

	"sopshq/internal/model"
)

func meta(id string) model.Meta { return model.Meta{UUID: id} }

// outline renders a tree as an indented "Label [kind]" outline for comparison.
func outline(nodes []Node, depth int) string {
	var b strings.Builder
	for _, n := range nodes {
		b.WriteString(strings.Repeat("  ", depth))
		b.WriteString(n.Label)
		b.WriteString(" [")
		b.WriteString(string(n.Kind))
		b.WriteString("]\n")
		b.WriteString(outline(n.Children, depth+1))
	}
	return b.String()
}

// sample returns the machines/osusers/keys/projects/assignments fixtures shared by
// the table cases.
func sample() Input {
	return Input{
		Machines: []*model.Machine{
			{M: meta("m1"), Name: "machine1"},
			{M: meta("m2"), Name: "machine2"},
		},
		OSUsers: []*model.OSUser{
			{M: meta("u1"), MachineID: "m1", Username: "user1"},
		},
		Keys: []*model.Key{
			{M: meta("k1"), Name: "key1"},
		},
		Projects: []*model.Project{
			{M: meta("p1"), Name: "projectname1", Paths: []model.ProjectPath{
				{MachineID: "m1", Path: "path1"},
				{MachineID: "m1", Path: "path2"},
			}},
		},
		Assignments: []*model.Assignment{
			{M: meta("a1"), KeyID: "k1", ProjectID: "p1", MachineID: "m1", OSUserID: "u1"},
		},
		SecretsByProject: map[string][]string{
			"p1": {"secretname1", "secretname2"},
		},
	}
}

func TestBuildTrees(t *testing.T) {
	cases := []struct {
		name   string
		in     Input
		levels []Attr
		want   string
	}{
		{
			// The operator's first example: Project -> Machine -> Path -> Secret.
			name:   "project-machine-path-secret",
			in:     sample(),
			levels: []Attr{AttrProject, AttrMachine, AttrPath, AttrSecretName},
			want: "" +
				"projectname1 [grouping]\n" +
				"  machine1 [grouping]\n" +
				"    path1 [grouping]\n" +
				"      secretname1 [leaf]\n" +
				"      secretname2 [leaf]\n" +
				"    path2 [grouping]\n" +
				"      secretname1 [leaf]\n" +
				"      secretname2 [leaf]\n",
		},
		{
			// The operator's second example: Machine -> OS user -> Project. machine2
			// has no projects/users assigned, so nothing references it and it does
			// not appear.
			name:   "machine-osuser-project",
			in:     sample(),
			levels: []Attr{AttrMachine, AttrOSUser, AttrProject},
			want: "" +
				"machine1 [grouping]\n" +
				"  user1 [grouping]\n" +
				"    projectname1 [leaf]\n",
		},
		{
			// Robustness: an attribute with no valid join (GlobalSet, when there are
			// no global sets) collapses, and the next level (Path) still renders.
			name:   "collapse-missing-level",
			in:     sample(),
			levels: []Attr{AttrGlobalSet, AttrPath},
			want: "" +
				"path1 [leaf]\n" +
				"path2 [leaf]\n",
		},
		{
			// Keys spine: Key -> Project -> OS user, all from the assignment join.
			name:   "key-project-osuser",
			in:     sample(),
			levels: []Attr{AttrKey, AttrProject, AttrOSUser},
			want: "" +
				"key1 [grouping]\n" +
				"  projectname1 [grouping]\n" +
				"    user1 [leaf]\n",
		},
		{
			name:   "empty-input",
			in:     Input{},
			levels: []Attr{AttrProject, AttrMachine},
			want:   "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := outline(Build(tc.in, View{Levels: tc.levels}), 0)
			if got != tc.want {
				t.Fatalf("tree mismatch\n--- got ---\n%s\n--- want ---\n%s", got, tc.want)
			}
		})
	}
}

// TestBuildGlobalSet checks the global-set family: a set drills GlobalSet -> OS
// user -> Secret name, and project-keyed orderings ignore it.
func TestBuildGlobalSet(t *testing.T) {
	in := Input{
		Machines: []*model.Machine{{M: meta("m1"), Name: "machine1"}},
		OSUsers:  []*model.OSUser{{M: meta("u1"), MachineID: "m1", Username: "user1"}},
		GlobalSets: []*model.GlobalSet{
			{M: meta("g1"), Name: "shared", MachineID: "m1", RecipientUserIDs: []string{"u1"}},
		},
		SecretsBySet: map[string][]string{"g1": {"OPENROUTER_API_KEY"}},
	}
	got := outline(Build(in, View{Levels: []Attr{AttrGlobalSet, AttrOSUser, AttrSecretName}}), 0)
	want := "" +
		"shared [grouping]\n" +
		"  user1 [grouping]\n" +
		"    OPENROUTER_API_KEY [leaf]\n"
	if got != want {
		t.Fatalf("global tree mismatch\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}

	// A project-only ordering has no project rows to group, so the tree is empty
	// (global-set rows carry no Project, and there is no later level to collapse to).
	if n := Build(in, View{Levels: []Attr{AttrProject}}); len(n) != 0 {
		t.Fatalf("project-only view should ignore global-set rows, got %d nodes", len(n))
	}
}

// TestRefsAreIdsNotLabels confirms leaf/grouping refs carry stable record ids (or
// the name for a secret/path), so the right pane can link by id.
func TestRefsAreIdsNotLabels(t *testing.T) {
	in := sample()
	nodes := Build(in, View{Levels: []Attr{AttrProject, AttrSecretName}})
	if len(nodes) != 1 || nodes[0].Ref != "p1" || nodes[0].Attr != AttrProject {
		t.Fatalf("project node ref/attr wrong: %+v", nodes[0])
	}
	// SecretName leaf ref is the name itself (never a value).
	leaf := nodes[0].Children[0]
	if leaf.Kind != KindLeaf || leaf.Ref != "secretname1" {
		t.Fatalf("secret leaf wrong: %+v", leaf)
	}
}

func TestViewFromRecordDropsUnknownAttrs(t *testing.T) {
	rec := &model.MapView{
		M:       meta("v1"),
		Name:    "custom",
		GroupBy: []string{"Machine", "Bogus", "OSUser"},
		Leaf:    "Project",
	}
	v := ViewFromRecord(rec)
	want := []Attr{AttrMachine, AttrOSUser, AttrProject}
	if len(v.Levels) != len(want) {
		t.Fatalf("levels = %v, want %v", v.Levels, want)
	}
	for i := range want {
		if v.Levels[i] != want[i] {
			t.Fatalf("levels[%d] = %q, want %q", i, v.Levels[i], want[i])
		}
	}
}

func TestDefaultViews(t *testing.T) {
	got := DefaultViews()
	if len(got) != 5 {
		t.Fatalf("want 5 default views, got %d", len(got))
	}
	for _, v := range got {
		if v.ID == "" || v.Name == "" || len(v.Levels) == 0 {
			t.Fatalf("malformed default view: %+v", v)
		}
	}
}
