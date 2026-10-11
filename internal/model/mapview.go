package model

// MapView is a custom, operator-defined "Map" tree layout. It names an ordered
// list of group-by attribute keys (the folder levels, outermost first) plus a
// leaf attribute key (the innermost level, rendered as items rather than
// folders). The Map page builds a nested tree by grouping the live records in
// that order, so the same records can be drilled down in whatever order the
// operator finds useful.
//
// Attribute keys are the fixed vocabulary the tree-builder understands: Project,
// Machine, OSUser, Path, Key, SecretName, GlobalSet. A MapView holds only those
// short ASCII keys and a display name - no record references and no secret of any
// kind - so it replicates verbatim like any other record (it embeds Meta and
// flows through the store's Put/Delete and the oplog).
type MapView struct {
	M Meta `json:"meta"`
	// Name is the operator-facing label shown on the view's tab.
	Name string `json:"name"`
	// GroupBy is the ordered list of grouping (folder) attribute keys, outermost
	// level first. An empty or odd ordering is tolerated by the tree-builder.
	GroupBy []string `json:"group_by"`
	// Leaf is the innermost attribute key, whose nodes render as items (leaves)
	// rather than folders.
	Leaf string `json:"leaf"`
}

func (v *MapView) Meta() *Meta { return &v.M }
