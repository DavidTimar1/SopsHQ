package keysvc

import (
	"errors"
	"testing"
)

// TestCreateProjectRejectsDuplicateName covers the name-uniqueness guard: a
// distinct name succeeds, an exact-duplicate and a different-case duplicate are
// both rejected, and an empty name is rejected.
func TestCreateProjectRejectsDuplicateName(t *testing.T) {
	svc, _, _ := build(t)

	if _, err := svc.CreateProject("webshop", "", "tester"); err != nil {
		t.Fatalf("first create should succeed, got %v", err)
	}

	if _, err := svc.CreateProject("webshop", "", "tester"); !errors.Is(err, ErrProjectExists) {
		t.Fatalf("exact duplicate: want ErrProjectExists, got %v", err)
	}
	if _, err := svc.CreateProject("WebShop", "", "tester"); !errors.Is(err, ErrProjectExists) {
		t.Fatalf("case-insensitive duplicate: want ErrProjectExists, got %v", err)
	}
	// Surrounding whitespace must not sneak a duplicate past the guard.
	if _, err := svc.CreateProject("  webshop  ", "", "tester"); !errors.Is(err, ErrProjectExists) {
		t.Fatalf("whitespace duplicate: want ErrProjectExists, got %v", err)
	}

	if _, err := svc.CreateProject("billing", "", "tester"); err != nil {
		t.Fatalf("distinct name should succeed, got %v", err)
	}

	if _, err := svc.CreateProject("   ", "", "tester"); !errors.Is(err, ErrProjectNameEmpty) {
		t.Fatalf("empty name: want ErrProjectNameEmpty, got %v", err)
	}
}

// TestCreateProjectFreesTombstonedName confirms that deleting a project frees
// its name for reuse (the store hides tombstoned records from List).
func TestCreateProjectFreesTombstonedName(t *testing.T) {
	svc, st, _ := build(t)

	p, err := svc.CreateProject("webshop", "", "tester")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := st.Projects.Delete(p.M.UUID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if svc.ProjectNameTaken("webshop", "") {
		t.Fatal("tombstoned project name should be free to reuse")
	}
	if _, err := svc.CreateProject("WEBSHOP", "", "tester"); err != nil {
		t.Fatalf("reuse of a tombstoned name should succeed, got %v", err)
	}
}

// TestProjectNameTakenExcludesSelf confirms the excludeID skip: a project's own
// name does not count as taken (a self-name check is a no-op), while any other
// live project's name does.
func TestProjectNameTakenExcludesSelf(t *testing.T) {
	svc, _, _ := build(t)

	p, err := svc.CreateProject("webshop", "", "tester")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if svc.ProjectNameTaken("webshop", p.M.UUID) {
		t.Fatal("a project's own name must not count as taken when excluded")
	}
	if svc.ProjectNameTaken("WebShop", p.M.UUID) {
		t.Fatal("case-insensitive self-name must not count as taken when excluded")
	}

	other, err := svc.CreateProject("billing", "", "tester")
	if err != nil {
		t.Fatalf("create other: %v", err)
	}
	if !svc.ProjectNameTaken("webshop", other.M.UUID) {
		t.Fatal("another live project's name must count as taken")
	}
}
