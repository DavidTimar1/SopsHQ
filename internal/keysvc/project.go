package keysvc

import (
	"errors"
	"fmt"
	"strings"

	"sopshq/internal/audit"
	"sopshq/internal/model"
	"sopshq/internal/store"
)

// Project creation. A project is a SINGLE record referenced from every machine
// (unlike a global set, which is scoped to one machine), so its name must be
// unique across the WHOLE cluster. CreateProject is the one entry point every
// creation path routes through; it enforces a case-insensitive unique name.

var (
	// ErrProjectNameEmpty means the trimmed project name is empty.
	ErrProjectNameEmpty = errors.New("keysvc: project name is required")
	// ErrProjectExists means a live project already uses that name (compared
	// case-insensitively after trimming).
	ErrProjectExists = errors.New("keysvc: a project with that name already exists")
)

// ProjectNameTaken reports whether a live (non-tombstoned) project already uses
// name, comparing case-insensitively after trimming surrounding whitespace.
// excludeID, when non-empty, is skipped so a project never collides with itself
// (used by a self-name check). Deleted projects are tombstoned and hidden by the
// store's List, so a deleted project's name is free to reuse.
func (s *Service) ProjectNameTaken(name, excludeID string) bool {
	name = strings.TrimSpace(name)
	for _, p := range s.store.Projects.List() {
		if p.M.UUID == excludeID {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(p.Name), name) {
			return true
		}
	}
	return false
}

// CreateProject creates a new project record after enforcing a case-insensitive,
// cluster-wide unique name. It trims the name and note, rejects an empty name
// with ErrProjectNameEmpty, and rejects a name that collides with an existing
// live project with ErrProjectExists. On success it audits the creation by name.
func (s *Service) CreateProject(name, note, actor string) (*model.Project, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, ErrProjectNameEmpty
	}
	if s.ProjectNameTaken(name, "") {
		return nil, ErrProjectExists
	}
	p := &model.Project{
		M:    model.Meta{UUID: store.NewID()},
		Name: name,
		Note: strings.TrimSpace(note),
	}
	if err := s.store.Projects.Put(p); err != nil {
		return nil, fmt.Errorf("keysvc: save project: %w", err)
	}
	_ = s.audit.Record(actor, "project_create", name, audit.OK, "")
	return p, nil
}
