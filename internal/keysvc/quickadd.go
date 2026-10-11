package keysvc

import (
	"errors"
	"fmt"

	"sopshq/internal/access"
	"sopshq/internal/keys"
	"sopshq/internal/model"
	"sopshq/internal/store"
)

// Quick add: a guided one-shot that adds a secret end to end. The operator picks
// the secret, a scope (project or global), and the target project/users; RunQuickAdd
// creates whatever is missing, places keys, applies, and encrypts - reusing the
// existing audited operations. ValidateQuickAdd runs the non-destructive pre-flight
// checks (filesystem access, home dir, name collisions, re-encryption) first.

// QuickAddInput is the plan from the wizard.
type QuickAddInput struct {
	Name, Value string
	Scope       string // "project" | "global"

	// Project scope: an existing project, or a new one (name + local path).
	ProjectID      string
	NewProjectName string
	ProjectPath    string

	// Global scope: an existing set, or a new one (name). Recipients are UserIDs.
	GlobalSetID string
	NewSetName  string

	// Selected existing LOCAL OS users. Project scope: granted access (key assigned
	// + placed). Global scope: the set's recipients.
	UserIDs []string
}

// QuickAddAlert is one non-secret pre-flight finding.
type QuickAddAlert struct {
	Level string // "block" | "warn" | "info"
	Text  string
}

const (
	alertBlock = "block"
	alertWarn  = "warn"
	alertInfo  = "info"
)

// QuickAddResult reports what RunQuickAdd did, step by step (names/locations only).
type QuickAddResult struct {
	Steps []string
}

// resolveProjectPath returns the local path Quick add will use for the project: an
// existing project's local path, or the new path the operator typed.
func (s *Service) resolveProjectPath(in QuickAddInput) string {
	if in.ProjectID != "" {
		if p, err := s.store.Projects.Get(in.ProjectID); err == nil {
			if d := s.localProjectPath(p); d != "" {
				return d
			}
		}
	}
	return in.ProjectPath
}

// ValidateQuickAdd runs the non-destructive checks and returns alerts. A "block"
// alert means RunQuickAdd would refuse; "warn"/"info" are advisory.
func (s *Service) ValidateQuickAdd(in QuickAddInput) []QuickAddAlert {
	var a []QuickAddAlert
	if s.localMachineID == "" {
		return []QuickAddAlert{{alertBlock, "Designate this machine first (Machines -> this machine)."}}
	}
	if in.Name == "" || !keys.ValidSecretName(in.Name) {
		a = append(a, QuickAddAlert{alertBlock, "Enter a valid secret name (letters, digits, '_', '-', '.')."})
	}
	if len(in.UserIDs) == 0 {
		a = append(a, QuickAddAlert{alertBlock, "Select at least one OS user."})
	}

	switch in.Scope {
	case "project":
		path := s.resolveProjectPath(in)
		if in.ProjectID == "" && in.NewProjectName == "" {
			a = append(a, QuickAddAlert{alertBlock, "Pick an existing project or name a new one."})
		}
		if in.ProjectID == "" && in.NewProjectName != "" && s.ProjectNameTaken(in.NewProjectName, "") {
			a = append(a, QuickAddAlert{alertBlock, fmt.Sprintf("A project named %q already exists.", in.NewProjectName)})
		}
		if path == "" {
			a = append(a, QuickAddAlert{alertBlock, "Set the project's local folder path."})
		}
		if in.ProjectID != "" {
			if names, err := s.ListSecrets(in.ProjectID); err == nil {
				for _, n := range names {
					if n == in.Name {
						a = append(a, QuickAddAlert{alertWarn, fmt.Sprintf("Secret %q already exists in this project; it will be overwritten.", in.Name)})
					}
				}
				if len(names) > 0 {
					a = append(a, QuickAddAlert{alertInfo, "This project already has secrets; adding one re-encrypts its secrets.yaml (expected)."})
				}
			}
		}
		a = append(a, s.userAccessAlerts(in.UserIDs, path)...)
	case "global":
		if in.GlobalSetID == "" && in.NewSetName == "" {
			a = append(a, QuickAddAlert{alertBlock, "Pick an existing shared set or name a new one."})
		}
		if in.GlobalSetID == "" && in.NewSetName != "" && !setNameRe.MatchString(in.NewSetName) {
			a = append(a, QuickAddAlert{alertBlock, "Set name may use only letters, digits, '_' and '-'."})
		}
		// Each reader needs a per_user key they OWN to encrypt the set to.
		for _, uid := range in.UserIDs {
			u, err := s.store.OSUsers.Get(uid)
			if err != nil {
				continue
			}
			if s.ownedKey(uid) == nil {
				a = append(a, QuickAddAlert{alertBlock, fmt.Sprintf("OS user %q owns no per-user key yet - create a per-user key for them first (Keys -> type per_user).", u.Username)})
			}
			// Resolve the real store base: a root-derived user has an empty KeyBase but a
			// store under keybase_root, so the access check must target the resolved path.
			a = append(a, s.userAccessAlerts([]string{uid}, s.userKeyBase(u))...)
		}
		if in.GlobalSetID != "" {
			if names, err := s.ListGlobalSecrets(in.GlobalSetID); err == nil {
				for _, n := range names {
					if n == in.Name {
						a = append(a, QuickAddAlert{alertWarn, fmt.Sprintf("Secret %q already exists in this set; it will be overwritten.", in.Name)})
					}
				}
			}
		}
	default:
		a = append(a, QuickAddAlert{alertBlock, "Choose a scope: project or global."})
	}
	return a
}

// userAccessAlerts checks each user's home dir and filesystem access to dir.
func (s *Service) userAccessAlerts(userIDs []string, dir string) []QuickAddAlert {
	var a []QuickAddAlert
	for _, uid := range userIDs {
		u, err := s.store.OSUsers.Get(uid)
		if err != nil {
			continue
		}
		if _, ok, reason := access.UserHasHome(u.Username); !ok && reason != "" {
			a = append(a, QuickAddAlert{alertWarn, fmt.Sprintf("%s: %s", u.Username, reason)})
		}
		if dir == "" {
			continue
		}
		res := access.CanReadDir(u.Username, dir)
		if !res.OK && res.Evaluated {
			a = append(a, QuickAddAlert{alertWarn, fmt.Sprintf("%s may not be able to read %s: %s", u.Username, dir, res.Reason)})
		} else if !res.Evaluated {
			a = append(a, QuickAddAlert{alertInfo, fmt.Sprintf("Could not fully verify %s's access to %s: %s", u.Username, dir, res.Reason)})
		}
	}
	return a
}

// hasBlock reports whether any alert blocks the run.
func hasBlock(alerts []QuickAddAlert) bool {
	for _, x := range alerts {
		if x.Level == alertBlock {
			return true
		}
	}
	return false
}

// RunQuickAdd executes the plan, creating what is missing, placing keys, applying,
// and encrypting. It re-validates first and refuses on any blocking alert.
func (s *Service) RunQuickAdd(in QuickAddInput, actor string) (QuickAddResult, error) {
	var res QuickAddResult
	if hasBlock(s.ValidateQuickAdd(in)) {
		return res, errors.New("keysvc: quick add has blocking problems; fix them first")
	}
	switch in.Scope {
	case "project":
		return s.runQuickAddProject(in, actor, &res)
	case "global":
		return s.runQuickAddGlobal(in, actor, &res)
	default:
		return res, errors.New("keysvc: unknown scope")
	}
}

func (s *Service) runQuickAddProject(in QuickAddInput, actor string, res *QuickAddResult) (QuickAddResult, error) {
	projectID := in.ProjectID
	if projectID == "" {
		p, err := s.CreateProject(in.NewProjectName, "", actor)
		if err != nil {
			return *res, fmt.Errorf("create project: %w", err)
		}
		projectID = p.M.UUID
		res.Steps = append(res.Steps, "created project "+in.NewProjectName)
	}
	// Ensure the local folder path is set.
	p, err := s.store.Projects.Get(projectID)
	if err != nil {
		return *res, err
	}
	if s.localProjectPath(p) == "" && in.ProjectPath != "" {
		p.Paths = append(p.Paths, model.ProjectPath{MachineID: s.localMachineID, Path: in.ProjectPath})
		if err := s.store.Projects.Put(p); err != nil {
			return *res, fmt.Errorf("set path: %w", err)
		}
		res.Steps = append(res.Steps, "set folder path "+in.ProjectPath)
	}
	// Wire (generates + assigns + applies a shared key if not already wired).
	if err := s.EnsureProjectWired(projectID, actor); err != nil {
		if errors.Is(err, ErrWiringConflict) {
			return *res, errors.New("the folder already has SOPS/age state - wire it on the project page (Reuse/Re-create) first, then re-run")
		}
		return *res, fmt.Errorf("wire project: %w", err)
	}
	res.Steps = append(res.Steps, "wired the project (key generated, assigned, placed)")
	// Grant the selected users access by assigning the project's key to each.
	p, _ = s.store.Projects.Get(projectID)
	k := s.assignedGeneratedKey(p)
	if k != nil {
		for _, uid := range in.UserIDs {
			if s.HasAssignment(k.M.UUID, projectID, s.localMachineID, uid) {
				continue
			}
			a := &model.Assignment{
				M: model.Meta{UUID: store.NewID()}, KeyID: k.M.UUID,
				ProjectID: projectID, MachineID: s.localMachineID, OSUserID: uid,
			}
			if err := s.store.Assignments.Put(a); err != nil {
				return *res, fmt.Errorf("assign key: %w", err)
			}
			if u, e := s.store.OSUsers.Get(uid); e == nil {
				res.Steps = append(res.Steps, "granted "+u.Username+" access")
			}
		}
	}
	if _, err := s.ApplyLocal(actor, false); err != nil {
		return *res, fmt.Errorf("apply: %w", err)
	}
	res.Steps = append(res.Steps, "applied (placed keys, wrote .sops.yaml)")
	if err := s.SetSecret(projectID, in.Name, in.Value, actor); err != nil {
		return *res, fmt.Errorf("set secret: %w", err)
	}
	res.Steps = append(res.Steps, "encrypted secret "+in.Name)
	return *res, nil
}

func (s *Service) runQuickAddGlobal(in QuickAddInput, actor string, res *QuickAddResult) (QuickAddResult, error) {
	setID := in.GlobalSetID
	if setID == "" {
		// Map each selected reader to the per_user key they own; the set is built by
		// selecting those keys (CreateGlobalSet derives the owners back).
		var keyIDs []string
		for _, uid := range in.UserIDs {
			k := s.ownedKey(uid)
			if k == nil {
				return *res, fmt.Errorf("create set: an OS user owns no per-user key to encrypt to")
			}
			keyIDs = append(keyIDs, k.M.UUID)
		}
		set, err := s.CreateGlobalSet(in.NewSetName, keyIDs, actor)
		if err != nil {
			return *res, fmt.Errorf("create set: %w", err)
		}
		setID = set.M.UUID
		res.Steps = append(res.Steps, "created shared set "+in.NewSetName)
	}
	if err := s.SetGlobalSecret(setID, in.Name, in.Value, actor); err != nil {
		return *res, fmt.Errorf("set secret: %w", err)
	}
	res.Steps = append(res.Steps, "encrypted secret "+in.Name+" for the set's users")
	return *res, nil
}

// OSUserHasKey reports whether an OS user has a generated key assigned (so it can
// receive global secrets or already participates in a project).
func (s *Service) OSUserHasKey(osUserID string) bool { return s.userGeneratedKey(osUserID) != nil }

// HasAssignment reports whether an Assignment for this exact key + project + machine
// + OS user already exists, so every assignment-creating path can be idempotent
// (never a duplicate row for the same real-world grant). An empty projectID matches
// an assignment with no project (an adopted key linked to a user + machine only).
func (s *Service) HasAssignment(keyID, projectID, machineID, osUserID string) bool {
	for _, a := range s.store.Assignments.List() {
		if a.KeyID == keyID && a.ProjectID == projectID && a.MachineID == machineID && a.OSUserID == osUserID {
			return true
		}
	}
	return false
}
