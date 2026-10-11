package keysvc

import (
	"fmt"
	"path/filepath"
	"strings"

	"sopshq/internal/agent"
	"sopshq/internal/audit"
	"sopshq/internal/keys"
	"sopshq/internal/model"
	"sopshq/internal/place"
	"sopshq/internal/transport"
)

// remote is the subset of agent.Client that ApplyAll and the drift probe need.
// Defining it here lets tests inject an in-process agent without a real network.
type remote interface {
	Place(agent.PlaceRequest) error
	WriteSopsYAML(agent.SopsYAMLRequest) error
	UpdateKeys(agent.UpdateKeysRequest) (int, error)
	Inspect(agent.InspectRequest) (agent.InspectResponse, error)
}

// SetTransferKey gives the service the shared transfer key used to authenticate
// to peer agents. Until set (non-empty), the service does not dial peers.
func (s *Service) SetTransferKey(token string) { s.transferKey = token }

// SetDialer overrides how a Machine is turned into a remote agent client (tests).
func (s *Service) SetDialer(f func(*model.Machine) (remote, bool)) { s.dialer = f }

// dialRemote resolves a Machine record to a peer agent client over HTTP, using the
// shared transfer key. It returns false for the local machine, when no transfer
// token is set, or when the machine has no reachable address.
func (s *Service) dialRemote(m *model.Machine) (remote, bool) {
	if s.dialer != nil {
		return s.dialer(m)
	}
	if m.M.UUID == s.localMachineID || s.transferKey == "" {
		return nil, false
	}
	if m.TailscaleHost == "" || m.AgentPort == 0 {
		return nil, false
	}
	return agent.Dial(transport.AgentBaseURL(m.TailscaleHost, m.AgentPort), s.transferKey), true
}

// keysWriteAndRekey writes a project's .sops.yaml locally and re-keys its secret
// files with the current private key.
func keysWriteAndRekey(dir string, recips []keys.Recipient, current string) error {
	if err := keys.WriteSopsYAML(dir, recips); err != nil {
		return err
	}
	if current != "" {
		if _, err := keys.UpdateKeysInDir(dir, current); err != nil {
			return err
		}
	}
	return nil
}

// ApplyAll reconciles desired state across ALL machines: local placements are
// done in-process; remote placements are pushed to each machine's agent over the
// agent channel (plain HTTP over Tailscale, authenticated by the shared transfer
// token). A machine that is neither local nor enrolled is reported in Skipped.
func (s *Service) ApplyAll(actor string, dryRun bool) (ApplyReport, error) {
	var rep ApplyReport
	if s.localMachineID == "" {
		return rep, ErrNoLocalMachine
	}

	// 1) Place keys for every (machine, user) pair ONCE, writing that user's FULL
	//    set of assigned keys (a user in several projects keeps all their keys in one
	//    keys.txt). Grouping avoids each assignment overwriting the previous key.
	type machineUser struct{ machineID, userID string }
	done := map[machineUser]bool{}
	for _, a := range s.store.Assignments.List() {
		mc, err := s.store.Machines.Get(a.MachineID)
		if err != nil {
			rep.skip("?", "assignment", "assignment references a missing machine")
			continue
		}
		k, err := s.store.Keys.Get(a.KeyID)
		if err != nil || k.Recipient == "" {
			rep.skip(mc.Name, "assignment", "key missing or not generated for an assignment")
			continue
		}
		u, err := s.store.OSUsers.Get(a.OSUserID)
		if err != nil {
			rep.skip(mc.Name, "assignment", "OS user missing or has no key base")
			continue
		}
		base := s.userKeyBase(u)
		if base == "" {
			rep.skip(mc.Name, "assignment", "OS user missing or has no key base")
			continue
		}
		grp := machineUser{mc.M.UUID, u.M.UUID}
		if done[grp] {
			continue
		}
		done[grp] = true

		priv, pub, names, err := s.userKeyMaterial(mc.M.UUID, u.M.UUID)
		if err != nil {
			return rep, err
		}
		target := u.Username + "@" + mc.Name
		keyFile := place.KeyFile(base)
		for _, name := range names {
			rep.placedKey(mc.Name, target, name+" -> "+keyFile)
		}
		if dryRun {
			continue
		}
		if mc.M.UUID == s.localMachineID {
			if err := s.placer(s.localPlaceOpts(u, pub, priv)); err != nil {
				return rep, fmt.Errorf("local place for %q: %w", u.Username, err)
			}
		} else {
			cli, ok := s.dialRemote(mc)
			if !ok {
				rep.skip(mc.Name, target, fmt.Sprintf("machine %q not enrolled; cannot place remotely", mc.Name))
				continue
			}
			if err := cli.Place(agent.PlaceRequest{Base: base, Recipient: pub, Private: priv, Username: u.Username}); err != nil {
				return rep, fmt.Errorf("remote place on %q: %w", mc.Name, err)
			}
		}
		_ = s.audit.Record(actor, "key_place", strings.Join(names, ","), audit.OK, fmt.Sprintf("%s on %s", u.Username, mc.Name))
	}

	// 2) Write .sops.yaml + re-key for every project path, on whichever machine.
	for _, p := range s.store.Projects.List() {
		recips, current := s.projectRecipients(p)
		if len(recips) == 0 {
			continue
		}
		for _, pp := range p.Paths {
			mc, err := s.store.Machines.Get(pp.MachineID)
			if err != nil {
				continue
			}
			sopsPath := filepath.Join(pp.Path, ".sops.yaml")
			if dryRun {
				rep.wiredProject(mc.Name, p.Name, sopsPath)
				continue
			}
			if mc.M.UUID == s.localMachineID {
				if err := keysWriteAndRekey(pp.Path, recips, current); err != nil {
					return rep, fmt.Errorf("local wire %q: %w", p.Name, err)
				}
			} else {
				cli, ok := s.dialRemote(mc)
				if !ok {
					rep.skip(mc.Name, p.Name, fmt.Sprintf("machine %q not enrolled; cannot wire %q", mc.Name, p.Name))
					continue
				}
				if err := cli.WriteSopsYAML(agent.SopsYAMLRequest{Dir: pp.Path, Recipients: recips}); err != nil {
					return rep, fmt.Errorf("remote wire %q on %q: %w", p.Name, mc.Name, err)
				}
				if current != "" {
					if n, err := cli.UpdateKeys(agent.UpdateKeysRequest{Dir: pp.Path, CurrentPriv: current}); err != nil {
						return rep, fmt.Errorf("remote updatekeys %q on %q: %w", p.Name, mc.Name, err)
					} else if n > 0 {
						rep.rekeyedSecrets(mc.Name, p.Name, n)
					}
				}
			}
			_ = s.audit.Record(actor, "sops_yaml_write", p.Name, audit.OK, mc.Name+":"+pp.Path)
			rep.wiredProject(mc.Name, p.Name, sopsPath)
		}
	}

	_ = s.audit.Record(actor, "apply_all", s.localMachineID, audit.OK,
		fmt.Sprintf("placed=%d wired=%d rekeyed=%d", rep.KeysPlaced, rep.ProjectsWired, rep.FilesRekeyed))
	return rep, nil
}
