// Package model defines SopsHQ's domain records.
//
// Every record embeds Meta, which carries the fields needed for multi-master
// replication: a stable UUID, the HLC timestamp of the last write, the node that
// originated that write, and a soft-delete tombstone. Last-writer-wins uses
// Meta.Updated to decide which side of a conflict survives.
//
// SECURITY: several fields hold vault-sealed secrets - an age PRIVATE key
// (Key.PrivSealed), a panel user's TOTP secret (PanelUser.TOTPSealed), the
// backup password (BackupSettings.PasswordSealed), and each backup destination's
// credential (BackupDest.PasswordSealed / BotTokenSealed). A sealed field is
// ciphertext, safe at rest; the plaintext it protects must never be logged,
// rendered into a template, or written to an audit row.
package model

import "sopshq/internal/hlc"

// Meta is the replication envelope embedded in every stored record.
type Meta struct {
	UUID    string        `json:"uuid"`
	Updated hlc.Timestamp `json:"updated"`
	Origin  string        `json:"origin"` // node id that produced the last write
	Deleted bool          `json:"deleted"`
	// MergedInto redirects a tombstoned record to the record that absorbed it, when it
	// was removed by a merge (an automatic lossless dedup, or an operator-confirmed
	// conflict merge). It lets EVERY reconcile pass re-point a reference that still names
	// the merged-away record onto its live survivor - so a grant another node created
	// against a record this node merged away converges onto the survivor instead of
	// being lost or pruned. Empty on a live record and on a plain (non-merge) delete.
	// (Machine carries its OWN merged_into field for the machine-identity flow; this is
	// the equivalent for every other record kind.)
	MergedInto string `json:"merged_into,omitempty"`
	// FieldVV holds a per-field-group version vector for per-field merge (see
	// merge.go). The key is a field-group name (e.g. "note", "keypair"); the value
	// maps a node id to that node's update counter for the group. It is present only
	// on records whose type implements Merger and only for groups that have actually
	// been written; a group absent here is treated as never-written (a zero vector).
	// A record with no FieldVV at all is a legacy record and falls back to
	// whole-record last-writer-wins by Updated. It carries only version counters, no
	// secret of any kind.
	FieldVV map[string]VClock `json:"field_vv,omitempty"`
}

// Record is satisfied by every stored type via a pointer receiver, giving the
// generic store access to the replication envelope.
type Record interface {
	Meta() *Meta
}

// OS is the operating system family of a machine.
type OS string

const (
	OSLinux   OS = "linux"
	OSWindows OS = "windows"
)

// Role is a panel user's permission level.
type Role string

const (
	RoleAdmin     Role = "admin"     // manage everything
	RoleDeveloper Role = "developer" // rotate keys they are assigned to
)

// KeyType selects the key model.
type KeyType string

const (
	// KeyShared is one keypair per project, placed for several users. Removing a
	// user means rotating the key.
	KeyShared KeyType = "shared"
	// KeyPerUser is one keypair owned by a single user, listed as one of many
	// recipients on the projects they access. Removing a user just drops their
	// recipient and re-keys (no full rotation).
	KeyPerUser KeyType = "per_user"
)

// KeyStatus tracks a key through its rotation lifecycle so an interrupted
// rotation is resumable.
type KeyStatus string

const (
	KeyActive   KeyStatus = "active"
	KeyRotating KeyStatus = "rotating"
	KeyRetired  KeyStatus = "retired"
)

// Machine is a node in the cluster.
//
// Cluster peer identity: a physical machine is ONE record cluster-wide. A node's
// OWN record is its "canonical" record - Canonical is true and, for a fresh
// install, the record UUID equals the node's stable config NodeID, so every peer
// converges on the same single id for that machine. A record the operator typed in
// by address ("Add peer") before the real node has synced is a non-canonical
// placeholder; it merges into the canonical record (by matching name) when that
// node syncs in. A brand-new canonical identity that appears while another
// confirmed peer already exists is held Pending until the operator says whether it
// is a new peer or a reinstall of an existing one.
type Machine struct {
	M             Meta   `json:"meta"`
	Name          string `json:"name"`
	OS            OS     `json:"os"`
	TailscaleHost string `json:"tailscale_host"`
	AgentPort     int    `json:"agent_port"`
	LastSeen      int64  `json:"last_seen"` // Unix seconds, 0 = never
	Version       string `json:"version"`   // agent-reported SopsHQ version
	// Canonical marks a node's OWN self-record (the one whose id is that node's
	// stable identity). A manually-added peer placeholder is not canonical until it
	// merges into the real node's canonical record.
	Canonical bool `json:"canonical,omitempty"`
	// Pending marks a newly-noticed peer identity awaiting operator confirmation
	// (new peer, or reinstall of an existing one). It is set the first time an
	// unrecognized peer is noticed while another confirmed peer already exists, and
	// cleared only by an explicit operator confirmation (or absorbed by a silent
	// placeholder merge). The reconcile pass never clears it, so nodes never fight
	// over it.
	Pending bool `json:"pending,omitempty"`
	// Confirmed records - on the REPLICATED record, so every node sees it - that this
	// peer's identity has been decided (accepted as new, kept as a reinstall survivor,
	// or grandfathered as pre-existing). A confirmed peer is never re-flagged Pending,
	// even on a node that has no local memory of it (a late joiner). It complements the
	// machine-local peers_ack.json: ack is this node's private memory, Confirmed is the
	// cluster-visible fact.
	Confirmed bool `json:"confirmed,omitempty"`
	// MergedInto redirects this (tombstoned) record to the machine that absorbed it.
	// It is set when a machine is merged into another - a placeholder into a
	// canonical record, or a reinstall into the existing peer it replaces - so every
	// node re-points its references to the survivor and a reinstalled node can follow
	// the pointer to rewrite its own local identity. Empty on a live record.
	MergedInto string `json:"merged_into,omitempty"`
}

func (m *Machine) Meta() *Meta { return &m.M }

// OSUser is an operating-system account that holds age private keys on a
// machine (for example alice on the linux server).
type OSUser struct {
	M         Meta   `json:"meta"`
	MachineID string `json:"machine_id"`
	Username  string `json:"username"`
	KeyBase   string `json:"key_base"` // key-store base dir, e.g. ~/.sops or a vault path
}

func (u *OSUser) Meta() *Meta { return &u.M }

// PanelUser is a login account for the admin panel.
type PanelUser struct {
	M           Meta   `json:"meta"`
	Username    string `json:"username"`
	PassHash    string `json:"pass_hash"`    // PBKDF2-HMAC-SHA384 encoded (not the password)
	TOTPSealed  string `json:"totp_sealed"`  // vault-sealed TOTP secret
	TOTPEnabled bool   `json:"totp_enabled"` // false until first verified enrollment
	// RecoveryCodes holds the PBKDF2-HMAC-SHA384 HASHES of one-time backup codes
	// the operator can type at login instead of an authenticator code. SECURITY:
	// these are hashes only - the plaintext codes are shown once at enrollment and
	// never stored. A consumed code's hash is dropped on use.
	RecoveryCodes []string `json:"recovery_codes,omitempty"`
	Role          Role     `json:"role"`
	Enabled       bool     `json:"enabled"`
}

func (u *PanelUser) Meta() *Meta { return &u.M }

// ProjectPath is the absolute folder for a project on one machine (the same
// project lives at different paths on Windows vs Linux).
type ProjectPath struct {
	MachineID string `json:"machine_id"`
	Path      string `json:"path"`
}

// Project is a logical project that maps to a folder per machine.
type Project struct {
	M     Meta          `json:"meta"`
	Name  string        `json:"name"`
	Note  string        `json:"note"`
	Paths []ProjectPath `json:"paths"`
}

func (p *Project) Meta() *Meta { return &p.M }

// Key is an age keypair under SopsHQ custody.
type Key struct {
	M          Meta      `json:"meta"`
	Name       string    `json:"name"`
	Type       KeyType   `json:"type"`
	Note       string    `json:"note"`
	Recipient  string    `json:"recipient"`   // age1... PUBLIC, safe to display
	PrivSealed string    `json:"priv_sealed"` // SECRET: vault-sealed AGE-SECRET-KEY-1...
	Generation int       `json:"generation"`
	Status     KeyStatus `json:"status"`
	CreatedAt  int64     `json:"created_at"` // Unix seconds
	EditedAt   int64     `json:"edited_at"`
	// OwnerUserID is set only for KeyPerUser keys (the single OS user that owns it).
	OwnerUserID string `json:"owner_user_id,omitempty"`
}

func (k *Key) Meta() *Meta { return &k.M }

// GlobalSet is a project-independent ("global") secret set encrypted to one or
// more OS users on a machine, so each can decrypt with their OWN key. The values
// live only in the per-recipient encrypted files on disk (encrypt-and-forget);
// this record just names the set and its recipients so SopsHQ knows whom to
// re-encrypt to and where to place copies. A one-recipient set is the
// "your own global secrets" case.
type GlobalSet struct {
	M         Meta   `json:"meta"`
	Name      string `json:"name"`       // filesystem-safe; the per-recipient dir name
	MachineID string `json:"machine_id"` // the machine whose OS users are recipients
	// RecipientUserIDs are the OS users who can read this set; the set is encrypted
	// to each one's key and a copy is placed in each one's keystore.
	RecipientUserIDs []string `json:"recipient_user_ids"`
}

func (g *GlobalSet) Meta() *Meta { return &g.M }

// Assignment ties a key to a project + machine + OS user. It drives both the
// project's .sops.yaml recipient list and which users receive the private key.
type Assignment struct {
	M         Meta   `json:"meta"`
	KeyID     string `json:"key_id"`
	ProjectID string `json:"project_id"`
	MachineID string `json:"machine_id"`
	OSUserID  string `json:"os_user_id"`
}

func (a *Assignment) Meta() *Meta { return &a.M }

// Default filename presets for a freshly created BackupSettings record. They are
// here (not in the backup package) so creating a record needs no extra import.
const (
	DefaultBackupBaseName     = "sopshq-backup"
	DefaultBackupDateFormat   = "20060102-150405"
	DefaultBackupDatePosition = "suffix"
)

// BackupSettings is one machine's scheduled-backup configuration. It is a normal
// replicated record (it embeds Meta and flows through the oplog), but it is
// scoped to ONE machine via MachineID: each node reads and executes only the
// record whose MachineID equals its own, because a destination (a local folder, an
// FTP host) is specific to the machine that owns it. When Enabled, that machine
// builds a sealed archive once per day at DailyAt and sends it to every
// destination.
type BackupSettings struct {
	M Meta `json:"meta"`
	// MachineID is the Machine record this configuration belongs to. The owning
	// node is the only one that acts on it.
	MachineID string `json:"machine_id"`
	// Enabled turns the daily backup on or off.
	Enabled bool `json:"enabled"`
	// DailyAt is the local time of day to run, "HH:MM" 24-hour (e.g. "03:30").
	DailyAt string `json:"daily_at"`
	// PasswordSealed is a vault-sealed ciphertext of the backup password. SECRET:
	// it is never the plaintext password and is never logged.
	PasswordSealed string `json:"password_sealed"`
	// BaseName is the archive filename stem (default "sopshq-backup").
	BaseName string `json:"base_name"`
	// DateFormat is one of the supported datetime presets (a Go reference layout,
	// or "unix" for epoch seconds) stamped into the filename.
	DateFormat string `json:"date_format"`
	// DatePosition places the datetime stamp as "prefix" or "suffix" of BaseName.
	DatePosition string `json:"date_position"`
	// Destinations are where each backup is sent.
	Destinations []BackupDest `json:"destinations"`
}

func (b *BackupSettings) Meta() *Meta { return &b.M }

// BackupDest is one backup destination. The fields used depend on Type: "local"
// uses Folder; "ftp" uses Host/Port/User/PasswordSealed/Path/FTPS; "telegram"
// uses BotTokenSealed/ChatID. SECURITY: the credential fields (PasswordSealed,
// BotTokenSealed) hold VAULT-SEALED ciphertext, never a plaintext credential -
// because this record replicates to the peer's store. They are unsealed in-process
// only at send time and are never logged. The non-secret fields stay plaintext.
type BackupDest struct {
	// Type is "local", "ftp", or "telegram".
	Type string `json:"type"`
	// Folder is the local destination directory (defaults to the data dir if empty).
	Folder string `json:"folder,omitempty"`
	// Host is the FTP server host.
	Host string `json:"host,omitempty"`
	// Port is the FTP server port (0 means the FTP default, 21).
	Port int `json:"port,omitempty"`
	// User is the FTP username.
	User string `json:"user,omitempty"`
	// PasswordSealed is the vault-sealed FTP password (SECRET).
	PasswordSealed string `json:"password_sealed,omitempty"`
	// Path is the remote FTP directory to upload into.
	Path string `json:"path,omitempty"`
	// FTPS requests explicit FTPS (AUTH TLS) for the FTP upload.
	FTPS bool `json:"ftps,omitempty"`
	// BotTokenSealed is the vault-sealed Telegram bot token (SECRET).
	BotTokenSealed string `json:"bot_token_sealed,omitempty"`
	// ChatID is the Telegram chat/channel id to send to.
	ChatID string `json:"chat_id,omitempty"`
}
