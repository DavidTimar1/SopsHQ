# Conflict resolution

This document explains what happens when SopsHQ finds **two records that look like the
same thing but disagree on a value**, why it refuses to merge them automatically, and how
an operator resolves each one safely. Every term is defined on first use. For the
overview, start at the [architecture index](README.md).

It builds on two neighbours:

- [Replication](replication.md): how the machines copy each other's records.
- [Cluster peer identity](peer-identity.md): how duplicate **machine** records heal, the
  new-versus-reinstall confirmation, and the automatic lossless de-duplication.

## Contents

- [Two kinds of conflict](#two-kinds-of-conflict)
- [Why duplicates that disagree are kept](#why-duplicates-that-disagree-are-kept)
- [What counts as a conflict](#what-counts-as-a-conflict)
- [Merge into one](#merge-into-one)
- [Keep both](#keep-both)
- [Machines](#machines)
- [The flow at a glance](#the-flow-at-a-glance)
- [References survive a merge on the other machine](#references-survive-a-merge-on-the-other-machine)
- [No field is dropped by the automatic merge](#no-field-is-dropped-by-the-automatic-merge)
- [Who can resolve](#who-can-resolve)
- [Safety properties](#safety-properties)
- [Known limits](#known-limits)

## Two kinds of conflict

The `/conflicts` page lists two kinds:

- **Duplicate records:** two SEPARATE records (different ids) that describe the same thing
  but disagree. Most of this document is about these.
- **Field conflicts:** ONE record whose SAME field two machines changed to different
  values at once, for example a key's note edited on both. They come from
  [per-field merge](replication.md#per-field-merge). They are resolved with the same
  two-step, double-confirmed pick described below, but delete no record: they write the
  winning value.

## Why duplicates that disagree are kept

Two machines can independently create records that describe the same thing: the same
project by name, the same account on the same machine, the same public key.

- **Usually they are identical**, and the reconcile pass folds them together with no loss
  (see [peer identity](peer-identity.md#lossless-only-de-duplication-of-everything-else)).
- **Sometimes they disagree on a real value.** Two records for the same public key hold
  *different* sealed private halves; the same project points at a *different* folder on
  the same machine; the same account names a *different* key store. Folding one away
  would silently delete that value, so the reconcile pass **skips the merge and keeps both
  records**.

The rule:

> Never destroy data to de-duplicate. If a merge would drop a value, keep both records and
> let a human decide, showing exactly what would be deleted and confirming it twice.

The Conflicts page is the operator's flow for those duplicates.

## What counts as a conflict

A **conflict group** is two or more live records that share a **natural key** (what makes
them "the same") but disagree on at least one non-empty field.

| Record kind             | Natural key                                 | Can they be genuinely different things? |
|-------------------------|---------------------------------------------|---------------------------------|
| Key                     | the public key                              | yes: keep both allowed          |
| Project                 | the project name                            | yes                             |
| OS user                 | machine and username                        | yes                             |
| Machine                 | the machine name                            | yes                             |
| Map view                | the view name                               | yes                             |
| Backup settings         | the machine (one record per machine)        | **no**: merge only              |
| Notification settings   | the machine (one record per machine)        | **no**: merge only              |

A machine can have only one settings record of each kind, so "keep both" makes no sense
there; the only resolution is to merge and pick which value wins.

**Detection is read-only and exact.** It reuses the same "do these disagree?" tests the
reconcile pass uses to decide what to skip, and replays the same merge sequence on a
throwaway copy. So it surfaces precisely the groups the lossless pass leaves intact, never
more and never less, and it writes nothing.

**Only non-secret facts are shown.** For each record the page shows what helps tell them
apart, and marks which field differs:

- machine name, key-store path, project folder, advertised address;
- presence flags such as "sealed password present: yes" or "telegram channel set: yes";
- when the record was created and which machine it came from.

It **never** shows a sealed private key, a password, a token, or any secret value. A
differing secret is shown by presence and origin only ("sealed private key present, from
linux-server").

## Merge into one

Merging folds the group into **one** surviving record and removes the duplicates. Because
it deletes data, it takes two confirmations:

1. **Review.** The page shows which record is **kept** and which is **removed**, with a
   radio button for each field that really differs, so the operator picks the winning
   value. Every field only one record set, and every reference (key grants, project paths,
   account and machine references), is kept automatically.
2. **Confirm deletion.** Submitting the picks opens a **separate** page that states exactly
   which record will be permanently deleted ("Permanently delete record X on machine Y.
   This cannot be undone.") and requires a checkbox.
3. **Execute.** Only the confirmation page reaches the execute step, which refuses unless
   the checkbox is present. A deletion is impossible without both confirmations.

On execute:

- the survivor gains every field that can merge without loss;
- the operator's chosen value is applied for each conflicting field;
- **every reference moves to the survivor**: assignments' key, project, account and
  machine ids, a project's paths, global-set readers, the settings records' machine id,
  and, if this machine's own record is the one absorbed, the running node's stored
  machine id;
- duplicate assignments are removed;
- finally the losers are tombstoned (a soft delete that replicates).

Nothing that was not shown and confirmed is dropped.

## Keep both

If the records are genuinely **different things** that happen to share a natural key, the
operator clicks **Keep both**.

- SopsHQ writes a small replicated marker, a `DistinctAck` record (the record kind and the
  record ids), saying "these are intentionally distinct".
- The page stops listing that group, and because the marker replicates, **the other
  machines reach the same decision**.
- Keep both deletes nothing, so it needs one confirmation.
- If a *third* record later appears with the same natural key, the marker no longer covers
  the larger group, and the conflict comes back for a fresh decision.
- Keep both is refused for the per-machine settings kinds (backup, notifications), where
  two records cannot both be valid.

## Machines

A new machine that appears while a peer already exists is still handled by the
new-versus-reinstall confirmation on the Machines page (see
[peer identity](peer-identity.md#add-peer-and-the-new-versus-reinstall-question)); it is
not repeated here.

- The Conflicts page adds the case of two **confirmed** same-name machine records that
  disagree on a value (address, port, OS, version): the operator merges and picks, or
  keeps both.
- A machine still awaiting the new-versus-reinstall decision is left to the Machines page
  and is not listed here too.

## The flow at a glance

```mermaid
flowchart TD
  A[Two machines replicate records] --> B{Do two records share a natural key?}
  B -- no --> Z[Nothing to do]
  B -- yes --> C{Do they disagree on a non-empty field?}
  C -- no --> D[Reconcile folds them losslessly: automatic, no loss]
  C -- yes --> E[Reconcile SKIPS the merge and keeps BOTH]
  E --> F[Conflicts page lists the group with non-secret facts]
  F --> G{Operator decision}
  G -- keep both --> H[Write replicated DistinctAck marker]
  H --> I[Group no longer flagged; both machines converge]
  G -- merge --> J[Step 1: review kept vs deleted, pick winning values]
  J --> K[Step 2: separate page confirms exact deletion + checkbox]
  K -- confirmed --> L[Union fields, re-point references, tombstone loser]
  K -- not confirmed --> F
  L --> M[Duplicate removed; change replicates]
```

## References survive a merge on the other machine

Machines act independently, so one machine can create a **grant** (an assignment, or a
global-set membership) naming a record that another machine merges away before the two
have synced. A merge therefore does not simply delete the duplicate:

- **A merge pointer.** When any duplicate is removed, by the automatic de-duplication or by
  an operator merge, its tombstone carries a durable **merged-into** pointer to the
  survivor (`Meta.MergedInto`). The pointer replicates like any field.
- **Every reconcile re-points.** Any reference that still names a merged-away record moves
  to its live survivor: an assignment's key, project or account id, and a global set's
  reader membership. A membership pointing at a merged-away account moves; it is never
  dropped.
- **Pruning is merge-aware.** A grant whose parent was **merged** is re-pointed, not
  pruned. Pruning only removes a grant whose parent is truly deleted (a tombstone with no
  merge pointer).

So when machine A merges k2 into k1 while machine B, not yet synced, creates a grant
against k2, B's grant points at k1 once B syncs and reconciles. Nothing dangles, nothing is
pruned.

## No field is dropped by the automatic merge

The automatic merge folds a duplicate away only when that loses nothing, and every field is
covered:

| Situation | What happens |
|---|---|
| A field only one record set | filled into the survivor |
| A list (project paths, global-set readers, per-event notification toggles) | unioned |
| A field both records set to **different** non-empty values | the automatic merge is blocked, and the pair is listed as a conflict |

This covers the sealed credentials and paths, and also the secondary fields: a
notification record's per-event toggles, a backup record's archive name pattern (base
name, date format, date position), a project's note, and a key's type.

A key's display **name** is the one deliberate exception. The same public key adopted
under two labels on two machines is one identity, so the names fold (the survivor keeps its
own) rather than blocking convergence on a cosmetic difference.

So the rule holds for the automatic path as for the operator path: **no differing
non-empty value is dropped without appearing as a conflict.**

## Who can resolve

- Any logged-in user can view the Conflicts list.
- **Resolving** a conflict, by merging (which deletes a record and chooses which sealed
  credential survives) or keeping both, is **admin-only**, matching the backup and
  notification settings it can change.

## Safety properties

- **No silent loss.** Detection lists exactly what the lossless pass keeps; a merge deletes
  only after two confirmations naming what is removed; every reference moves before the
  delete.
- **No secret is shown or logged.** The page shows non-secret facts and origin only; a
  merge copies a chosen sealed value without unsealing it; audit entries carry the record
  kind and ids only (`conflict_merge`, `conflict_keep_both`).
- **Deterministic and convergent.** Every decision is an ordinary replicated write (a merge
  is tombstones plus a survivor update; keep both is a `DistinctAck`), so all machines
  reach the same state. SopsHQ never resolves a real conflict on its own.

## Known limits

- A reference is re-pointed once the machine holding it has synced the merged-away
  record's tombstone (which carries the merge pointer) and run a reconcile pass.
- Until then the reference still names the record locally, which is correct, because the
  record is still live there. The re-point is repeatable and stable, so once the tombstone
  arrives the reference moves to the survivor and stays there.
