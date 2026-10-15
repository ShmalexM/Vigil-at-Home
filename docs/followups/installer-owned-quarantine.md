# Follow-up: quarantining items an installer owns

## Today

The helper moves files only as the user who controls the path
(`packages/helper/src/commands/transfer.ts`). Root acts directly only when every
folder on the path is root's alone. An item that root owns, in a folder others can
write to, is refused with the code `installer-owned`. The usual case is an app that a
package installed in `/Applications`, which is `root:admin 0775`. A root-owned file in
`/tmp` is another.

No user can move such an item, and root won't act through a path someone else can
change. The app shows one line where the user asked. It says the app is blocked only
when the same alert holds a Santa block that is still in force.

## A safe version

Moving such an item needs two things: the bytes, and the right to remove the entry
from its folder. They can be split so that root never follows a path a user can
change.

1. **Read as a user.** A user's child process packs the item, as `fsChild pack`
   already does. The user must be able to read every file. A package-installed app is
   usually world-readable; a file mode that isn't should be refused, not read as root.
2. **Write only into root's own store.** Root, or a root child, places the archive
   into `Quarantine/<id>/`, as today. Nothing is staged in a user-owned folder.
   Nothing root reads goes through a folder a user owns.
3. **Remove the entry.** This is the open part (see below). The entry lives in a
   folder that others can write to, and is owned by root. A user who can write to the
   folder can unlink the top entry, but cannot remove a root-owned folder tree: that
   needs write permission on each folder inside it.

## Open questions

- **Folder permissions.** Renaming a folder to another parent needs write permission
  on the folder itself, so its `..` entry can be updated. Removing a folder's contents
  needs write permission on each folder in the tree. A user child has neither for a
  root-owned bundle. Could root remove the tree inside the bundle? Only if every
  folder in the bundle is root-owned and not writable by others, checked on each
  component without following links. The top entry would still be removed by the
  user, by name, in the shared folder.
- **Matching the removal to the copy.** Between the user's copy and root's removal,
  the user could swap the bundle for a link or another tree. Removal must check each
  entry's device and inode against what was packed, and stop at the first mismatch.
  It must never follow a link.
- **Which user.** For `/Applications`, any admin can write the folder. Should the
  console user act, or the group that makes the folder writable? What about the case
  where no one logged in is an admin?
- **macOS protections.** Signed-system and App Management privacy rules may stop even
  root from changing some app bundles. A refusal there should read the same as today.
- **Restore.** Putting a root-owned tree back would need root to create it, in a
  folder others can write to. Creating it exclusively (`O_EXCL|O_NOFOLLOW`, `mkdir`)
  avoids replacing anything. The folders inside are new and root's. But the top entry
  can be renamed by others as soon as it exists. Is a restore that leaves it
  user-owned acceptable instead?
