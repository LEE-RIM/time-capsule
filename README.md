# Dear Tomorrow — Time Capsule

A small interactive time capsule app. Write a note, choose a future date, seal it, and open it when that date arrives.

## Run locally

Open `index.html` in a modern browser. Capsules are stored in that browser's local storage.

## Publish with GitHub Pages

1. Put the contents of this folder at the root of a GitHub repository.
2. Push the files to the `main` branch.
3. In the repository, open **Settings → Pages** and set the build and deployment source to **GitHub Actions**.
4. The included workflow deploys the site on each push to `main`. You can also start it from the **Actions** tab with **Run workflow**.

The workflow publishes the repository root as a static site; no build step or packages are needed.

## Important

- Each capsule is encrypted in this browser with its own secret code. The code is required after the opening date to read the note.
- Add an optional private label and colour to recognize capsules in the list. The label is visible in this browser and is included inside encrypted backups, but it is not part of the encrypted note itself.
- Use **Edit label** on a saved capsule to rename its private label or change its card colour without decrypting or changing the note.
- Opening a capsule shows a short envelope-reveal animation after the correct code is entered. The animation is skipped for browsers set to reduce motion.
- Capsules saved with an older version are not encrypted yet; use **Set code & protect** on each older capsule to encrypt it.
- A one-time recovery key is shown when a capsule is sealed. Keep it somewhere safe: it is not stored by the app. If you forget the code, the key lets you choose a new one; if you lose both, the note cannot be recovered.
- Use **Download encrypted backup** to create a passphrase-protected file, and **Restore from backup** to merge it into the current browser. The backup passphrase is separate from capsule codes and is never stored. Each capsule still needs its own code after restore.
- Keep the backup file and its passphrase in separate safe places. Losing the passphrase means the backup cannot be restored. Restoring merges capsules and skips copies already present; it does not remove current capsules.
- Backups are limited to 10 MB. The browser downloads the encrypted file; this app does not upload it.
- Notes and encrypted data stay in this browser on this device. They do not sync, upload, or get sent to the recipient.
- A published site uses a different browser origin from the local preview, so capsules saved in the preview will not appear on the published site.
- Clearing browser storage or using a different browser/device can remove or hide saved notes. Save the recovery key separately; it cannot restore a capsule after its encrypted browser data is deleted.
- Opening dates use this device's local timezone. This static app cannot enforce dates against someone who controls the browser or device clock.
- Use a strong secret code of at least 8 characters. A weak code may be guessed by someone with a copy of the saved browser data.
- This app has no server, account, or email-based password reset. It is a personal keepsake, not a substitute for a professionally audited password manager.
