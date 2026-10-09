const storageKey = "dear-tomorrow-capsules-v1";
const capsuleForm = document.querySelector("#capsuleForm");
const titleInput = document.querySelector("#capsuleTitle");
const messageInput = document.querySelector("#capsuleMessage");
const recipientInput = document.querySelector("#capsuleRecipient");
const dateInput = document.querySelector("#capsuleDate");
const capsuleLabelInput = document.querySelector("#capsuleLabel");
const capsuleColorInput = document.querySelector("#capsuleColor");
const codeInput = document.querySelector("#capsuleCode");
const codeConfirmInput = document.querySelector("#capsuleCodeConfirm");
const messageCount = document.querySelector("#messageCount");
const formMessage = document.querySelector("#formMessage");
const capsulesList = document.querySelector("#capsulesList");
const emptyState = document.querySelector("#emptyState");
const capsuleCount = document.querySelector("#capsuleCount");
const toast = document.querySelector("#toast");
const exportBackupButton = document.querySelector("#exportBackup");
const importBackupButton = document.querySelector("#importBackup");
const backupFileInput = document.querySelector("#backupFile");
const backupMessage = document.querySelector("#backupMessage");

const encryptionIterations = 600000;
const backupFormat = "dear-tomorrow-encrypted-backup";
const maxBackupBytes = 10 * 1024 * 1024;
const encoder = new TextEncoder();
let capsules = loadCapsules();
let toastTimer;

function getLocalDateString(date) {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}

function parseLocalDate(dateString) {
  const [year, month, day] = dateString.split("-").map(Number);
  return new Date(year, month - 1, day, 0, 0, 0, 0);
}

const tomorrow = new Date();
tomorrow.setDate(tomorrow.getDate() + 1);
dateInput.min = getLocalDateString(tomorrow);

function showToast(message) {
  toast.textContent = message;
  toast.classList.add("visible");
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => toast.classList.remove("visible"), 3000);
}

function setPreviewDate(dateString) {
  if (!dateString) {
    document.querySelector("#previewDate").innerHTML = "A DAY<br>TO COME";
    return;
  }
  document.querySelector("#previewDate").textContent = new Intl.DateTimeFormat("en", {
    day: "numeric",
    month: "short",
    year: "numeric"
  }).format(parseLocalDate(dateString));
}

function updatePreview() {
  document.querySelector("#previewTitle").textContent = titleInput.value.trim() || "A little reminder for later";
  document.querySelector("#previewMessage").textContent = messageInput.value.trim() || "Your words will find their way here. Take your time; there's no rush.";
  document.querySelector("#previewRecipient").textContent = recipientInput.value.trim() || "future me";
  setPreviewDate(dateInput.value);
  messageCount.textContent = `${messageInput.value.length} / 1500`;
}

function encodeBase64Url(bytes) {
  let binary = "";
  bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function decodeBase64Url(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64 + "=".repeat((4 - base64.length % 4) % 4));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function deriveWrappingKey(secret, salt) {
  const material = await crypto.subtle.importKey("raw", encoder.encode(secret), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: encryptionIterations, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function wrapDataKey(dataKey, wrappingKey) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const rawDataKey = await crypto.subtle.exportKey("raw", dataKey);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, wrappingKey, rawDataKey);
  return { iv: encodeBase64Url(iv), wrappedKey: encodeBase64Url(new Uint8Array(ciphertext)) };
}

async function encryptCapsuleContent(content, secret) {
  const dataKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const contentIv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: contentIv },
    dataKey,
    encoder.encode(JSON.stringify(content))
  );

  const passwordSalt = crypto.getRandomValues(new Uint8Array(16));
  const passwordKey = await deriveWrappingKey(secret, passwordSalt);
  const passwordWrapper = await wrapDataKey(dataKey, passwordKey);
  const recoveryBytes = crypto.getRandomValues(new Uint8Array(32));
  const recoveryKey = await crypto.subtle.importKey("raw", recoveryBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  const recoveryWrapper = await wrapDataKey(dataKey, recoveryKey);

  return {
    recoveryCode: encodeBase64Url(recoveryBytes),
    encrypted: {
      version: 1,
      contentIv: encodeBase64Url(contentIv),
      ciphertext: encodeBase64Url(new Uint8Array(ciphertext)),
      passwordSalt: encodeBase64Url(passwordSalt),
      passwordIv: passwordWrapper.iv,
      passwordWrappedKey: passwordWrapper.wrappedKey,
      recoveryIv: recoveryWrapper.iv,
      recoveryWrappedKey: recoveryWrapper.wrappedKey
    }
  };
}

async function unwrapDataKey(encrypted, secret, useRecoveryCode) {
  const iv = decodeBase64Url(useRecoveryCode ? encrypted.recoveryIv : encrypted.passwordIv);
  const wrappedKey = decodeBase64Url(useRecoveryCode ? encrypted.recoveryWrappedKey : encrypted.passwordWrappedKey);
  let wrappingKey;
  if (useRecoveryCode) {
    wrappingKey = await crypto.subtle.importKey("raw", decodeBase64Url(secret), { name: "AES-GCM" }, false, ["decrypt"]);
  } else {
    wrappingKey = await deriveWrappingKey(secret, decodeBase64Url(encrypted.passwordSalt));
  }
  const rawDataKey = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, wrappingKey, wrappedKey);
  return crypto.subtle.importKey("raw", rawDataKey, { name: "AES-GCM" }, true, ["decrypt", "encrypt"]);
}

async function decryptCapsuleContent(capsule, secret, useRecoveryCode = false) {
  const encrypted = capsule.encrypted;
  const dataKey = await unwrapDataKey(encrypted, secret, useRecoveryCode);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: decodeBase64Url(encrypted.contentIv) },
    dataKey,
    decodeBase64Url(encrypted.ciphertext)
  );
  return { content: JSON.parse(new TextDecoder().decode(plaintext)), dataKey };
}

async function replacePasswordWrapper(capsule, dataKey, newSecret) {
  const passwordSalt = crypto.getRandomValues(new Uint8Array(16));
  const passwordKey = await deriveWrappingKey(newSecret, passwordSalt);
  const wrapper = await wrapDataKey(dataKey, passwordKey);
  return {
    ...capsule,
    encrypted: {
      ...capsule.encrypted,
      passwordSalt: encodeBase64Url(passwordSalt),
      passwordIv: wrapper.iv,
      passwordWrappedKey: wrapper.wrappedKey
    }
  };
}

function loadCapsules() {
  let saved;
  try {
    saved = window.localStorage.getItem(storageKey);
  } catch (error) {
    console.error("Could not read saved time capsules.", error);
    formMessage.textContent = "This browser blocked local storage. Allow site storage to save capsules.";
    return [];
  }
  if (!saved) return [];

  try {
    const parsed = JSON.parse(saved);
    if (!Array.isArray(parsed)) throw new Error("Saved capsule data is not a list.");
    return parsed.filter((capsule) =>
      capsule &&
      typeof capsule.id === "string" &&
      typeof capsule.openAt === "string" &&
      Number.isFinite(Date.parse(capsule.openAt)) &&
      typeof capsule.openDate === "string" &&
      (capsule.encrypted?.version === 1 ||
        (typeof capsule.title === "string" &&
          typeof capsule.message === "string" &&
          typeof capsule.recipient === "string"))
    );
  } catch (error) {
    console.error("Could not parse saved time capsules.", error);
    formMessage.textContent = "Saved capsule data could not be read. Your other browser data was left untouched.";
    return [];
  }
}

function persistCapsules(nextCapsules) {
  try {
    window.localStorage.setItem(storageKey, JSON.stringify(nextCapsules));
    capsules = nextCapsules;
    return true;
  } catch (error) {
    console.error("Could not save time capsules.", error);
    formMessage.textContent = "Capsule wasn't saved. Check that browser storage is enabled and has space.";
    return false;
  }
}

function validateCapsuleRecord(capsule) {
  if (!capsule || typeof capsule !== "object" || Array.isArray(capsule)) return false;
  if (typeof capsule.id !== "string" || !capsule.id || capsule.id.length > 200) return false;
  if (typeof capsule.openAt !== "string" || !Number.isFinite(Date.parse(capsule.openAt))) return false;
  if (typeof capsule.openDate !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(capsule.openDate)) return false;
  if (typeof capsule.createdAt !== "string" || !Number.isFinite(Date.parse(capsule.createdAt))) return false;
  if (capsule.label !== undefined && (typeof capsule.label !== "string" || capsule.label.length > 32)) return false;
  if (capsule.labelColor !== undefined && !["rose", "sage", "blue", "gold", "lavender"].includes(capsule.labelColor)) return false;
  const parsedDate = parseLocalDate(capsule.openDate);
  if (!Number.isFinite(parsedDate.getTime()) || getLocalDateString(parsedDate) !== capsule.openDate) return false;

  if (capsule.encrypted?.version === 1) {
    const encrypted = capsule.encrypted;
    try {
      return [
        [encrypted.contentIv, 12],
        [encrypted.passwordSalt, 16],
        [encrypted.passwordIv, 12],
        [encrypted.recoveryIv, 12]
      ].every(([value, length]) => typeof value === "string" && decodeBase64Url(value).length === length) &&
        ["ciphertext", "passwordWrappedKey", "recoveryWrappedKey"].every((key) =>
          typeof encrypted[key] === "string" && decodeBase64Url(encrypted[key]).length > 0
        );
    } catch {
      return false;
    }
  }

  return typeof capsule.title === "string" &&
    capsule.title.length <= 60 &&
    typeof capsule.message === "string" &&
    capsule.message.length <= 1500 &&
    typeof capsule.recipient === "string" &&
    capsule.recipient.length <= 50;
}

function createBackupDialog(title, description) {
  const { dialog, paper } = makeDialog(title, "ENCRYPTED BACKUP");
  const explanation = document.createElement("p");
  explanation.className = "opened-message";
  explanation.textContent = description;
  const form = document.createElement("form");
  form.className = "credential-form";
  const passphraseLabel = document.createElement("label");
  passphraseLabel.className = "field-label";
  passphraseLabel.htmlFor = "backupPassphrase";
  passphraseLabel.textContent = "BACKUP PASSPHRASE (12+ CHARACTERS)";
  const passphraseInput = document.createElement("input");
  passphraseInput.className = "text-input";
  passphraseInput.id = "backupPassphrase";
  passphraseInput.type = "password";
  passphraseInput.minLength = 12;
  passphraseInput.maxLength = 128;
  passphraseInput.autocomplete = "new-password";
  passphraseInput.required = true;
  const confirmLabel = document.createElement("label");
  confirmLabel.className = "field-label";
  confirmLabel.htmlFor = "backupPassphraseConfirm";
  confirmLabel.textContent = "CONFIRM PASSPHRASE";
  const confirmInput = document.createElement("input");
  confirmInput.className = "text-input";
  confirmInput.id = "backupPassphraseConfirm";
  confirmInput.type = "password";
  confirmInput.minLength = 12;
  confirmInput.maxLength = 128;
  confirmInput.autocomplete = "new-password";
  confirmInput.required = true;
  const status = document.createElement("p");
  status.className = "form-message";
  status.setAttribute("role", "status");
  const submit = document.createElement("button");
  submit.className = "seal-button";
  submit.type = "submit";
  form.append(passphraseLabel, passphraseInput, confirmLabel, confirmInput, submit, status);
  paper.append(explanation, form);
  dialog.addEventListener("close", () => {
    passphraseInput.value = "";
    confirmInput.value = "";
  }, { once: true });
  dialog.showModal();
  passphraseInput.focus();
  return { dialog, form, passphraseInput, confirmInput, status, submit };
}

async function createEncryptedBackup(passphrase) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveWrappingKey(passphrase, salt);
  const archive = {
    format: "dear-tomorrow-capsules",
    version: 1,
    capsules
  };
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoder.encode(JSON.stringify(archive))
  );
  return {
    format: backupFormat,
    version: 1,
    kdf: "PBKDF2-SHA-256",
    iterations: encryptionIterations,
    salt: encodeBase64Url(salt),
    iv: encodeBase64Url(iv),
    ciphertext: encodeBase64Url(new Uint8Array(ciphertext))
  };
}

function downloadBackup(backup) {
  const blob = new Blob([JSON.stringify(backup, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `dear-tomorrow-backup-${getLocalDateString(new Date())}.json`;
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function openExportDialog() {
  backupMessage.textContent = "";
  if (capsules.length === 0) {
    backupMessage.textContent = "Create a capsule before downloading a backup.";
    return;
  }
  const { dialog, form, passphraseInput, confirmInput, status, submit } = createBackupDialog(
    "Protect your backup.",
    "Choose a separate passphrase of at least 12 characters. You will need it to restore this file. The passphrase is never saved."
  );
  submit.textContent = "Download encrypted backup";
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (passphraseInput.value.length < 12 || passphraseInput.value !== confirmInput.value) {
      status.textContent = passphraseInput.value.length < 12 ? "Use at least 12 characters for the backup passphrase." : "The passphrases don't match.";
      return;
    }
    submit.disabled = true;
    status.textContent = "Encrypting backup on this device…";
    try {
      const backup = await createEncryptedBackup(passphraseInput.value);
      downloadBackup(backup);
      dialog.close();
      backupMessage.textContent = "Encrypted backup downloaded. Keep both the file and its passphrase safe.";
    } catch (error) {
      console.error("Could not create encrypted backup.", error);
      status.textContent = "The backup couldn't be encrypted or downloaded. Your saved capsules were not changed.";
    } finally {
      submit.disabled = false;
    }
  });
}

async function decryptBackup(file, passphrase) {
  if (file.size > maxBackupBytes) throw new Error("The backup file is larger than 10 MB.");
  const parsed = JSON.parse(await file.text());
  if (!parsed || parsed.format !== backupFormat || parsed.version !== 1 || parsed.kdf !== "PBKDF2-SHA-256" || parsed.iterations !== encryptionIterations) {
    throw new Error("This file is not a supported Dear Tomorrow backup.");
  }
  const salt = decodeBase64Url(parsed.salt);
  const iv = decodeBase64Url(parsed.iv);
  const ciphertext = decodeBase64Url(parsed.ciphertext);
  if (salt.length !== 16 || iv.length !== 12 || ciphertext.length < 17) {
    throw new Error("The backup file is incomplete or damaged.");
  }
  const key = await deriveWrappingKey(passphrase, salt);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  const archive = JSON.parse(new TextDecoder().decode(plaintext));
  if (!archive || archive.format !== "dear-tomorrow-capsules" || archive.version !== 1 || !Array.isArray(archive.capsules) || archive.capsules.some((capsule) => !validateCapsuleRecord(capsule))) {
    throw new Error("The decrypted backup has an invalid capsule list.");
  }
  return archive.capsules;
}

function mergeCapsules(importedCapsules) {
  const merged = [...capsules];
  let added = 0;
  let alreadyPresent = 0;
  for (const imported of importedCapsules) {
    const existing = merged.find((capsule) => capsule.id === imported.id);
    if (existing && JSON.stringify(existing) === JSON.stringify(imported)) {
      alreadyPresent += 1;
      continue;
    }
    const candidate = existing
      ? { ...imported, id: crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random()}` }
      : imported;
    merged.push(candidate);
    added += 1;
  }
  return { merged, added, alreadyPresent };
}

function openImportDialog(file) {
  backupMessage.textContent = "";
  const { dialog, form, passphraseInput, status, submit } = createBackupDialog(
    "Restore your capsules.",
    "Enter the backup passphrase you chose when downloading this file. Restored capsules will be added; existing capsules will not be removed."
  );
  const confirmLabel = dialog.querySelector('label[for="backupPassphraseConfirm"]');
  const confirmInput = dialog.querySelector("#backupPassphraseConfirm");
  confirmLabel.remove();
  confirmInput.remove();
  passphraseInput.minLength = 1;
  passphraseInput.autocomplete = "current-password";
  passphraseInput.labels[0].textContent = "BACKUP PASSPHRASE";
  submit.textContent = "Decrypt & restore";
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    submit.disabled = true;
    status.textContent = "Decrypting backup on this device…";
    try {
      const imported = await decryptBackup(file, passphraseInput.value);
      const { merged, added, alreadyPresent } = mergeCapsules(imported);
      if (!persistCapsules(merged)) {
        status.textContent = "Restored capsules could not be saved. Your current capsules were left unchanged.";
        return;
      }
      renderCapsules();
      dialog.close();
      backupMessage.textContent = `Restored ${added} capsule${added === 1 ? "" : "s"}${alreadyPresent ? `; skipped ${alreadyPresent} already present` : ""}.`;
    } catch (error) {
      if (error.name === "OperationError") {
        status.textContent = "The passphrase is incorrect or the backup file was damaged.";
      } else {
        console.error("Could not restore encrypted backup.", error);
        status.textContent = error.message || "The backup could not be restored. Your current capsules were left unchanged.";
      }
    } finally {
      submit.disabled = false;
    }
  });
}

function getCapsuleStatus(capsule) {
  return Date.now() >= Date.parse(capsule.openAt) ? "open" : "sealed";
}

function getDaysRemaining(capsule) {
  const difference = Date.parse(capsule.openAt) - Date.now();
  return Math.max(0, Math.ceil(difference / 86400000));
}

function formatDate(dateString) {
  return new Intl.DateTimeFormat("en", {
    weekday: "short",
    day: "numeric",
    month: "long",
    year: "numeric"
  }).format(parseLocalDate(dateString));
}

function renderCapsules() {
  capsules.sort((a, b) => Date.parse(a.openAt) - Date.parse(b.openAt));
  const sealedCount = capsules.filter((capsule) => getCapsuleStatus(capsule) === "sealed").length;
  capsuleCount.textContent = `${sealedCount} SEALED`;
  emptyState.hidden = capsules.length > 0;
  capsulesList.replaceChildren(...capsules.map((capsule) => {
    const isEncrypted = Boolean(capsule.encrypted);
    const item = document.createElement("article");
    item.className = "capsule-item";
    const icon = document.createElement("span");
    icon.className = "capsule-icon";
    icon.dataset.color = ["rose", "sage", "blue", "gold", "lavender"].includes(capsule.labelColor) ? capsule.labelColor : "rose";
    icon.setAttribute("aria-hidden", "true");
    icon.textContent = getCapsuleStatus(capsule) === "open" ? "✉" : "✳";

    const copy = document.createElement("span");
    copy.className = "capsule-copy";
    const title = document.createElement("strong");
    title.textContent = capsule.label || (isEncrypted ? "Locked time capsule" : "Unprotected capsule");
    const recipient = document.createElement("span");
    recipient.textContent = isEncrypted ? (capsule.label ? "Private label · note encrypted" : "Encrypted on this device") : "Set a code to encrypt this note";
    copy.append(title, recipient);

    const time = document.createElement("span");
    time.className = "capsule-time";
    if (!isEncrypted) {
      const protectButton = document.createElement("button");
      protectButton.className = "open-capsule";
      protectButton.type = "button";
      protectButton.textContent = "Set code & protect";
      protectButton.addEventListener("click", () => protectLegacyCapsule(capsule));
      time.append(protectButton);
    } else if (getCapsuleStatus(capsule) === "open") {
      const openButton = document.createElement("button");
      openButton.className = "open-capsule";
      openButton.type = "button";
      openButton.textContent = "Enter code to open";
      openButton.addEventListener("click", () => openCapsule(capsule));
      time.append(openButton);
    } else {
      const countdown = document.createElement("span");
      countdown.className = "countdown";
      countdown.textContent = `${getDaysRemaining(capsule)} days to go`;
      time.append(countdown);
    }
    const openDate = document.createElement("span");
    openDate.className = "open-date";
    openDate.textContent = formatDate(capsule.openDate);
    time.append(openDate);

    const actions = document.createElement("span");
    actions.className = "capsule-actions";
    const edit = document.createElement("button");
    edit.className = "edit-capsule";
    edit.type = "button";
    edit.textContent = "Edit label";
    edit.setAttribute("aria-label", `Edit label for ${capsule.label || "time capsule"}`);
    edit.addEventListener("click", () => editCapsuleLabel(capsule));
    const remove = document.createElement("button");
    remove.className = "delete-capsule";
    remove.type = "button";
    remove.textContent = "×";
    remove.setAttribute("aria-label", "Delete this time capsule");
    remove.addEventListener("click", () => deleteCapsule(capsule));
    actions.append(edit, remove);
    item.append(icon, copy, time, actions);
    return item;
  }));
}

function makeDialog(titleText, eyebrowText) {
  const dialog = document.createElement("dialog");
  dialog.className = "capsule-dialog";
  const paper = document.createElement("article");
  paper.className = "opened-letter";
  const close = document.createElement("button");
  close.className = "dialog-close";
  close.type = "button";
  close.setAttribute("aria-label", "Close note");
  close.textContent = "×";
  close.addEventListener("click", () => dialog.close());
  const eyebrow = document.createElement("p");
  eyebrow.className = "eyebrow";
  eyebrow.textContent = eyebrowText;
  const heading = document.createElement("h2");
  heading.textContent = titleText;
  paper.append(close, eyebrow, heading);
  dialog.append(paper);
  document.body.append(dialog);
  dialog.addEventListener("close", () => dialog.remove(), { once: true });
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog) dialog.close();
  });
  return { dialog, paper, heading };
}

function editCapsuleLabel(capsule) {
  const { dialog, paper } = makeDialog("Make it easy to find.", "EDIT PRIVATE LABEL");
  const explanation = document.createElement("p");
  explanation.className = "opened-message";
  explanation.textContent = "Change only the label and card colour. Your encrypted note and secret code stay untouched.";
  const form = document.createElement("form");
  form.className = "credential-form";
  const label = document.createElement("label");
  label.className = "field-label";
  label.htmlFor = "editCapsuleLabel";
  label.textContent = "PRIVATE LABEL (OPTIONAL)";
  const input = document.createElement("input");
  input.className = "text-input";
  input.id = "editCapsuleLabel";
  input.maxLength = 32;
  input.value = capsule.label || "";
  const colorLabel = document.createElement("label");
  colorLabel.className = "field-label";
  colorLabel.htmlFor = "editCapsuleColor";
  colorLabel.textContent = "CARD COLOUR";
  const color = document.createElement("select");
  color.className = "text-input color-select";
  color.id = "editCapsuleColor";
  for (const option of [
    ["rose", "Rose"],
    ["sage", "Sage"],
    ["blue", "Blue"],
    ["gold", "Gold"],
    ["lavender", "Lavender"]
  ]) {
    const choice = document.createElement("option");
    choice.value = option[0];
    choice.textContent = option[1];
    color.append(choice);
  }
  color.value = capsule.labelColor || "rose";
  const status = document.createElement("p");
  status.className = "form-message";
  status.setAttribute("role", "status");
  const save = document.createElement("button");
  save.className = "seal-button";
  save.type = "submit";
  save.textContent = "Save label";
  form.append(label, input, colorLabel, color, save, status);
  paper.append(explanation, form);
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const nextCapsules = capsules.map((item) => item.id === capsule.id
      ? { ...item, label: input.value.trim(), labelColor: color.value }
      : item);
    if (persistCapsules(nextCapsules)) {
      renderCapsules();
      dialog.close();
      showToast("Capsule label updated.");
    } else {
      status.textContent = "The label couldn't be saved. Your capsule was left unchanged.";
    }
  });
  dialog.showModal();
  input.focus();
}

function showRecoveryCode(recoveryCode) {
  const { dialog, paper } = makeDialog("Keep this recovery key safe.", "ONE-TIME RECOVERY KEY");
  const explanation = document.createElement("p");
  explanation.className = "opened-message";
  explanation.textContent = "Write it down or save it somewhere private. This key is shown only once and cannot be retrieved later.";
  const key = document.createElement("code");
  key.className = "recovery-code";
  key.textContent = recoveryCode;
  const confirm = document.createElement("button");
  confirm.className = "seal-button recovery-confirm";
  confirm.type = "button";
  confirm.textContent = "I've saved my recovery key";
  confirm.addEventListener("click", () => dialog.close());
  dialog.addEventListener("cancel", (event) => event.preventDefault());
  paper.append(explanation, key, confirm);
  dialog.showModal();
}

function showOpenedCapsule(capsule, content) {
  const { dialog, paper, heading } = makeDialog("A note from your past.", "A NOTE THAT MADE IT THROUGH TIME");
  const reveal = document.createElement("div");
  reveal.className = "envelope-reveal";
  reveal.setAttribute("aria-hidden", "true");
  const envelopeLetter = document.createElement("span");
  envelopeLetter.className = "envelope-letter";
  const envelope = document.createElement("span");
  envelope.className = "envelope-shape";
  const flap = document.createElement("span");
  flap.className = "envelope-flap";
  envelope.append(flap);
  reveal.append(envelopeLetter, envelope);
  const announcement = document.createElement("p");
  announcement.className = "reveal-announcement";
  announcement.setAttribute("role", "status");
  announcement.textContent = "Opening your time capsule…";
  const letter = document.createElement("div");
  letter.className = "revealed-letter";
  letter.hidden = true;
  const recipient = document.createElement("p");
  recipient.className = "opened-recipient";
  recipient.textContent = `Dear ${content.recipient},`;
  const message = document.createElement("p");
  message.className = "opened-message";
  message.textContent = content.message;
  const date = document.createElement("span");
  date.className = "opened-date";
  date.textContent = `Written for ${formatDate(capsule.openDate)}`;
  letter.append(recipient, message, date);
  paper.append(reveal, announcement, letter);
  dialog.showModal();

  const revealLetter = () => {
    if (!dialog.open) return;
    reveal.remove();
    announcement.remove();
    heading.textContent = content.title;
    letter.hidden = false;
    letter.classList.add("letter-arrived");
  };
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    revealLetter();
  } else {
    window.setTimeout(revealLetter, 1400);
  }
}

function showCredentials(capsule, onSubmit) {
  const { dialog, paper } = makeDialog("Unlock your capsule.", "PRIVATE TO THIS BROWSER");
  const explanation = document.createElement("p");
  explanation.className = "opened-message";
  explanation.textContent = "Enter this capsule's secret code. If you forgot it, use its one-time recovery key to set a new code.";
  const form = document.createElement("form");
  form.className = "credential-form";
  const label = document.createElement("label");
  label.className = "field-label";
  label.htmlFor = "unlockCode";
  label.textContent = "SECRET CODE";
  const input = document.createElement("input");
  input.className = "text-input";
  input.id = "unlockCode";
  input.type = "password";
  input.autocomplete = "current-password";
  input.required = true;
  const status = document.createElement("p");
  status.className = "form-message";
  status.setAttribute("role", "status");
  const unlock = document.createElement("button");
  unlock.className = "seal-button";
  unlock.type = "submit";
  unlock.textContent = "Unlock capsule";
  const recover = document.createElement("button");
  recover.className = "recovery-link";
  recover.type = "button";
  recover.textContent = "Forgot password? Use recovery key";
  form.append(label, input, unlock, recover, status);
  paper.append(explanation, form);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    unlock.disabled = true;
    status.textContent = "Checking code…";
    try {
      await onSubmit(input.value, false, status);
    } finally {
      unlock.disabled = false;
      if (dialog.open) input.focus();
    }
  });
  recover.addEventListener("click", () => {
    dialog.close();
    showRecoveryPrompt(capsule, onSubmit);
  });
  dialog.showModal();
  input.focus();
}

function showRecoveryPrompt(capsule, onSubmit) {
  const { dialog, paper } = makeDialog("Recover your capsule.", "FORGOT YOUR SECRET CODE?");
  const explanation = document.createElement("p");
  explanation.className = "opened-message";
  explanation.textContent = "Enter the recovery key you saved when sealing this capsule, then choose a new secret code.";
  const form = document.createElement("form");
  form.className = "credential-form";
  const recoveryLabel = document.createElement("label");
  recoveryLabel.className = "field-label";
  recoveryLabel.htmlFor = "recoveryCode";
  recoveryLabel.textContent = "RECOVERY KEY";
  const recoveryInput = document.createElement("input");
  recoveryInput.className = "text-input";
  recoveryInput.id = "recoveryCode";
  recoveryInput.autocomplete = "off";
  recoveryInput.required = true;
  const newCodeLabel = document.createElement("label");
  newCodeLabel.className = "field-label";
  newCodeLabel.htmlFor = "recoveryNewCode";
  newCodeLabel.textContent = "NEW SECRET CODE (8+ CHARACTERS)";
  const newCodeInput = document.createElement("input");
  newCodeInput.className = "text-input";
  newCodeInput.id = "recoveryNewCode";
  newCodeInput.type = "password";
  newCodeInput.minLength = 8;
  newCodeInput.maxLength = 128;
  newCodeInput.autocomplete = "new-password";
  newCodeInput.required = true;
  const confirmLabel = document.createElement("label");
  confirmLabel.className = "field-label";
  confirmLabel.htmlFor = "recoveryConfirmCode";
  confirmLabel.textContent = "CONFIRM NEW CODE";
  const confirmInput = document.createElement("input");
  confirmInput.className = "text-input";
  confirmInput.id = "recoveryConfirmCode";
  confirmInput.type = "password";
  confirmInput.minLength = 8;
  confirmInput.maxLength = 128;
  confirmInput.autocomplete = "new-password";
  confirmInput.required = true;
  const status = document.createElement("p");
  status.className = "form-message";
  status.setAttribute("role", "status");
  const submit = document.createElement("button");
  submit.className = "seal-button";
  submit.type = "submit";
  submit.textContent = "Recover & set new code";
  form.append(recoveryLabel, recoveryInput, newCodeLabel, newCodeInput, confirmLabel, confirmInput, submit, status);
  paper.append(explanation, form);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (newCodeInput.value.length < 8 || newCodeInput.value !== confirmInput.value) {
      status.textContent = newCodeInput.value.length < 8 ? "Use at least 8 characters for your new code." : "The new codes don't match.";
      return;
    }
    submit.disabled = true;
    status.textContent = "Recovering capsule…";
    try {
      await onSubmit(recoveryInput.value, true, status, newCodeInput.value);
    } finally {
      submit.disabled = false;
      if (dialog.open) recoveryInput.focus();
    }
  });
  dialog.showModal();
  recoveryInput.focus();
}

function protectLegacyCapsule(capsule) {
  const { dialog, paper } = makeDialog("Add a secret code.", "PROTECT AN OLDER CAPSULE");
  const explanation = document.createElement("p");
  explanation.className = "opened-message";
  explanation.textContent = "This older capsule is not encrypted yet. Set a code now; its title and note will then be encrypted on this device.";
  const form = document.createElement("form");
  form.className = "credential-form";
  const codeLabel = document.createElement("label");
  codeLabel.className = "field-label";
  codeLabel.htmlFor = "legacyCode";
  codeLabel.textContent = "SECRET CODE (8+ CHARACTERS)";
  const code = document.createElement("input");
  code.className = "text-input";
  code.id = "legacyCode";
  code.type = "password";
  code.minLength = 8;
  code.maxLength = 128;
  code.autocomplete = "new-password";
  code.required = true;
  const confirmLabel = document.createElement("label");
  confirmLabel.className = "field-label";
  confirmLabel.htmlFor = "legacyCodeConfirm";
  confirmLabel.textContent = "CONFIRM CODE";
  const confirmation = document.createElement("input");
  confirmation.className = "text-input";
  confirmation.id = "legacyCodeConfirm";
  confirmation.type = "password";
  confirmation.minLength = 8;
  confirmation.maxLength = 128;
  confirmation.autocomplete = "new-password";
  confirmation.required = true;
  const status = document.createElement("p");
  status.className = "form-message";
  status.setAttribute("role", "status");
  const submit = document.createElement("button");
  submit.className = "seal-button";
  submit.type = "submit";
  submit.textContent = "Encrypt this capsule";
  form.append(codeLabel, code, confirmLabel, confirmation, submit, status);
  paper.append(explanation, form);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (code.value.length < 8 || code.value !== confirmation.value) {
      status.textContent = code.value.length < 8 ? "Use at least 8 characters for the secret code." : "The secret codes don't match.";
      return;
    }
    submit.disabled = true;
    status.textContent = "Encrypting this capsule…";
    try {
      const { recoveryCode, encrypted } = await encryptCapsuleContent({
        title: capsule.title,
        message: capsule.message,
        recipient: capsule.recipient
      }, code.value);
      const protectedCapsule = {
        id: capsule.id,
        label: capsule.label || "",
        labelColor: capsule.labelColor || "rose",
        openDate: capsule.openDate,
        openAt: capsule.openAt,
        createdAt: capsule.createdAt,
        encrypted
      };
      const nextCapsules = capsules.map((item) => item.id === capsule.id ? protectedCapsule : item);
      if (persistCapsules(nextCapsules)) {
        renderCapsules();
        dialog.close();
        showRecoveryCode(recoveryCode);
      } else {
        status.textContent = "The protected capsule couldn't be saved. Your older note was left unchanged.";
      }
    } catch (error) {
      console.error("Could not encrypt the existing time capsule.", error);
      status.textContent = "This capsule couldn't be encrypted. Your saved note was left unchanged.";
    } finally {
      submit.disabled = false;
    }
  });
  dialog.showModal();
  code.focus();
}

async function openCapsule(capsule) {
  if (getCapsuleStatus(capsule) !== "open") {
    showToast("This capsule is still sealed until its opening date.");
    return;
  }
  showCredentials(capsule, async (secret, useRecoveryCode, status, newSecret) => {
    try {
      const { content, dataKey } = await decryptCapsuleContent(capsule, secret, useRecoveryCode);
      if (useRecoveryCode) {
        const updatedCapsule = await replacePasswordWrapper(capsule, dataKey, newSecret);
        const nextCapsules = capsules.map((item) => item.id === capsule.id ? updatedCapsule : item);
        if (!persistCapsules(nextCapsules)) {
          status.textContent = "The new code couldn't be saved. Your capsule is unchanged; check browser storage and retry.";
          return;
        }
        capsule = updatedCapsule;
      }
      document.querySelector(".capsule-dialog")?.close();
      showOpenedCapsule(capsule, content);
    } catch (error) {
      if (error.name === "OperationError" || error.name === "DataError" || error.name === "InvalidCharacterError") {
        status.textContent = useRecoveryCode ? "That recovery key didn't match this capsule." : "That secret code didn't match.";
      } else {
        console.error("Could not unlock the time capsule.", error);
        status.textContent = "The capsule couldn't be unlocked due to a browser encryption error. Your saved data was left unchanged.";
      }
    }
  });
}

function deleteCapsule(capsule) {
  const nextCapsules = capsules.filter((item) => item.id !== capsule.id);
  if (persistCapsules(nextCapsules)) {
    renderCapsules();
    showToast("Time capsule removed from this device.");
  }
}

[titleInput, messageInput, recipientInput, dateInput].forEach((input) => {
  input.addEventListener("input", updatePreview);
  input.addEventListener("change", updatePreview);
});

exportBackupButton.addEventListener("click", openExportDialog);
importBackupButton.addEventListener("click", () => {
  backupFileInput.value = "";
  backupFileInput.click();
});
backupFileInput.addEventListener("change", () => {
  const [file] = backupFileInput.files || [];
  if (file) openImportDialog(file);
});

capsuleForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  formMessage.textContent = "";
  const title = titleInput.value.trim();
  const message = messageInput.value.trim();
  const recipient = recipientInput.value.trim();
  const openDate = dateInput.value;
  const label = capsuleLabelInput.value.trim();
  const labelColor = capsuleColorInput.value;
  const secret = codeInput.value;
  if (!title || !message || !recipient || !openDate) {
    formMessage.textContent = "Fill in the note, recipient, and opening date first.";
    return;
  }
  if (secret.length < 8) {
    formMessage.textContent = "Choose a secret code with at least 8 characters.";
    return;
  }
  if (secret !== codeConfirmInput.value) {
    formMessage.textContent = "The secret codes don't match.";
    return;
  }
  if (label.length > 32 || !["rose", "sage", "blue", "gold", "lavender"].includes(labelColor)) {
    formMessage.textContent = "Choose a valid capsule label and colour.";
    return;
  }
  const opensAt = parseLocalDate(openDate);
  if (Number.isNaN(opensAt.getTime()) || opensAt <= new Date()) {
    formMessage.textContent = "Choose a day in the future. Today’s note can wait until tomorrow.";
    return;
  }

  const submitButton = document.querySelector("#sealButton");
  submitButton.disabled = true;
  submitButton.querySelector("span:nth-child(2)").textContent = "Encrypting your note…";
  formMessage.textContent = "Encrypting privately on this device…";
  try {
    const { recoveryCode, encrypted } = await encryptCapsuleContent({ title, message, recipient }, secret);
    const capsule = {
      id: crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random()}`,
      label,
      labelColor,
      openDate,
      openAt: opensAt.toISOString(),
      createdAt: new Date().toISOString(),
      encrypted
    };
    if (persistCapsules([...capsules, capsule])) {
      renderCapsules();
      capsuleForm.reset();
      updatePreview();
      formMessage.textContent = "";
      showRecoveryCode(recoveryCode);
      showToast("Sealed and encrypted on this device.");
      document.querySelector("#capsulesTitle").scrollIntoView({ behavior: "smooth", block: "start" });
    }
  } catch (error) {
    console.error("Could not encrypt the time capsule.", error);
    formMessage.textContent = "The capsule couldn't be encrypted. Your note was not saved; please try again.";
  } finally {
    submitButton.disabled = false;
    submitButton.querySelector("span:nth-child(2)").textContent = "Seal this time capsule";
  }
});

updatePreview();
renderCapsules();
