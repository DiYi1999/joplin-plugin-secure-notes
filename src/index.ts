/*****************************************************************************
 * @file        : src/index.ts
 * @description : Secure Notes — a Joplin plugin that encrypts notes with a
 *                password using AES encryption.
 * @author      : Aravind Potluri <aravindswami135@gmail.com>
 *****************************************************************************/

/** Imports */
import joplin from "api";
import {
  ToastType,
  SettingItemType,
  ToolbarButtonLocation,
  MenuItemLocation,
  ContentScriptType,
  ModelType,
} from "api/types";
import {
  showToast,
  validateFormat,
  renderMarkdown,
  isNoteLocked,
  generateEncryptedNote,
  showLegacyDialog,
  validateOldFormat,
  removeTag,
  getTagID,
  hasTag,
  showEncryptionDialog,
  showDecryptionDialog,
  refreshNoteView,
  isFolderOrParentEncrypted,
} from "./utils";
import {
  AesOptions,
  WrongPasswordError,
  encryptData,
  decryptData,
} from "./encryption";
import {
  encryptFolder as encryptFolderOp,
  decryptFolder as decryptFolderOp,
  isFolderEncrypted,
  reEncryptFolder,
} from "./folderManager";
import {
  isPlatformMobile,
  authenticateWithBiometrics,
  getPasswordForFolder,
  storePasswordForFolder,
  removePasswordForFolder,
  FOLDER_PASSWORDS_KEY,
} from "./biometrics";
import { createLogger } from "./pluginLogger";

/** Global constants */
export const PLUGIN_ID = "SecureNotes";
export const LOG_LEVEL = "DEBUG";

export const SETTINGS_SECTION = {
  MAIN: `${PLUGIN_ID}.settings`,
};

export const SETTINGS_MAIN = {
  KEY_SIZE: `${SETTINGS_SECTION.MAIN}.bitSize`,
  AES_MODE: `${SETTINGS_SECTION.MAIN}.cipherCategory`,
  BIOMETRIC_ENABLED: `${SETTINGS_SECTION.MAIN}.biometricEnabled`,
};

export const INTERACTIONS = {
  TOOLBAR: `${PLUGIN_ID}.toolbar`,
  MENU: `${PLUGIN_ID}.menu`,
  FOLDER_MENU: `${PLUGIN_ID}.folderMenu`,
};

export const COMMANDS = {
  ENCRYPT: `${PLUGIN_ID}.encrypt`,
  DECRYPT: `${PLUGIN_ID}.decrypt`,
  TOGGLELOCK: `${PLUGIN_ID}.toggleLock`,
  ENCRYPT_FOLDER: `${PLUGIN_ID}.encryptFolder`,
  DECRYPT_FOLDER: `${PLUGIN_ID}.decryptFolder`,
};

export const CONTENT_SCRIPT = {
  MARKDOWNIT_ID: "SecureView",
};

/** Global state */
let encryptionDialogId: string | null = null;
let decryptionDialogId: string | null = null;
let LegacyNoteDialogId: string | null = null;
let lockedTagId: string | null = null;
let aesOptions: AesOptions = {
  KeySize: 256,
  AesMode: "AES-GCM",
};

/** Tracks notes that have been unlocked for editing (noteId -> folderId) */
const unlockedNotes = new Map<string, string>();
/** Guard: skip re-encrypt for notes that are currently being refreshed */
const skipReEncryptForRefresh = new Set<string>();

/** Logger instance */
const logger = createLogger(`[${PLUGIN_ID}]`, LOG_LEVEL);

/**
 * Plugin registerations - commands, UI, and settings, etc.
 */
joplin.plugins.register({
  onStart: async () => {
    // Register settings section
    await joplin.settings.registerSection(SETTINGS_SECTION.MAIN, {
      label: "Secure Notes",
      iconName: "fas fa-user-shield",
    });

    // Register plugin settings
    await joplin.settings.registerSettings({
      [SETTINGS_MAIN.KEY_SIZE]: {
        value: 256,
        type: SettingItemType.Int,
        section: SETTINGS_SECTION.MAIN,
        public: true,
        label: "AES Key Size",
        isEnum: true,
        options: {
          128: "128-bit",
          256: "256-bit (Recommended)",
        },
      },
      [SETTINGS_MAIN.AES_MODE]: {
        value: "AES-GCM",
        type: SettingItemType.String,
        section: SETTINGS_SECTION.MAIN,
        public: true,
        label: "AES Cipher Mode",
        isEnum: true,
        options: {
          "AES-CBC": "CBC",
          "AES-CTR": "CTR",
          "AES-GCM": "GCM (Recommended)",
        },
      },
      [SETTINGS_MAIN.BIOMETRIC_ENABLED]: {
        value: false,
        type: SettingItemType.Bool,
        section: SETTINGS_SECTION.MAIN,
        public: true,
        label: "Enable Biometric Unlock (Mobile)",
        description:
          "Store folder passwords securely and use device biometrics to unlock. Only available on mobile.",
      },
      [FOLDER_PASSWORDS_KEY]: {
        value: "{}",
        type: SettingItemType.String,
        section: SETTINGS_SECTION.MAIN,
        public: false,
        secure: true,
        label: "Encrypted Folder Passwords",
      },
    });

    // Register commands
    await joplin.commands.register({
      name: COMMANDS.ENCRYPT,
      label: "Encrypt Note",
      enabledCondition: "oneNoteSelected",
      execute: encryptNote,
      iconName: "fas fa-lock",
    });
    await joplin.commands.register({
      name: COMMANDS.DECRYPT,
      label: "Decrypt Note",
      enabledCondition: "oneNoteSelected",
      execute: decryptNote,
      iconName: "fas fa-unlock",
    });
    await joplin.commands.register({
      name: COMMANDS.TOGGLELOCK,
      enabledCondition: "oneNoteSelected",
      label: "Toggle Note Lock",
      execute: toggleLock,
      iconName: "fas fa-user-lock",
    });
    await joplin.commands.register({
      name: COMMANDS.ENCRYPT_FOLDER,
      label: "Encrypt Folder",
      execute: encryptFolderCmd,
      iconName: "fas fa-folder-lock",
    });
    await joplin.commands.register({
      name: COMMANDS.DECRYPT_FOLDER,
      label: "Decrypt Folder",
      execute: decryptFolderCmd,
      iconName: "fas fa-folder-unlock",
    });

    // Register toolbar and menu entries
    await joplin.views.toolbarButtons.create(
      INTERACTIONS.TOOLBAR,
      COMMANDS.TOGGLELOCK,
      ToolbarButtonLocation.NoteToolbar,
    );
    await joplin.views.menus.create(
      INTERACTIONS.MENU,
      "Secure Notes",
      [
        { commandName: COMMANDS.TOGGLELOCK },
        { commandName: COMMANDS.ENCRYPT_FOLDER },
        { commandName: COMMANDS.DECRYPT_FOLDER },
      ],
      MenuItemLocation.Tools,
    );

    // Register folder context menu
    await joplin.views.menus.create(
      INTERACTIONS.FOLDER_MENU,
      "Secure Notes",
      [
        { commandName: COMMANDS.ENCRYPT_FOLDER },
        { commandName: COMMANDS.DECRYPT_FOLDER },
      ],
      MenuItemLocation.FolderContextMenu,
    );

    // Register contentScripts
    await joplin.contentScripts.register(
      ContentScriptType.MarkdownItPlugin,
      CONTENT_SCRIPT.MARKDOWNIT_ID,
      "./contentScripts/secureView.js",
    );

    // Event listeners
    await joplin.settings.onChange(async () => {
      logger.debug("Settings change detected");
      await updateSettings();
    });

    await joplin.contentScripts.onMessage(
      CONTENT_SCRIPT.MARKDOWNIT_ID,
      async (message: any) => {
        // MarkdownIt Logger
        if (message.type === "log") {
          logger.debug(message.msg);
          return;
        }

        // Password handler (view-only — returns rendered HTML)
        if (message.type === "password") {
          const decryptStatus = await handlePasswdSubmit(message.msg);
          return decryptStatus;
        }

        // Unlock & Edit — decrypts note body on disk so user can edit
        if (message.type === "unlockAndEdit") {
          return await handleUnlockAndEdit(message.msg);
        }

        // Biometric unlock handler (called from content script runtime)
        if (message.type === "biometricUnlock") {
          return await handleBiometricUnlock();
        }

        // Get the editor mode
        if (message.type === "getEditorMode") {
          // NOTE: Not used anymore, just keeping this in case
          // necessary for future.
          const values = await joplin.settings.globalValues([
            "editor.codeView",
          ]);
          return { mode: values[0] ? "markdown" : "rte" };
        }
      },
    );

    await joplin.workspace.onNoteSelectionChange(async () => {
      // Re-encrypt previously unlocked notes
      await reEncryptUnlockedNotes();
      await checkForLegacyNote();
    });

    // Auto-encrypt new notes added to an encrypted folder
    await joplin.workspace.onNoteChange(async (event: any) => {
      if (event.event === 1) {
        // ItemChangeType.Create
        await autoEncryptNewNote(event.id);
      }
    });

    // Initialize plugin state
    logger.info("Plugin started");
    encryptionDialogId = await joplin.views.dialogs.create("encryptionDialog");
    decryptionDialogId = await joplin.views.dialogs.create("decryptionDialog");
    LegacyNoteDialogId = await joplin.views.dialogs.create("LegacyNoteDialog");
    lockedTagId = await getTagID("secure-notes");
    await updateSettings();
  },
});

/**
 * Update global vars based on settings change.
 */
async function updateSettings() {
  const pluginSettings = await joplin.settings.values([
    SETTINGS_MAIN.KEY_SIZE,
    SETTINGS_MAIN.AES_MODE,
  ]);

  aesOptions = {
    KeySize: pluginSettings[SETTINGS_MAIN.KEY_SIZE] as AesOptions["KeySize"],
    AesMode: pluginSettings[SETTINGS_MAIN.AES_MODE] as AesOptions["AesMode"],
  };

  logger.info("Settings:", aesOptions.KeySize, aesOptions.AesMode);
}

/**
 * Function which triggers encrypt/decrypt Note function based on locked status.
 */
async function toggleLock() {
  logger.debug("ToggleLock invoked");
  // TODO: Fix the workspace.SelectedNote() in joplin and use it.
  // Two calls to the DB can be reduced to one call.
  const [noteId] = await joplin.workspace.selectedNoteIds();
  const note = await joplin.data.get(["notes", noteId], {
    fields: ["id", "body"],
  });
  logger.debug("noteID:", note.id);

  const isLocked = await isNoteLocked(note.body);
  const isOldLocked = await hasTag(note.id, lockedTagId!);
  logger.debug("IsLocked:", isLocked, "IsOldLocked:", isOldLocked);

  if (isLocked) {
    await decryptNote(note);
  } else if (isOldLocked) {
    await decryptOldNote(note);
  } else {
    await encryptNote(note);
  }
}

/**
 * Function to validate password and send back the decrypted data if successful.
 * @param passwd Password that need to be validated
 * @returns Validatation status and Decrypted content if successful.
 */
export async function handlePasswdSubmit(passwd: string) {
  // TODO: Also update this to workspace.selectedNote()
  const [noteId] = await joplin.workspace.selectedNoteIds();
  const note = await joplin.data.get(["notes", noteId], {
    fields: ["*"],
  });

  const parsed = await validateFormat(note.body);

  if (!parsed) {
    logger.error("Invalid format");
    await showToast("Invalid format", ToastType.Error);
    return { type: "error", msg: "Invalid format" };
  }

  try {
    const decryptedContent = await decryptData(
      parsed.aesOptions,
      parsed.data,
      passwd,
    );

    const renderedContent = await renderMarkdown(decryptedContent);

    return {
      type: "success",
      msg: renderedContent,
    };
  } catch (error) {
    if (error instanceof WrongPasswordError) {
      logger.info("Incorrect password");
      return { type: "error", msg: "Incorrect password, try again" };
    }
    logger.error("Decryption error:", error);
    showToast("Decryption failed", ToastType.Error);
    return { type: "error", msg: "Decryption failed" };
  }
}

/**
 * Handle biometric unlock request from content script.
 * Automatically retrieves the stored password and decrypts the note body
 * on disk, then refreshes the view so user can edit freely.
 * The note will be auto-re-encrypted when user navigates away.
 * @returns Decryption result.
 */
export async function handleBiometricUnlock(): Promise<any> {
  try {
    const [noteId] = await joplin.workspace.selectedNoteIds();
    if (!noteId) return { type: "error", msg: "No note selected" };

    const note = await joplin.data.get(["notes", noteId], {
      fields: ["parent_id"],
    });
    if (!note || !note.parent_id) return { type: "error", msg: "No folder" };

    // Check if folder chain is encrypted
    const isEncrypted = await isFolderOrParentEncrypted(note.parent_id);
    if (!isEncrypted) return { type: "error", msg: "Folder not encrypted" };

    // Find the encrypted root folder
    let folderId = note.parent_id;
    while (folderId) {
      if (await isFolderEncrypted(folderId)) break;
      const folder = await joplin.data.get(["folders", folderId], {
        fields: ["parent_id"],
      });
      folderId = folder?.parent_id || "";
    }
    if (!folderId) return { type: "error", msg: "No encrypted folder found" };

    // Try biometric unlock
    const pwd = await authenticateWithBiometrics(folderId);
    if (!pwd) return { type: "error", msg: "Biometric unlock unavailable" };

    // Decrypt the note body on disk for editing
    const fullNote = await joplin.data.get(["notes", noteId], {
      fields: ["*"],
    });
    const parsed = await validateFormat(fullNote.body);
    if (!parsed) return { type: "error", msg: "Invalid format" };

    const decryptedContent = await decryptData(
      parsed.aesOptions,
      parsed.data,
      pwd,
    );

    // Save decrypted body to disk (replaces encrypted content)
    await joplin.data.put(["notes", noteId], null, {
      body: decryptedContent,
    });

    // Set guard before refresh to prevent immediate re-encrypt
    skipReEncryptForRefresh.add(noteId);

    // Track this note for auto-re-encrypt
    unlockedNotes.set(noteId, folderId);

    // Refresh view to show decrypted content
    await refreshNoteView(noteId);

    // Remove guard after refresh completes
    skipReEncryptForRefresh.delete(noteId);

    logger.debug("Biometric unlock + edit mode for note:", noteId);
    return { type: "success", msg: "unlocked" };
  } catch (error) {
    logger.debug("Biometric unlock failed:", error);
    return { type: "error", msg: "Biometric unlock failed" };
  }
}

/**
 * Encrypt the active note using a password and AES encryption.
 * @param note Note to be encrypted.
 */
export async function encryptNote(note: any) {
  logger.debug("EncryptNote invoked");

  const isLocked = await isNoteLocked(note.body);

  if (isLocked) {
    logger.debug("Note is already encrypted");
    await showToast("Note is already encrypted", ToastType.Info);
    return;
  }

  const passwd = await showEncryptionDialog(
    encryptionDialogId,
    "Enter password to Encrypt",
  );
  if (!passwd) {
    logger.debug("Password dialog cancelled");
    return;
  }

  const encryptedData = await encryptData(aesOptions, note.body || "", passwd);
  await joplin.data.put(["notes", note.id], null, {
    body: await generateEncryptedNote(aesOptions, encryptedData),
  });

  await showToast("Note encrypted successfully", ToastType.Success);
  logger.info("Encryption complete");
  await refreshNoteView(note.id);
}

/**
 * Decrypt the active note and remove encryption.
 * @param note Note to be decrypted.
 */
export async function decryptNote(note: any) {
  logger.debug("DecryptNote invoked");
  const isLocked = await isNoteLocked(note.body);

  if (!isLocked) {
    logger.debug("Note is not encrypted");
    await showToast("Note is not encrypted", ToastType.Info);
    return;
  }

  const parsed = await validateFormat(note.body);
  if (!parsed) {
    logger.error("Invalid format");
    await showToast("Invalid format", ToastType.Error);
    return;
  }

  let msg = "Enter password to Decrypt";
  // TODO: This is dangerous, limit it to 3 counts.
  while (true) {
    const passwd = await showDecryptionDialog(decryptionDialogId, msg);
    if (!passwd) {
      logger.debug("Password dialog cancelled");
      return;
    }

    try {
      const decryptedContent = await decryptData(
        parsed.aesOptions,
        parsed.data,
        passwd,
      );
      await joplin.data.put(["notes", note.id], null, {
        body: decryptedContent,
      });
      await showToast("Note decrypted successfully", ToastType.Success);
      logger.info("Decryption complete");
      await refreshNoteView(note.id);
      return;
    } catch (error) {
      if (error instanceof WrongPasswordError) {
        logger.info("Incorrect password");
        msg = "Incorrect password, try again";
      } else {
        logger.info("Decryption failed: ", error);
        showToast("Decryption faild", ToastType.Error);
        return;
      }
    }
  }
}

/**
 * Decrypt the old encryption format note and remove the legacy tag.
 * @param note - Note to be decrypted (must contain id and body).
 */
export async function decryptOldNote(note: any) {
  logger.debug("DecryptOldNote invoked");

  const parsed = validateOldFormat(note.body || "{}");
  if (!parsed) {
    logger.error("Invalid old format");
    await showToast("Invalid old format", ToastType.Error);
    return;
  }

  let msg = "Enter password to Decrypt";

  while (true) {
    const passwd = await showDecryptionDialog(decryptionDialogId, msg);
    if (!passwd) {
      logger.debug("Password dialog cancelled");
      return;
    }
    try {
      const decrypted = await decryptData(
        parsed.encryption,
        parsed.data,
        passwd,
      );
      await joplin.data.put(["notes", note.id], null, { body: decrypted });
      await removeTag(note.id, lockedTagId!);
      await showToast("Note decrypted successfully", ToastType.Success);
      logger.info("Decryption complete:", note.id);
      await refreshNoteView(note.id);
      return;
    } catch (error) {
      if (error instanceof WrongPasswordError) {
        logger.info("Incorrect password");
        msg = "Incorrect password, try again";
      } else {
        logger.info("Decryption failed: ", error);
        showToast("Decryption faild", ToastType.Error);
        return;
      }
    }
  }
}

/**
 * Auto-encrypt a newly created note if its parent folder is encrypted.
 * @param noteId - The ID of the newly created note.
 */
async function autoEncryptNewNote(noteId: string) {
  try {
    const note = await joplin.data.get(["notes", noteId], {
      fields: ["id", "body", "parent_id"],
    });
    if (!note || !note.parent_id) return;

    // Check if the note's parent folder (or ancestor) is encrypted
    const isEncrypted = await isFolderOrParentEncrypted(note.parent_id);
    if (!isEncrypted) return;

    // Don't re-encrypt already locked notes
    if (await isNoteLocked(note.body)) return;

    // Get the top-level encrypted folder's password from keychain
    // Since each folder has its own password, we need the root encrypted folder
    let folderId = note.parent_id;
    while (folderId) {
      if (await isFolderEncrypted(folderId)) break;
      const folder = await joplin.data.get(["folders", folderId], {
        fields: ["parent_id"],
      });
      folderId = folder?.parent_id || "";
    }

    if (!folderId) return;

    // Try to get password from secure storage (keychain)
    const pwd = await getPasswordForFolder(folderId);
    if (!pwd) {
      logger.debug(
        "Auto-encrypt skipped: no stored password for folder",
        folderId,
      );
      return;
    }

    // Encrypt the note
    const encryptedDataStr = await encryptData(aesOptions, note.body || "", pwd);
    const newBody = await generateEncryptedNote(aesOptions, encryptedDataStr);
    await joplin.data.put(["notes", note.id], null, { body: newBody });
    logger.debug("Auto-encrypted new note in encrypted folder:", note.id);
  } catch (err) {
    logger.debug("autoEncryptNewNote error:", err);
  }
}

/**
 * Encrypt Folder command handler.
 * Receives folderId from FolderContextMenu.
 * @param args - Command arguments (folderId from context menu).
 */
async function encryptFolderCmd(...args: any[]) {
  logger.debug("encryptFolderCmd invoked");

  // The first argument is the folderId from FolderContextMenu
  const folderId = args[0];
  if (!folderId) {
    logger.debug("No folderId provided");
    await showToast("No folder selected", ToastType.Error);
    return;
  }

  // Check if already encrypted
  const alreadyEncrypted = await isFolderEncrypted(folderId);
  if (alreadyEncrypted) {
    logger.debug("Folder already encrypted");
    await showToast("Folder is already encrypted", ToastType.Info);
    return;
  }

  // Ask for password (confirm-only dialog since we encrypt with it)
  const passwd = await showEncryptionDialog(
    encryptionDialogId,
    "Enter password to Encrypt this Folder",
  );
  if (!passwd) {
    logger.debug("Folder encryption cancelled");
    return;
  }

  logger.debug("Encrypting folder:", folderId);

  // Perform batch encryption
  const count = await encryptFolderOp(folderId, passwd, aesOptions);

  // Check if biometric is available and offer to store password
  const mobile = await isPlatformMobile();
  if (mobile && count > 0) {
    await storePasswordForFolder(folderId, passwd);
    logger.debug("Folder password stored securely for biometric unlock");
  }

  logger.info("Folder encryption complete:", folderId, "- notes:", count);
}

/**
 * Decrypt Folder command handler.
 * Receives folderId from FolderContextMenu.
 * @param args - Command arguments (folderId from context menu).
 */
async function decryptFolderCmd(...args: any[]) {
  logger.debug("decryptFolderCmd invoked");

  const folderId = args[0];
  if (!folderId) {
    logger.debug("No folderId provided");
    await showToast("No folder selected", ToastType.Error);
    return;
  }

  // Check if folder is actually encrypted
  const encrypted = await isFolderEncrypted(folderId);
  if (!encrypted) {
    logger.debug("Folder not encrypted");
    await showToast("Folder is not encrypted", ToastType.Info);
    return;
  }

  // Try biometric unlock first on mobile
  let passwd: string | null = null;
  const mobile = await isPlatformMobile();
  if (mobile) {
    passwd = await authenticateWithBiometrics(folderId);
  }

  // Fall back to password dialog
  if (!passwd) {
    let msg = "Enter password to Decrypt this Folder";
    while (true) {
      passwd = await showDecryptionDialog(decryptionDialogId, msg);
      if (!passwd) {
        logger.debug("Folder decryption cancelled");
        return;
      }

      try {
        await decryptFolderOp(folderId, passwd, aesOptions);
        break; // Success, exit the loop
      } catch (error) {
        if (error instanceof WrongPasswordError) {
          logger.info("Incorrect password for folder");
          msg = "Incorrect password, try again";
          continue;
        }
        logger.error("Folder decryption failed:", error);
        await showToast("Folder decryption failed", ToastType.Error);
        return;
      }
    }
  } else {
    // Biometric password retrieved — decrypt directly
    try {
      await decryptFolderOp(folderId, passwd, aesOptions);
    } catch (error) {
      logger.error("Folder decryption failed:", error);
      await showToast("Folder decryption failed", ToastType.Error);
    }
  }

  // Optionally remove stored password after decryption
  if (passwd && mobile) {
    await removePasswordForFolder(folderId);
  }
}

/**
 * Unlock a note for editing — decrypts the note body on disk.
 * @param passwd Password to use for decryption.
 * @returns Success/error response.
 */
export async function handleUnlockAndEdit(passwd: string): Promise<any> {
  const [noteId] = await joplin.workspace.selectedNoteIds();
  if (!noteId) return { type: "error", msg: "No note selected" };

  const note = await joplin.data.get(["notes", noteId], {
    fields: ["*"],
  });

  const parsed = await validateFormat(note.body);
  if (!parsed) {
    logger.error("Invalid format");
    return { type: "error", msg: "Invalid format" };
  }

  try {
    const decryptedContent = await decryptData(
      parsed.aesOptions,
      parsed.data,
      passwd,
    );

    // Save decrypted body to disk
    await joplin.data.put(["notes", noteId], null, {
      body: decryptedContent,
    });

    // Find which encrypted folder this note belongs to
    const noteWithFolder = await joplin.data.get(["notes", noteId], {
      fields: ["parent_id"],
    });
    let folderId = noteWithFolder.parent_id || "";
    while (folderId) {
      if (await isFolderEncrypted(folderId)) break;
      const folder = await joplin.data.get(["folders", folderId], {
        fields: ["parent_id"],
      });
      folderId = folder?.parent_id || "";
    }
    if (folderId) {
      unlockedNotes.set(noteId, folderId);
    }

    // Set guard before refresh
    skipReEncryptForRefresh.add(noteId);
    await refreshNoteView(noteId);
    skipReEncryptForRefresh.delete(noteId);
    logger.info("Note unlocked for editing:", noteId);
    return { type: "success", msg: "unlocked" };
  } catch (error) {
    if (error instanceof WrongPasswordError) {
      logger.info("Incorrect password");
      return { type: "error", msg: "Incorrect password, try again" };
    }
    logger.error("Unlock failed:", error);
    return { type: "error", msg: "Decryption failed" };
  }
}

/**
 * Re-encrypt all notes that were previously unlocked for editing.
 * Called when user navigates away from a note.
 */
async function reEncryptUnlockedNotes() {
  if (unlockedNotes.size === 0) return;

  logger.debug("Re-encrypting unlocked notes:", unlockedNotes.size);

  for (const [noteId, folderId] of unlockedNotes.entries()) {
    // Skip notes that are currently being refreshed
    if (skipReEncryptForRefresh.has(noteId)) continue;
    try {
      const pwd = await getPasswordForFolder(folderId);
      if (!pwd) {
        logger.debug("No stored password for folder, skipping re-encrypt:", folderId);
        continue;
      }

      const note = await joplin.data.get(["notes", noteId], {
        fields: ["id", "body"],
      });
      if (!note) continue;

      // Skip if already encrypted
      if (await isNoteLocked(note.body)) continue;

      // Re-encrypt
      const encryptedDataStr = await encryptData(aesOptions, note.body || "", pwd);
      const newBody = await generateEncryptedNote(aesOptions, encryptedDataStr);
      await joplin.data.put(["notes", noteId], null, { body: newBody });
      logger.debug("Re-encrypted note:", noteId);
    } catch (err) {
      logger.error("reEncryptUnlockedNotes error for note:", noteId, err);
    }
  }

  unlockedNotes.clear();
  logger.info("All unlocked notes re-encrypted");
}

/**
 * Checks if the currently selected note has the legacy "secure-notes" tag,
 * Checks if the currently selected note has the legacy "secure-notes" tag,
 * and if so, shows a migration dialog with Decrypt and Close options.
 */
async function checkForLegacyNote() {
  const note = await joplin.workspace.selectedNote();
  if (!note) return;

  if (!lockedTagId) return;
  if (!(await hasTag(note.id, lockedTagId))) return;

  const shouldDecrypt = await showLegacyDialog(LegacyNoteDialogId);
  if (!shouldDecrypt) return;

  const fullNote = await joplin.data.get(["notes", note.id], {
    fields: ["id", "body"],
  });
  await decryptOldNote(fullNote);
}
