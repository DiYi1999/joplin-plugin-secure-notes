/*****************************************************************************
 * @file        : src/folderManager.ts
 * @description : Manages folder-level encryption for Secure Notes plugin.
 *                Handles recursive encrypt/decrypt of all notes within a
 *                folder, and stores encryption state via Joplin userData API.
 * @author      : Aravind Potluri <aravindswami135@gmail.com>
 *****************************************************************************/

/** Imports */
import joplin from "api";
import { ModelType } from "api/types";
import { ToastType } from "api/types";
import {
  showToast,
  getNotesInFolder,
  getAllFolderIdsRecursive,
  isNoteLocked,
  generateEncryptedNote,
  validateFormat,
} from "./utils";
import { AesOptions, encryptData, decryptData, WrongPasswordError } from "./encryption";
import { createLogger } from "./pluginLogger";

/** Logger */
const logger = createLogger("[FolderManager]", "DEBUG");

/** Key used to store encryption state in folder userData */
const USER_DATA_KEY = "secureNotes.encrypted";

/**
 * Checks if a folder is marked as encrypted via userData.
 * @param folderId - The folder ID to check.
 * @returns True if the folder has encryption state set.
 */
export async function isFolderEncrypted(folderId: string): Promise<boolean> {
  try {
    const state = await joplin.data.userDataGet(
      ModelType.Folder,
      folderId,
      USER_DATA_KEY,
    );
    return !!(state && (state as any).encrypted);
  } catch (err) {
    logger.debug("isFolderEncrypted error:", err);
    return false;
  }
}

/**
 * Sets the encryption state on a folder.
 * @param folderId - The target folder ID.
 * @param encrypted - True to mark encrypted, false to remove mark.
 */
export async function setFolderEncryptionState(
  folderId: string,
  encrypted: boolean,
): Promise<void> {
  try {
    if (encrypted) {
      await joplin.data.userDataSet(
        ModelType.Folder,
        folderId,
        USER_DATA_KEY,
        { encrypted: true, encryptedAt: Date.now() },
      );
    } else {
      await joplin.data.userDataSet(
        ModelType.Folder,
        folderId,
        USER_DATA_KEY,
        {},
      );
    }
  } catch (err) {
    logger.error("setFolderEncryptionState error:", err);
  }
}

/**
 * Encrypts all unencrypted notes in a folder (recursively including sub-folders).
 * @param folderId - The folder ID to encrypt.
 * @param passwd - The password to use for encryption.
 * @param aesOptions - AES configuration options.
 * @returns The number of notes encrypted.
 */
export async function encryptFolder(
  folderId: string,
  passwd: string,
  aesOptions: AesOptions,
): Promise<number> {
  logger.debug("encryptFolder invoked for:", folderId);

  // Get all folder IDs recursively
  const allFolderIds = await getAllFolderIdsRecursive(folderId);
  let encryptedCount = 0;

  for (const fId of allFolderIds) {
    const notes = await getNotesInFolder(fId);
    for (const note of notes) {
      // Skip already-encrypted notes
      if (await isNoteLocked(note.body)) {
        logger.debug("Note already encrypted, skipping:", note.id);
        continue;
      }

      try {
        const encryptedDataStr = await encryptData(aesOptions, note.body || "", passwd);
        const newBody = await generateEncryptedNote(aesOptions, encryptedDataStr);
        await joplin.data.put(["notes", note.id], null, { body: newBody });
        encryptedCount++;
      } catch (err) {
        logger.error("Failed to encrypt note:", note.id, err);
      }
    }
  }

  // Mark the root folder as encrypted
  await setFolderEncryptionState(folderId, true);

  await showToast(
    `Folder encrypted: ${encryptedCount} note(s) processed`,
    ToastType.Success,
  );
  logger.info("Folder encryption complete, notes encrypted:", encryptedCount);
  return encryptedCount;
}

/**
 * Decrypts all notes in a folder (recursively including sub-folders).
 * @param folderId - The folder ID to decrypt.
 * @param passwd - The password to use for decryption.
 * @param aesOptions - AES configuration options.
 * @returns The number of notes decrypted.
 */
export async function decryptFolder(
  folderId: string,
  passwd: string,
  aesOptions: AesOptions,
): Promise<number> {
  logger.debug("decryptFolder invoked for:", folderId);

  // First, validate the password by trying to decrypt the first encrypted note
  const validationResult = await validateFolderPassword(
    folderId,
    passwd,
    aesOptions,
  );
  if (!validationResult) {
    throw new WrongPasswordError();
  }

  // Get all folder IDs recursively
  const allFolderIds = await getAllFolderIdsRecursive(folderId);
  let decryptedCount = 0;

  for (const fId of allFolderIds) {
    const notes = await getNotesInFolder(fId);
    for (const note of notes) {
      if (!(await isNoteLocked(note.body))) {
        continue; // Skip non-encrypted notes
      }

      const parsed = await validateFormat(note.body);
      if (!parsed) {
        logger.debug("Invalid format, skipping:", note.id);
        continue;
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
        decryptedCount++;
      } catch (err) {
        // If password validation passed but a note fails, it may use a different
        // (individual) password — skip it
        logger.debug("Skipping note (wrong password or error):", note.id);
      }
    }
  }

  // Remove the encryption mark from the root folder
  await setFolderEncryptionState(folderId, false);

  await showToast(
    `Folder decrypted: ${decryptedCount} note(s) processed`,
    ToastType.Success,
  );
  logger.info("Folder decryption complete, notes decrypted:", decryptedCount);
  return decryptedCount;
}

/**
 * Re-encrypts notes in an already-encrypted folder.
 * Useful for encrypting newly-added notes without re-encrypting existing ones.
 * @param folderId - The folder ID.
 * @param passwd - The password to use for encryption.
 * @param aesOptions - AES configuration options.
 * @returns The number of notes newly encrypted.
 */
export async function reEncryptFolder(
  folderId: string,
  passwd: string,
  aesOptions: AesOptions,
): Promise<number> {
  // Validate the folder is marked as encrypted
  if (!(await isFolderEncrypted(folderId))) {
    logger.debug("Folder is not encrypted, running full encrypt instead");
    return encryptFolder(folderId, passwd, aesOptions);
  }

  // Only encrypt notes that aren't already locked
  const notes = await getNotesInFolder(folderId);
  let encryptedCount = 0;

  for (const note of notes) {
    if (await isNoteLocked(note.body)) continue;

    try {
      const encryptedDataStr = await encryptData(aesOptions, note.body || "", passwd);
      const newBody = await generateEncryptedNote(aesOptions, encryptedDataStr);
      await joplin.data.put(["notes", note.id], null, { body: newBody });
      encryptedCount++;
    } catch (err) {
      logger.error("reEncryptFolder: Failed to encrypt note:", note.id, err);
    }
  }

  if (encryptedCount > 0) {
    await showToast(
      `New notes encrypted: ${encryptedCount}`,
      ToastType.Success,
    );
  }
  return encryptedCount;
}

/**
 * Attempts to decrypt a single note — used to validate the folder password.
 * @param folderId - The folder containing the note.
 * @param passwd - Password to test.
 * @param aesOptions - Fallback AES options.
 * @returns True if password is valid for at least one note.
 */
async function validateFolderPassword(
  folderId: string,
  passwd: string,
  aesOptions: AesOptions,
): Promise<boolean> {
  const allFolderIds = await getAllFolderIdsRecursive(folderId);

  for (const fId of allFolderIds) {
    const notes = await getNotesInFolder(fId);
    for (const note of notes) {
      if (!(await isNoteLocked(note.body))) continue;

      const parsed = await validateFormat(note.body);
      if (!parsed) continue;

      try {
        await decryptData(parsed.aesOptions, parsed.data, passwd);
        return true; // Successfully decrypted a note
      } catch {
        continue; // Try next note
      }
    }
  }

  return false; // No note could be decrypted with this password
}
