/*****************************************************************************
 * @file        : src/biometrics.ts
 * @description : Biometric authentication integration for Secure Notes.
 *                On mobile: leverages Joplin's app-level biometric lock.
 *                All folder passwords stored in ONE secure setting (OS keychain).
 * @author      : Aravind Potluri <aravindswami135@gmail.com>
 *****************************************************************************/

/** Imports */
import joplin from "api";
import { createLogger } from "./pluginLogger";

/** Logger */
const logger = createLogger("[Biometrics]", "DEBUG");

/** Setting key where all folder passwords are stored as JSON string */
export const FOLDER_PASSWORDS_KEY = "SecureNotes.settings.folderPasswords";

/**
 * Detects whether the plugin is running on a mobile platform.
 * @returns True if running on mobile (Android/iOS).
 */
export async function isPlatformMobile(): Promise<boolean> {
  try {
    const versionInfo = await joplin.versionInfo();
    return versionInfo.platform === "mobile";
  } catch (err) {
    logger.error("isPlatformMobile error:", err);
    return false;
  }
}

/**
 * Checks if biometric authentication is available.
 * On mobile: returns true (Joplin provides app-level biometric lock).
 * On desktop: returns false (no biometric API through plugin).
 * @returns True if biometric unlock is feasible.
 */
export async function isBiometricAvailable(): Promise<boolean> {
  try {
    const mobile = await isPlatformMobile();
    if (!mobile) return false;

    // Check if the user has enabled biometric unlock in settings
    const settings = await joplin.settings.values(["biometricEnabled"]);
    return !!(settings.biometricEnabled as boolean);
  } catch (err) {
    logger.error("isBiometricAvailable error:", err);
    return false;
  }
}

/**
 * Reads all stored folder passwords from the single secure setting.
 * @returns Map of folderId -> password.
 */
async function readAllPasswords(): Promise<Record<string, string>> {
  try {
    const raw = await joplin.settings.value(FOLDER_PASSWORDS_KEY);
    if (raw && typeof raw === "string" && raw.length > 0) {
      return JSON.parse(raw);
    }
    return {};
  } catch (err) {
    logger.debug("readAllPasswords error:", err);
    return {};
  }
}

/**
 * Writes the full passwords map to the single secure setting.
 * @param map - Record of folderId -> password.
 */
async function writeAllPasswords(map: Record<string, string>): Promise<void> {
  try {
    await joplin.settings.setValue(FOLDER_PASSWORDS_KEY, JSON.stringify(map));
  } catch (err) {
    logger.error("writeAllPasswords error:", err);
  }
}

/**
 * Stores a folder's encryption password in the OS keychain
 * via Joplin's single secure setting.
 * @param folderId - The folder ID.
 * @param password - The password to store.
 */
export async function storePasswordForFolder(
  folderId: string,
  password: string,
): Promise<void> {
  const map = await readAllPasswords();
  map[folderId] = password;
  await writeAllPasswords(map);
  logger.debug("Password stored securely for folder:", folderId);
}

/**
 * Retrieves a folder's encryption password from the OS keychain.
 * On mobile, this requires the app-level biometric/password lock to
 * have been satisfied already.
 * @param folderId - The folder ID.
 * @returns The stored password, or null if not found.
 */
export async function getPasswordForFolder(
  folderId: string,
): Promise<string | null> {
  const map = await readAllPasswords();
  const pwd = map[folderId];
  return pwd && pwd.length > 0 ? pwd : null;
}

/**
 * Removes a stored folder password from the keychain.
 * @param folderId - The folder ID.
 */
export async function removePasswordForFolder(
  folderId: string,
): Promise<void> {
  const map = await readAllPasswords();
  delete map[folderId];
  await writeAllPasswords(map);
  logger.debug("Password removed for folder:", folderId);
}

/**
 * Attempts to retrieve the folder password using biometric unlock.
 *
 * Flow:
 * 1. Check if platform is mobile and biometric setting is enabled
 * 2. If yes, the Joplin app-level biometric lock already protected
 *    the session, so we can directly read from the secure setting
 *
 * @param folderId - The folder to unlock.
 * @returns The folder password if available, null otherwise.
 */
export async function authenticateWithBiometrics(
  folderId: string,
): Promise<string | null> {
  const mobile = await isPlatformMobile();
  if (!mobile) {
    logger.debug("Biometrics not available on desktop");
    return null;
  }

  if (!(await isBiometricAvailable())) {
    logger.debug("Biometric unlock not enabled in settings");
    return null;
  }

  logger.debug("Attempting biometric unlock for folder:", folderId);
  const password = await getPasswordForFolder(folderId);
  if (password) {
    logger.debug("Biometric unlock successful for folder:", folderId);
    return password;
  }

  logger.debug("No stored password found for folder:", folderId);
  return null;
}
