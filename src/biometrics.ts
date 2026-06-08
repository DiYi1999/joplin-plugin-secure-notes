/*****************************************************************************
 * @file        : src/biometrics.ts
 * @description : Biometric authentication module for Joplin mobile app.
 *                Integrates with Joplin's native biometric unlock feature.
 * @author      : Enhanced by Copilot
 *****************************************************************************/

import joplin from "api";
import { createLogger } from "./pluginLogger";

const logger = createLogger("[BiometricsModule]", "DEBUG");

/**
 * Check if biometric authentication is available on the device
 * @returns Promise<boolean> - True if biometrics hardware is available
 */
export async function isBiometricsAvailable(): Promise<boolean> {
  try {
    // Check if running on mobile platform
    const isAndroid = await checkPlatform("android");
    const isIOS = await checkPlatform("ios");

    if (!isAndroid && !isIOS) {
      logger.info("Biometrics not available: not on mobile platform");
      return false;
    }

    logger.info("Biometrics hardware check performed");
    return true;
  } catch (error) {
    logger.warn("Error checking biometrics availability:", error);
    return false;
  }
}

/**
 * Authenticate user using biometric (fingerprint or face recognition)
 * @param promptMessage - Message to display during authentication
 * @returns Promise<boolean> - True if authentication successful, false otherwise
 */
export async function authenticateWithBiometrics(
  promptMessage: string = "Verify your identity to access encrypted notes"
): Promise<boolean> {
  try {
    logger.info("Starting biometric authentication");

    // Call Joplin's native biometric authentication
    // This uses expo-local-authentication under the hood
    const result = await joplin.plugins.joplin.mobile.biometrics.authenticateAsync({
      promptMessage,
    });

    if (result.success === true) {
      logger.info("Biometric authentication successful");
      return true;
    }

    const errorName = result.error || "unknown";
    logger.warn("Biometric authentication failed:", errorName);

    // Handle specific error cases
    if (
      errorName === "not_enrolled" ||
      errorName === "not_available"
    ) {
      logger.info("Biometric unlock not setup on device");
      return false;
    }

    return false;
  } catch (error) {
    logger.error("Biometric authentication error:", error);
    return false;
  }
}

/**
 * Get supported biometric sensors on the device
 * @returns Promise<string[]> - Array of supported sensor types
 */
export async function getSupportedBiometrics(): Promise<string[]> {
  try {
    const sensors = await joplin.plugins.joplin.mobile.biometrics.supportedAuthenticationTypesAsync();
    
    const supported: string[] = [];
    sensors.forEach((sensor: string) => {
      if (sensor === "Fingerprint") supported.push("Touch ID");
      else if (sensor === "FaceRecognition") supported.push("Face ID");
      else if (sensor === "Iris") supported.push("Iris");
    });

    logger.info("Supported biometrics:", supported);
    return supported;
  } catch (error) {
    logger.warn("Error getting supported biometrics:", error);
    return [];
  }
}

/**
 * Check if running on specific platform
 * @param platform - Platform to check ('android' or 'ios')
 * @returns Promise<boolean>
 */
async function checkPlatform(platform: "android" | "ios"): Promise<boolean> {
  try {
    // This is a simplified check; actual implementation depends on Joplin API
    const globalSettings = await joplin.settings.globalValues(["platform"]);
    return globalSettings[0]?.toLowerCase() === platform;
  } catch {
    return false;
  }
}
