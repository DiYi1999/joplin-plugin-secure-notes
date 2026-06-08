/**
 * @file        : src/contentScripts/runtime.js
 * @description : SecureView runtime script.
 */

let contentScriptId = "SecureView";

// Plugin Logger
function logger(msg) {
  webviewApi.postMessage(contentScriptId, { type: "log", msg: msg });
}

// ShowInputBox Error function
async function shakeInput(input, placeholderMsg) {
  input.value = "";
  input.placeholder = placeholderMsg;
  input.classList.add("jiggle");
  setTimeout(() => input.classList.remove("jiggle"), 400);
  input.focus();
}

// Unlock for editing function
async function handleSubmit() {
  const csID = document.getElementById("data-contentscript-id").innerText;
  const input = document.getElementById("md-lock-input");
  const password = input?.value?.trim() ?? "";

  if (!password) {
    await shakeInput(input, "Password cannot be empty");
    logger("Empty password");
    return;
  }

  // Show unlocking state
  const btn = document.getElementById("md-lock-btn");
  if (btn) {
    btn.disabled = true;
    btn.textContent = "Unlocking...";
  }

  const result = await webviewApi.postMessage(csID, {
    type: "unlockAndEdit",
    msg: password,
  });

  if (result.type === "error") {
    if (btn) {
      btn.disabled = false;
      btn.textContent = "Unlock";
    }
    await shakeInput(input, result.msg);
    return;
  }

  // Success — note will be refreshed automatically, no need to update UI
  logger("Note unlocked for editing");
}

// Initializtion
async function init() {
  const snMd = document.getElementById("sn-md");
  const snRte = document.getElementById("sn-rte");
  const input = document.getElementById("md-lock-input");

  const isRTE = document.body.classList.contains("mce-content-body");

  // NOTE: The remove(), is solving the RTE bug.
  if (isRTE) {
    // Show only RTE div, remove MD div entirely
    if (snMd) snMd.remove();
    if (snRte) snRte.style.display = "block";
  } else {
    // Show only MD div, remove RTE div entirely
    if (snRte) snRte.remove();
    if (snMd) snMd.style.display = "flex";
    if (input) {
      input.value = "";
      input.placeholder = "Enter Password to Unlock & Edit";
      input.focus();
    }

    // Try biometric unlock silently after render
    setTimeout(async () => {
      try {
        const csID = document.getElementById("data-contentscript-id");
        if (!csID) return;
        const btn = document.getElementById("md-lock-btn");
        if (btn) {
          btn.disabled = true;
          btn.textContent = "Unlocking...";
        }
        const result = await webviewApi.postMessage(csID.innerText, {
          type: "biometricUnlock",
        });
        if (result && result.type === "success") {
          // Note body decrypted on disk, note view will refresh
          logger("Biometric unlock successful");
        } else {
          // Fall back to password input
          if (btn) {
            btn.disabled = false;
            btn.textContent = "Unlock & Edit";
          }
        }
      } catch (e) {
        // Biometric not available — silently fall back to password input
        const btn = document.getElementById("md-lock-btn");
        if (btn) {
          btn.disabled = false;
          btn.textContent = "Unlock & Edit";
        }
      }
    }, 300);
  }
}

// Click event listener
document.addEventListener("click", function (e) {
  if (e.target.id === "md-lock-btn") {
    handleSubmit();
  }
});

// Keypress eventlistener
document.addEventListener("keydown", function (e) {
  if (e.target.id === "md-lock-input" && e.key === "Enter") {
    e.preventDefault();
    handleSubmit();
  }
});

// Content update event listener
document.addEventListener("joplin-noteDidUpdate", async () => {
  await init();
});

// Delay run for artifacts
setTimeout(async () => {
  await init();
}, 250);
