const csrfMeta = document.querySelector('meta[name="dassiedrop-csrf-token"]');
const csrfToken = (csrfMeta && csrfMeta.content) || "";
const accessCodeInput = document.getElementById("settingsAccessCode");
const apiKeyInput = document.getElementById("settingsApiKey");
const superPasswordInput = document.getElementById("settingsSuperPassword");
const clearAccessCode = document.getElementById("clearAccessCode");
const clearApiKey = document.getElementById("clearApiKey");
const clearSuperPassword = document.getElementById("clearSuperPassword");
const saveSettingsBtn = document.getElementById("saveSettingsBtn");
const settingsStatus = document.getElementById("settingsStatus");
const accessCodeState = document.getElementById("accessCodeState");
const apiKeyState = document.getElementById("apiKeyState");
const superPasswordState = document.getElementById("superPasswordState");
const hashIterationsState = document.getElementById("hashIterationsState");

function withCsrfHeaders(headers = {}) {
  if (!csrfToken) {
    return headers;
  }
  return { ...headers, "X-CSRF-Token": csrfToken };
}

function configuredLabel(value) {
  return value ? "Configured" : "Not configured";
}

function renderSettings(settings) {
  accessCodeState.textContent = configuredLabel(settings.access_code_configured);
  apiKeyState.textContent = configuredLabel(settings.api_key_configured);
  superPasswordState.textContent = configuredLabel(settings.workspace_super_password_configured);
  hashIterationsState.textContent = String(settings.password_hash_iterations || "");
}

function bindClearControl(input, checkbox) {
  function syncClearState() {
    input.disabled = checkbox.checked;
    input.classList.toggle("settings-input-cleared", checkbox.checked);
    if (checkbox.checked) {
      input.value = "";
    }
  }
  checkbox.addEventListener("change", syncClearState);
  syncClearState();
  return syncClearState;
}

const syncClearControls = [
  bindClearControl(accessCodeInput, clearAccessCode),
  bindClearControl(apiKeyInput, clearApiKey),
  bindClearControl(superPasswordInput, clearSuperPassword)
];

function syncAllClearControls() {
  syncClearControls.forEach((syncClearControl) => syncClearControl());
}

async function loadSettings() {
  try {
    const response = await fetch("/api/settings");
    if (!response.ok) {
      throw new Error(`Settings load failed: ${response.status}`);
    }
    renderSettings(await response.json());
  } catch (error) {
    settingsStatus.textContent = "Could not load settings.";
  }
}

async function saveSettings() {
  const payload = {};
  if (clearAccessCode.checked || accessCodeInput.value) {
    payload.access_code = clearAccessCode.checked ? "" : accessCodeInput.value;
  }
  if (clearApiKey.checked || apiKeyInput.value) {
    payload.api_key = clearApiKey.checked ? "" : apiKeyInput.value;
  }
  if (clearSuperPassword.checked || superPasswordInput.value) {
    payload.workspace_super_password = clearSuperPassword.checked ? "" : superPasswordInput.value;
  }
  settingsStatus.textContent = "Saving...";
  try {
    const response = await fetch("/api/settings", {
      method: "POST",
      headers: withCsrfHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify(payload)
    });
    if (!response.ok) {
      throw new Error(`Settings save failed: ${response.status}`);
    }
    accessCodeInput.value = "";
    apiKeyInput.value = "";
    superPasswordInput.value = "";
    clearAccessCode.checked = false;
    clearApiKey.checked = false;
    clearSuperPassword.checked = false;
    syncAllClearControls();
    renderSettings(await response.json());
    settingsStatus.textContent = "Settings saved.";
  } catch (error) {
    settingsStatus.textContent = "Could not save settings.";
  }
}

saveSettingsBtn.addEventListener("click", saveSettings);
loadSettings();
