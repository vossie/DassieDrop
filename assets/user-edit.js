const csrfMeta = document.querySelector('meta[name="dassiedrop-csrf-token"]');
const csrfToken = (csrfMeta && csrfMeta.content) || "";
const editUserName = document.getElementById("editUserName");
const editUserNameField = document.getElementById("editUserNameField");
const editUserPassword = document.getElementById("editUserPassword");
const editUserApiKey = document.getElementById("editUserApiKey");
const editUserRole = document.getElementById("editUserRole");
const editUserRoleField = document.getElementById("editUserRoleField");
const setupTotpBtn = document.getElementById("setupTotpBtn");
const disableTotpBtn = document.getElementById("disableTotpBtn");
const totpSetupPanel = document.getElementById("totpSetupPanel");
const totpQrCode = document.getElementById("totpQrCode");
const totpServerTime = document.getElementById("totpServerTime");
const totpServerCode = document.getElementById("totpServerCode");
const totpSecret = document.getElementById("totpSecret");
const totpUri = document.getElementById("totpUri");
const totpCode = document.getElementById("totpCode");
const confirmTotpBtn = document.getElementById("confirmTotpBtn");
const saveEditUserBtn = document.getElementById("saveEditUserBtn");
const editUserStatus = document.getElementById("editUserStatus");
const userId = new URLSearchParams(window.location.search).get("id") || "";
let canManageUsers = false;
let loadedUser = null;
let currentUserId = "";

function withCsrfHeaders(headers = {}) {
  if (!csrfToken) {
    return headers;
  }
  return { ...headers, "X-CSRF-Token": csrfToken };
}

async function loadUser() {
  if (!userId) {
    editUserStatus.textContent = "User not found.";
    saveEditUserBtn.disabled = true;
    return;
  }
  try {
    const response = await fetch("/api/users");
    if (!response.ok) {
      throw new Error(`Users load failed: ${response.status}`);
    }
    const payload = await response.json();
    canManageUsers = Boolean(payload.can_manage_users);
    currentUserId = payload.current_user_id || "";
    const user = (payload.users || []).find((candidate) => candidate.id === userId);
    if (!user) {
      editUserStatus.textContent = "User not found.";
      saveEditUserBtn.disabled = true;
      return;
    }
    loadedUser = user;
    editUserName.value = user.username;
    editUserRole.value = user.role;
    editUserName.disabled = !canManageUsers;
    editUserRole.disabled = !canManageUsers;
    editUserNameField.classList.toggle("user-self-hidden", !canManageUsers);
    editUserRoleField.classList.toggle("user-self-hidden", !canManageUsers);
    setupTotpBtn.hidden = userId !== currentUserId;
    disableTotpBtn.hidden = userId !== currentUserId && !canManageUsers;
    disableTotpBtn.disabled = !user.totp_enabled;
    setupTotpBtn.textContent = user.totp_enabled ? "Reset Authenticator" : "Set Up";
  } catch (error) {
    editUserStatus.textContent = "Could not load user.";
    saveEditUserBtn.disabled = true;
  }
}

async function setupTotp() {
  editUserStatus.textContent = "Creating authenticator secret...";
  try {
    const response = await fetch(`/api/users/${encodeURIComponent(userId)}/totp/setup`, {
      method: "POST",
      headers: withCsrfHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({})
    });
    if (!response.ok) {
      throw new Error(`Authenticator setup failed: ${response.status}`);
    }
    const payload = await response.json();
    totpQrCode.innerHTML = payload.qr_svg || "";
    totpSecret.value = payload.secret || "";
    totpUri.value = payload.otpauth_uri || "";
    if (payload.server_time) {
      const serverDate = new Date(payload.server_time * 1000);
      totpServerTime.textContent = `Server time: ${serverDate.toISOString().replace(".000", "")}`;
    } else {
      totpServerTime.textContent = "";
    }
    totpServerCode.textContent = payload.server_code ? `Server check code: ${payload.server_code}` : "";
    totpCode.value = "";
    totpSetupPanel.hidden = false;
    editUserStatus.textContent = "Add the secret to your authenticator app.";
    totpCode.focus();
  } catch (error) {
    editUserStatus.textContent = "Could not start authenticator setup.";
  }
}

async function confirmTotp() {
  if (confirmTotpBtn.disabled) {
    return;
  }
  const code = totpCode.value.trim();
  if (!/^\d{6}$/.test(code)) {
    editUserStatus.textContent = "Enter the 6-digit authenticator code.";
    totpCode.focus();
    return;
  }
  editUserStatus.textContent = "Checking authenticator code...";
  confirmTotpBtn.disabled = true;
  try {
    const response = await fetch(`/api/users/${encodeURIComponent(userId)}/totp/confirm`, {
      method: "POST",
      headers: withCsrfHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ code })
    });
    if (!response.ok) {
      const message = await response.text();
      throw new Error(message || `Authenticator confirm failed: ${response.status}`);
    }
    const payload = await response.json();
    loadedUser = payload.user || loadedUser;
    totpSetupPanel.hidden = true;
    disableTotpBtn.disabled = false;
    setupTotpBtn.textContent = "Reset Authenticator";
    editUserStatus.textContent = "Authenticator enabled.";
  } catch (error) {
    confirmTotpBtn.disabled = false;
    editUserStatus.textContent = error.message.includes("Authenticator setup has not been started")
      ? "Authenticator setup expired. Click Set Up and scan the current QR again."
      : "Wrong authenticator code. Check that it matches the current server check code shown above.";
  }
}

async function disableTotp() {
  if (loadedUser && !loadedUser.totp_enabled) {
    return;
  }
  editUserStatus.textContent = "Disabling authenticator...";
  try {
    const response = await fetch(`/api/users/${encodeURIComponent(userId)}/totp`, {
      method: "DELETE",
      headers: withCsrfHeaders({ "Content-Type": "application/json" })
    });
    if (!response.ok) {
      throw new Error(`Authenticator disable failed: ${response.status}`);
    }
    const payload = await response.json();
    loadedUser = payload.user || loadedUser;
    totpSetupPanel.hidden = true;
    disableTotpBtn.disabled = true;
    setupTotpBtn.textContent = "Set Up";
    editUserStatus.textContent = "Authenticator disabled.";
  } catch (error) {
    editUserStatus.textContent = "Could not disable authenticator.";
  }
}

async function saveEditUser() {
  const payload = {};
  if (canManageUsers) {
    const username = editUserName.value.trim();
    if (!username) {
      editUserStatus.textContent = "Username required.";
      editUserName.focus();
      return;
    }
    payload.username = username;
    payload.role = editUserRole.value;
  }
  if (editUserPassword.value) {
    payload.password = editUserPassword.value;
  }
  if (editUserApiKey.value) {
    payload.api_key = editUserApiKey.value;
  }

  editUserStatus.textContent = "Saving...";
  try {
    const response = await fetch(`/api/users/${encodeURIComponent(userId)}`, {
      method: "POST",
      headers: withCsrfHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify(payload)
    });
    if (!response.ok) {
      throw new Error(`User save failed: ${response.status}`);
    }
    window.location.href = "/users";
  } catch (error) {
    editUserStatus.textContent = "Could not save user.";
  }
}

saveEditUserBtn.addEventListener("click", saveEditUser);
setupTotpBtn.addEventListener("click", setupTotp);
confirmTotpBtn.addEventListener("click", confirmTotp);
disableTotpBtn.addEventListener("click", disableTotp);
editUserName.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    saveEditUser();
  }
});
editUserPassword.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    saveEditUser();
  }
});
editUserApiKey.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    saveEditUser();
  }
});
totpCode.addEventListener("input", () => {
  totpCode.value = totpCode.value.replace(/\D/g, "").slice(0, 6);
});
totpCode.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    confirmTotp();
  }
});

loadUser();
