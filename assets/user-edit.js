const csrfMeta = document.querySelector('meta[name="dassiedrop-csrf-token"]');
const csrfToken = (csrfMeta && csrfMeta.content) || "";
const editUserName = document.getElementById("editUserName");
const editUserPassword = document.getElementById("editUserPassword");
const editUserApiKey = document.getElementById("editUserApiKey");
const editUserRole = document.getElementById("editUserRole");
const saveEditUserBtn = document.getElementById("saveEditUserBtn");
const editUserStatus = document.getElementById("editUserStatus");
const userId = new URLSearchParams(window.location.search).get("id") || "";

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
    const user = (payload.users || []).find((candidate) => candidate.id === userId);
    if (!user) {
      editUserStatus.textContent = "User not found.";
      saveEditUserBtn.disabled = true;
      return;
    }
    editUserName.value = user.username;
    editUserRole.value = user.role;
  } catch (error) {
    editUserStatus.textContent = "Could not load user.";
    saveEditUserBtn.disabled = true;
  }
}

async function saveEditUser() {
  const username = editUserName.value.trim();
  if (!username) {
    editUserStatus.textContent = "Username required.";
    editUserName.focus();
    return;
  }

  const payload = {
    username,
    role: editUserRole.value
  };
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

loadUser();
