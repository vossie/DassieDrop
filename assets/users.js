const csrfMeta = document.querySelector('meta[name="dassiedrop-csrf-token"]');
const csrfToken = (csrfMeta && csrfMeta.content) || "";
const editUserPanel = document.getElementById("editUserPanel");
const editUserName = document.getElementById("editUserName");
const editUserPassword = document.getElementById("editUserPassword");
const editUserApiKey = document.getElementById("editUserApiKey");
const editUserRole = document.getElementById("editUserRole");
const saveEditUserBtn = document.getElementById("saveEditUserBtn");
const cancelEditUserBtn = document.getElementById("cancelEditUserBtn");
const usersStatus = document.getElementById("usersStatus");
const usersList = document.getElementById("usersList");

function withCsrfHeaders(headers = {}) {
  if (!csrfToken) {
    return headers;
  }
  return { ...headers, "X-CSRF-Token": csrfToken };
}

function formatUserDate(ts) {
  if (!ts) {
    return "Just now";
  }
  return new Date(ts * 1000).toLocaleString();
}

function clearEditUser() {
  editUserName.value = "";
  editUserPassword.value = "";
  editUserApiKey.value = "";
  editUserRole.value = "user";
  editUserPanel.classList.add("hidden");
  editUserPanel.setAttribute("aria-hidden", "true");
}

function beginEditUser(user) {
  editUserName.value = user.username;
  editUserPassword.value = "";
  editUserApiKey.value = "";
  editUserRole.value = user.role;
  editUserPanel.classList.remove("hidden");
  editUserPanel.setAttribute("aria-hidden", "false");
  editUserName.focus();
  usersStatus.textContent = "Editing user. Leave password or API key blank to keep the stored value.";
}

function renderUsers(users) {
  usersList.innerHTML = "";
  if (!users.length) {
    const li = document.createElement("li");
    li.className = "muted";
    li.textContent = "No users yet.";
    usersList.appendChild(li);
    return;
  }

  for (const user of users) {
    const li = document.createElement("li");
    li.className = "history-item user-item";

    const details = document.createElement("div");
    details.className = "workspace-details";

    const name = document.createElement("div");
    name.className = "file-name";
    name.textContent = user.username;

    const meta = document.createElement("div");
    meta.className = "meta workspace-meta";
    const passwordState = user.password_configured ? "password set" : "no password";
    const apiKeyState = user.api_key_configured ? "API key set" : "no API key";
    meta.textContent = `${user.role} - ${passwordState} - ${apiKeyState} - Updated ${formatUserDate(user.updated_at)}`;

    details.appendChild(name);
    details.appendChild(meta);

    const actions = document.createElement("div");
    actions.className = "file-card-actions";

    const editBtn = document.createElement("button");
    editBtn.type = "button";
    editBtn.textContent = "Edit";
    editBtn.addEventListener("click", () => beginEditUser(user));

    const deleteBtn = document.createElement("button");
    deleteBtn.type = "button";
    deleteBtn.className = "danger";
    deleteBtn.textContent = "Delete";
    deleteBtn.addEventListener("click", async () => {
      try {
        const response = await fetch(`/api/users/${encodeURIComponent(user.id)}`, {
          method: "DELETE",
          headers: withCsrfHeaders({ "Content-Type": "application/json" })
        });
        if (!response.ok) {
          throw new Error(`User delete failed: ${response.status}`);
        }
        const payload = await response.json();
        renderUsers(payload.users || []);
        clearEditUser();
        usersStatus.textContent = "User deleted.";
      } catch (error) {
        usersStatus.textContent = "Could not delete user.";
      }
    });

    actions.appendChild(editBtn);
    actions.appendChild(deleteBtn);
    li.appendChild(details);
    li.appendChild(actions);
    usersList.appendChild(li);
  }
}

async function loadUsers() {
  try {
    const response = await fetch("/api/users");
    if (!response.ok) {
      throw new Error(`Users load failed: ${response.status}`);
    }
    const payload = await response.json();
    renderUsers(payload.users || []);
  } catch (error) {
    usersStatus.textContent = "Could not load users.";
  }
}

async function saveEditUser() {
  const username = editUserName.value.trim();
  if (!username) {
    usersStatus.textContent = "Username required.";
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

  usersStatus.textContent = "Saving...";
  try {
    const response = await fetch("/api/users", {
      method: "POST",
      headers: withCsrfHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify(payload)
    });
    if (!response.ok) {
      throw new Error(`User save failed: ${response.status}`);
    }
    const result = await response.json();
    renderUsers(result.users || []);
    clearEditUser();
    usersStatus.textContent = "User saved.";
  } catch (error) {
    usersStatus.textContent = "Could not save user.";
  }
}

saveEditUserBtn.addEventListener("click", saveEditUser);
cancelEditUserBtn.addEventListener("click", () => {
  clearEditUser();
  usersStatus.textContent = "Edit cancelled.";
});
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

clearEditUser();
loadUsers();
