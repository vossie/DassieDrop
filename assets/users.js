const csrfMeta = document.querySelector('meta[name="dassiedrop-csrf-token"]');
const csrfToken = (csrfMeta && csrfMeta.content) || "";
const userName = document.getElementById("userName");
const userPassword = document.getElementById("userPassword");
const userApiKey = document.getElementById("userApiKey");
const userRole = document.getElementById("userRole");
const saveUserBtn = document.getElementById("saveUserBtn");
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
    editBtn.addEventListener("click", () => {
      userName.value = user.username;
      userPassword.value = "";
      userApiKey.value = "";
      userRole.value = user.role;
      userName.focus();
      usersStatus.textContent = "Editing user. Leave password or API key blank to keep the stored value.";
    });

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

async function saveUser() {
  const username = userName.value.trim();
  if (!username) {
    usersStatus.textContent = "Username required.";
    userName.focus();
    return;
  }

  const payload = {
    username,
    role: userRole.value
  };
  if (userPassword.value) {
    payload.password = userPassword.value;
  }
  if (userApiKey.value) {
    payload.api_key = userApiKey.value;
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
    userName.value = "";
    userPassword.value = "";
    userApiKey.value = "";
    userRole.value = "user";
    renderUsers(result.users || []);
    usersStatus.textContent = "User saved.";
  } catch (error) {
    usersStatus.textContent = "Could not save user.";
  }
}

saveUserBtn.addEventListener("click", saveUser);
userName.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    saveUser();
  }
});
userPassword.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    saveUser();
  }
});
userApiKey.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    saveUser();
  }
});

loadUsers();
