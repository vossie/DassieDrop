const csrfMeta = document.querySelector('meta[name="dassiedrop-csrf-token"]');
const csrfToken = (csrfMeta && csrfMeta.content) || "";
const usersStatus = document.getElementById("usersStatus");
const usersList = document.getElementById("usersList");
const usersToolbar = document.getElementById("usersToolbar");
let canManageUsers = false;

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
  usersToolbar.classList.toggle("user-self-hidden", !canManageUsers);
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

    const editLink = document.createElement("a");
    editLink.className = "workspace-cancel-btn button-link";
    editLink.href = `/users/edit?id=${encodeURIComponent(user.id)}`;
    editLink.textContent = "Edit";

    actions.appendChild(editLink);
    if (canManageUsers) {
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
          canManageUsers = Boolean(payload.can_manage_users);
          renderUsers(payload.users || []);
          usersStatus.textContent = "User deleted.";
        } catch (error) {
          usersStatus.textContent = "Could not delete user.";
        }
      });
      actions.appendChild(deleteBtn);
    }
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
    canManageUsers = Boolean(payload.can_manage_users);
    renderUsers(payload.users || []);
  } catch (error) {
    usersStatus.textContent = "Could not load users.";
  }
}

loadUsers();
