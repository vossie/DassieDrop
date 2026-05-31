const csrfMeta = document.querySelector('meta[name="dassiedrop-csrf-token"]');
const csrfToken = (csrfMeta && csrfMeta.content) || "";
const hasAccessUsers = document.getElementById("hasAccessUsers");
const noAccessUsers = document.getElementById("noAccessUsers");
const removeAccessBtn = document.getElementById("removeAccessBtn");
const addAccessBtn = document.getElementById("addAccessBtn");
const saveAccessBtn = document.getElementById("saveAccessBtn");
const workspacePasswordPanel = document.getElementById("workspacePasswordPanel");
const workspaceAccessPassword = document.getElementById("workspaceAccessPassword");
const saveWorkspacePasswordBtn = document.getElementById("saveWorkspacePasswordBtn");
const accessStatus = document.getElementById("accessStatus");
let workspace = null;
let users = [];
let selectedUsernames = new Set();

function withCsrfHeaders(headers = {}) {
  if (!csrfToken) {
    return headers;
  }
  return { ...headers, "X-CSRF-Token": csrfToken };
}

function setAccessStatus(message) {
  accessStatus.textContent = message;
}

function optionForUser(user, isOwner = false) {
  const option = document.createElement("option");
  option.value = user.username;
  option.textContent = `${user.username} (${user.role})${isOwner ? " - owner" : ""}`;
  option.disabled = isOwner;
  return option;
}

function selectableUsers() {
  return users.filter((user) => user.username);
}

function renderAccessLists() {
  hasAccessUsers.innerHTML = "";
  noAccessUsers.innerHTML = "";

  const explicitMode = workspace && workspace.access_mode === "explicit";
  document.querySelector(".access-manager").hidden = !explicitMode;
  saveAccessBtn.hidden = !explicitMode;
  workspacePasswordPanel.hidden = !(workspace && workspace.access_mode === "password");
  if (!explicitMode) {
    return;
  }

  for (const user of selectableUsers()) {
    const isOwner = user.username === workspace.owner_username;
    const target = selectedUsernames.has(user.username) ? hasAccessUsers : noAccessUsers;
    target.appendChild(optionForUser(user, isOwner));
  }
}

function moveSelected(fromSelect, hasAccess) {
  for (const option of Array.from(fromSelect.selectedOptions)) {
    if (hasAccess) {
      selectedUsernames.add(option.value);
    } else {
      selectedUsernames.delete(option.value);
    }
  }
  renderAccessLists();
}

async function loadAccess() {
  try {
    const response = await fetch("/api/workspaces/access");
    if (!response.ok) {
      throw new Error(`Workspace access load failed: ${response.status}`);
    }
    const payload = await response.json();
    workspace = payload.workspace;
    users = payload.users || [];
    selectedUsernames = new Set(workspace.explicit_usernames || []);
    renderAccessLists();
  } catch (error) {
    setAccessStatus("Could not load workspace access.");
  }
}

async function saveAccess() {
  if (!workspace) {
    return;
  }
  try {
    const response = await fetch(`/api/workspaces/${encodeURIComponent(workspace.id)}/users`, {
      method: "POST",
      headers: withCsrfHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ usernames: Array.from(selectedUsernames) })
    });
    if (!response.ok) {
      throw new Error(`Workspace access save failed: ${response.status}`);
    }
    const payload = await response.json();
    workspace = payload.workspace;
    selectedUsernames = new Set(workspace.explicit_usernames || []);
    renderAccessLists();
    setAccessStatus("Workspace access saved.");
  } catch (error) {
    setAccessStatus("Could not save workspace access.");
  }
}

async function saveWorkspacePassword() {
  if (!workspace) {
    return;
  }
  const password = workspaceAccessPassword.value.trim();
  if (!password) {
    setAccessStatus("Workspace password required.");
    return;
  }
  try {
    const response = await fetch(`/api/workspaces/${encodeURIComponent(workspace.id)}/password`, {
      method: "POST",
      headers: withCsrfHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ password })
    });
    if (!response.ok) {
      throw new Error(`Workspace password save failed: ${response.status}`);
    }
    const payload = await response.json();
    workspace = payload.workspace;
    workspaceAccessPassword.value = "";
    renderAccessLists();
    setAccessStatus("Workspace password saved.");
  } catch (error) {
    setAccessStatus("Could not save workspace password.");
  }
}

removeAccessBtn.addEventListener("click", () => moveSelected(hasAccessUsers, false));
addAccessBtn.addEventListener("click", () => moveSelected(noAccessUsers, true));
saveAccessBtn.addEventListener("click", saveAccess);
saveWorkspacePasswordBtn.addEventListener("click", saveWorkspacePassword);

loadAccess();
