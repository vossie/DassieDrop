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
let selectedUserIds = new Set();

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
  option.value = user.id;
  option.textContent = `${user.username} (${user.role})${isOwner ? " - owner" : ""}`;
  option.disabled = isOwner;
  return option;
}

function selectableUsers() {
  return users.filter((user) => user.id);
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
    const isOwner = user.id === workspace.owner_user_id;
    const target = selectedUserIds.has(user.id) ? hasAccessUsers : noAccessUsers;
    target.appendChild(optionForUser(user, isOwner));
  }
}

function moveSelected(fromSelect, hasAccess) {
  for (const option of Array.from(fromSelect.selectedOptions)) {
    if (hasAccess) {
      selectedUserIds.add(option.value);
    } else {
      selectedUserIds.delete(option.value);
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
    selectedUserIds = new Set(workspace.explicit_user_ids || []);
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
      body: JSON.stringify({ user_ids: Array.from(selectedUserIds) })
    });
    if (!response.ok) {
      throw new Error(`Workspace access save failed: ${response.status}`);
    }
    const payload = await response.json();
    workspace = payload.workspace;
    selectedUserIds = new Set(workspace.explicit_user_ids || []);
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
