const workspaceList = document.getElementById("workspaceList");
const workspaceStatus = document.getElementById("workspaceStatus");
const workspaceName = document.getElementById("workspaceName");
const workspaceAccessMode = document.getElementById("workspaceAccessMode");
const workspacePasswordWrap = document.getElementById("workspacePasswordWrap");
const workspacePassword = document.getElementById("workspacePassword");
const workspaceExpiry = document.getElementById("workspaceExpiry");
const workspaceMessageExpiry = document.getElementById("workspaceMessageExpiry");
const createWorkspaceBtn = document.getElementById("createWorkspaceBtn");
const requestedWorkspaceSlug = new URLSearchParams(window.location.search).get("workspace") || "";
const csrfMeta = document.querySelector('meta[name="dassiedrop-csrf-token"]');
const csrfToken = (csrfMeta && csrfMeta.content) || "";
let pendingWorkspaceAction = null;

function withCsrfHeaders(headers = {}) {
  if (!csrfToken) {
    return headers;
  }
  return { ...headers, "X-CSRF-Token": csrfToken };
}

window.addEventListener("pageshow", (event) => {
  if (event.persisted) {
    window.location.reload();
  }
});

function toggleWorkspacePassword() {
  const passwordMode = workspaceAccessMode.value === "password";
  workspacePasswordWrap.classList.toggle("visible", passwordMode);
  if (!passwordMode) {
    workspacePassword.value = "";
  }
}

function setWorkspaceStatus(message) {
  workspaceStatus.textContent = message;
}

function setPendingWorkspaceAction(workspaceId, action) {
  pendingWorkspaceAction = workspaceId && action ? { workspaceId, action } : null;
  loadWorkspaces();
}

function formatWorkspaceDate(ts) {
  if (!ts) {
    return "Just now";
  }
  return new Date(ts * 1000).toLocaleString();
}

function formatWorkspaceExpiry(seconds) {
  if (seconds === 0) {
    return "Never expires";
  }
  if (seconds % 86400 === 0) {
    const days = seconds / 86400;
    return `Expires after ${days} ${days === 1 ? "day" : "days"}`;
  }
  if (seconds % 3600 === 0) {
    const hours = seconds / 3600;
    return `Expires after ${hours} ${hours === 1 ? "hour" : "hours"}`;
  }
  return `Expires after ${seconds} seconds`;
}

function syncMessageExpiryOptions() {
  const workspaceSeconds = Number.parseInt(workspaceExpiry.value, 10);
  const messageSeconds = Number.parseInt(workspaceMessageExpiry.value, 10);
  let selectedStillAllowed = false;

  for (const option of workspaceMessageExpiry.options) {
    const optionSeconds = Number.parseInt(option.value, 10);
    const tooLong =
      Number.isInteger(workspaceSeconds) &&
      workspaceSeconds > 0 &&
      (optionSeconds === 0 || optionSeconds > workspaceSeconds);
    option.disabled = tooLong;
    if (!tooLong && option.value === workspaceMessageExpiry.value) {
      selectedStillAllowed = true;
    }
  }

  if (!selectedStillAllowed || (workspaceSeconds > 0 && messageSeconds > workspaceSeconds)) {
    workspaceMessageExpiry.value = workspaceExpiry.value;
  }
}

async function openWorkspace(workspace) {
  if (workspace.password_required) {
    setPendingWorkspaceAction(workspace.id, "enter");
    return;
  }
  try {
    const response = await fetch(`/api/workspaces/${encodeURIComponent(workspace.id)}/enter`, {
      method: "POST",
      headers: withCsrfHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ password: "" })
    });
    if (!response.ok) {
      throw new Error(`Workspace enter failed: ${response.status}`);
    }
    window.location.href = "/";
  } catch (error) {
    setWorkspaceStatus("Could not enter workspace.");
  }
}

async function loadWorkspaces() {
  try {
    const response = await fetch("/api/workspaces");
    if (!response.ok) {
      throw new Error(`Workspace load failed: ${response.status}`);
    }
    const payload = await response.json();
    renderWorkspaces(
      payload.workspaces || [],
      payload.current_workspace_id || null
    );
  } catch (error) {
    setWorkspaceStatus("Could not load workspaces.");
  }
}

function workspaceScopeLabel(workspace) {
  if (workspace.access_mode === "explicit") {
    return "Explicit users";
  }
  if (workspace.access_mode === "password" || workspace.password_required) {
    return "Password protected";
  }
  return "Public";
}

function renderWorkspaces(workspaces, currentWorkspaceId) {
  workspaceList.innerHTML = "";
  if (!workspaces.length) {
    const li = document.createElement("li");
    li.className = "muted";
    li.textContent = "No workspaces yet.";
    workspaceList.appendChild(li);
    return;
  }

  for (const workspace of workspaces) {
    const li = document.createElement("li");
    li.className = "history-item workspace-item";
    li.addEventListener("click", (event) => {
      if (event.target.closest("button, input, label, select, a")) {
        return;
      }
      openWorkspace(workspace);
    });

    const row = document.createElement("div");
    row.className = "workspace-row";

    const details = document.createElement("div");
    details.className = "workspace-details";

    const name = document.createElement("div");
    name.className = "file-name";
    name.textContent = workspace.name;

    const meta = document.createElement("div");
    meta.className = "meta workspace-meta";
    const scope = workspaceScopeLabel(workspace);
    const current = workspace.id === currentWorkspaceId ? " • Current selection" : "";
    meta.textContent = `${scope} - Workspace ${formatWorkspaceExpiry(workspace.expiry_seconds).toLowerCase()} - Messages ${formatWorkspaceExpiry(workspace.message_expiry_seconds).toLowerCase()} - Created ${formatWorkspaceDate(workspace.created_at)}${current}`;

    details.appendChild(name);
    details.appendChild(meta);

    const actions = document.createElement("div");
    actions.className = "file-card-actions";

    const enterBtn = document.createElement("button");
    enterBtn.type = "button";
    enterBtn.textContent = workspace.id === currentWorkspaceId ? "Open" : "Enter";
    enterBtn.addEventListener("click", async (event) => {
      event.stopPropagation();
      openWorkspace(workspace);
    });

    const deleteBtn = document.createElement("button");
    deleteBtn.type = "button";
    deleteBtn.className = "danger";
    deleteBtn.textContent = "Delete";
    deleteBtn.addEventListener("click", async (event) => {
      event.stopPropagation();
      if (workspace.password_required) {
        setPendingWorkspaceAction(workspace.id, "delete");
        return;
      }
      try {
        const response = await fetch(`/api/workspaces/${encodeURIComponent(workspace.id)}`, {
          method: "DELETE",
          headers: withCsrfHeaders({ "Content-Type": "application/json" }),
          body: JSON.stringify({ password: "" })
        });
        if (!response.ok) {
          throw new Error(`Workspace delete failed: ${response.status}`);
        }
        const payload = await response.json();
        pendingWorkspaceAction = null;
        renderWorkspaces(
          payload.workspaces || [],
          payload.current_workspace_id || null
        );
        setWorkspaceStatus("Workspace deleted.");
      } catch (error) {
        setWorkspaceStatus("Could not delete workspace.");
      }
    });

    actions.appendChild(enterBtn);
    if (workspace.id !== "default") {
      actions.appendChild(deleteBtn);
    }
    row.appendChild(details);
    row.appendChild(actions);
    li.appendChild(row);

    const requestedAction =
      !pendingWorkspaceAction &&
      requestedWorkspaceSlug &&
      workspace.slug === requestedWorkspaceSlug &&
      workspace.password_required
        ? "enter"
        : null;
    const actionToRender =
      pendingWorkspaceAction && pendingWorkspaceAction.workspaceId === workspace.id
        ? pendingWorkspaceAction.action
        : requestedAction;

    if (workspace.password_required && actionToRender) {
      const authRow = document.createElement("div");
      authRow.className = "workspace-auth-row";

      const authLabel = document.createElement("div");
      authLabel.className = "meta workspace-auth-label";
      authLabel.textContent =
        actionToRender === "delete"
          ? "Enter the workspace password or a root/admin user password to delete this workspace."
          : "Enter the workspace password or a root/admin user password to open this workspace.";

      const authInput = document.createElement("input");
      authInput.type = "password";
      authInput.className = "inline-input workspace-auth-input";
      authInput.placeholder = "Workspace password";
      authInput.autocomplete = "current-password";
      authInput.enterKeyHint = actionToRender === "delete" ? "done" : "go";

      const authInputWrap = document.createElement("div");
      authInputWrap.className = "password-field-wrap";
      const authToggle = document.createElement("button");
      authToggle.type = "button";
      authToggle.className = "password-toggle-btn";
      authToggle.setAttribute("data-password-toggle", "");
      authToggle.setAttribute("aria-label", "Show password");
      authToggle.setAttribute("title", "Show password");
      authToggle.setAttribute("aria-pressed", "false");
      const authToggleIcon = document.createElement("span");
      authToggleIcon.className = "password-eye-icon";
      authToggleIcon.setAttribute("aria-hidden", "true");
      authToggle.appendChild(authToggleIcon);
      authInputWrap.appendChild(authInput);
      authInputWrap.appendChild(authToggle);

      const submitBtn = document.createElement("button");
      submitBtn.type = "button";
      submitBtn.textContent = actionToRender === "delete" ? "Delete Now" : "Open";
      if (actionToRender === "delete") {
        submitBtn.className = "danger";
      }

      const cancelBtn = document.createElement("button");
      cancelBtn.type = "button";
      cancelBtn.className = "workspace-cancel-btn";
      cancelBtn.textContent = "Cancel";
      cancelBtn.addEventListener("click", () => {
        setPendingWorkspaceAction(null, null);
      });

      async function submitWorkspaceAction() {
        const action = pendingWorkspaceAction?.action;
        const password = authInput.value;
        if (!password) {
          setWorkspaceStatus("Workspace password required.");
          authInput.focus();
          return;
        }
        try {
          if (action === "delete") {
            const response = await fetch(`/api/workspaces/${encodeURIComponent(workspace.id)}`, {
              method: "DELETE",
              headers: withCsrfHeaders({ "Content-Type": "application/json" }),
              body: JSON.stringify({ password })
            });
            if (!response.ok) {
              throw new Error(`Workspace delete failed: ${response.status}`);
            }
            const payload = await response.json();
            pendingWorkspaceAction = null;
            renderWorkspaces(payload.workspaces || [], payload.current_workspace_id || null);
            setWorkspaceStatus("Workspace deleted.");
            return;
          }

          const response = await fetch(`/api/workspaces/${encodeURIComponent(workspace.id)}/enter`, {
            method: "POST",
            headers: withCsrfHeaders({ "Content-Type": "application/json" }),
            body: JSON.stringify({ password })
          });
          if (!response.ok) {
            throw new Error(`Workspace enter failed: ${response.status}`);
          }
          window.location.href = "/";
        } catch (error) {
          setWorkspaceStatus(
            action === "delete"
              ? "Could not delete workspace."
              : "Could not enter workspace."
          );
        }
      }

      submitBtn.addEventListener("click", submitWorkspaceAction);
      authInput.addEventListener("keydown", (event) => {
        if (event.key === "Enter") {
          submitWorkspaceAction();
        }
      });

      authRow.appendChild(authLabel);
      authRow.appendChild(authInputWrap);
      authRow.appendChild(submitBtn);
      authRow.appendChild(cancelBtn);
      li.appendChild(authRow);

      window.setTimeout(() => authInput.focus(), 0);
    }
    workspaceList.appendChild(li);
  }
}

async function createWorkspace() {
  const name = workspaceName.value.trim();
  if (!name) {
    setWorkspaceStatus("Workspace name required.");
    return;
  }
  const accessMode = workspaceAccessMode.value;
  const password = accessMode === "password" ? workspacePassword.value : "";
  const expirySeconds = Number.parseInt(workspaceExpiry.value, 10);
  const messageExpirySeconds = Number.parseInt(workspaceMessageExpiry.value, 10);
  if (!Number.isInteger(expirySeconds) || expirySeconds < 0) {
    setWorkspaceStatus("Workspace expiry invalid.");
    return;
  }
  if (!Number.isInteger(messageExpirySeconds) || messageExpirySeconds < 0) {
    setWorkspaceStatus("Message expiry invalid.");
    return;
  }
  if (expirySeconds > 0 && (messageExpirySeconds === 0 || messageExpirySeconds > expirySeconds)) {
    setWorkspaceStatus("Messages cannot expire after the workspace.");
    syncMessageExpiryOptions();
    return;
  }
  try {
    const response = await fetch("/api/workspaces", {
      method: "POST",
      headers: withCsrfHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({
        name,
        password,
        expiry_seconds: expirySeconds,
        message_expiry_seconds: messageExpirySeconds,
        access_mode: accessMode
      })
    });
    if (!response.ok) {
      throw new Error(`Workspace create failed: ${response.status}`);
    }
    workspaceName.value = "";
    workspaceExpiry.value = "86400";
    workspaceMessageExpiry.value = "86400";
    workspaceAccessMode.value = "public";
    workspacePassword.value = "";
    toggleWorkspacePassword();
    syncMessageExpiryOptions();
    const payload = await response.json();
    renderWorkspaces(
      payload.workspaces || [],
      payload.current_workspace_id || null
    );
    setWorkspaceStatus("Workspace created.");
  } catch (error) {
    setWorkspaceStatus("Could not create workspace.");
  }
}

workspaceAccessMode.addEventListener("change", toggleWorkspacePassword);
workspaceExpiry.addEventListener("change", syncMessageExpiryOptions);
createWorkspaceBtn.addEventListener("click", createWorkspace);
workspaceName.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    createWorkspace();
  }
});
workspacePassword.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    createWorkspace();
  }
});

toggleWorkspacePassword();
syncMessageExpiryOptions();
loadWorkspaces();
