const csrfMeta = document.querySelector('meta[name="dassiedrop-csrf-token"]');
const workspaceMeta = document.querySelector('meta[name="dassiedrop-workspace-id"]');
const csrfToken = (csrfMeta && csrfMeta.content) || "";
const workspaceId = (workspaceMeta && workspaceMeta.content) || "";
const workspaceOpenPassword = document.getElementById("workspaceOpenPassword");
const openWorkspaceBtn = document.getElementById("openWorkspaceBtn");
const workspaceOpenStatus = document.getElementById("workspaceOpenStatus");

function withCsrfHeaders(headers = {}) {
  if (!csrfToken) {
    return headers;
  }
  return { ...headers, "X-CSRF-Token": csrfToken };
}

function setWorkspaceOpenStatus(message) {
  workspaceOpenStatus.textContent = message;
}

async function openWorkspace() {
  const password = workspaceOpenPassword.value;
  if (!password) {
    setWorkspaceOpenStatus("Workspace password required.");
    workspaceOpenPassword.focus();
    return;
  }
  try {
    const response = await fetch(`/api/workspaces/${encodeURIComponent(workspaceId)}/enter`, {
      method: "POST",
      headers: withCsrfHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ password })
    });
    if (!response.ok) {
      throw new Error(`Workspace open failed: ${response.status}`);
    }
    window.location.href = "/";
  } catch (error) {
    setWorkspaceOpenStatus("Wrong workspace password.");
  }
}

openWorkspaceBtn.addEventListener("click", openWorkspace);
workspaceOpenPassword.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    openWorkspace();
  }
});
workspaceOpenPassword.focus();
