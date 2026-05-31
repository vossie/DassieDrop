const csrfMeta = document.querySelector('meta[name="dassiedrop-csrf-token"]');
const csrfToken = (csrfMeta && csrfMeta.content) || "";
const newUserName = document.getElementById("newUserName");
const newUserPassword = document.getElementById("newUserPassword");
const newUserApiKey = document.getElementById("newUserApiKey");
const newUserRole = document.getElementById("newUserRole");
const createUserBtn = document.getElementById("createUserBtn");
const newUserStatus = document.getElementById("newUserStatus");

function withCsrfHeaders(headers = {}) {
  if (!csrfToken) {
    return headers;
  }
  return { ...headers, "X-CSRF-Token": csrfToken };
}

async function createUser() {
  const username = newUserName.value.trim();
  if (!username) {
    newUserStatus.textContent = "Username required.";
    newUserName.focus();
    return;
  }

  const payload = {
    username,
    role: newUserRole.value
  };
  if (newUserPassword.value) {
    payload.password = newUserPassword.value;
  }
  if (newUserApiKey.value) {
    payload.api_key = newUserApiKey.value;
  }

  newUserStatus.textContent = "Saving...";
  try {
    const response = await fetch("/api/users", {
      method: "POST",
      headers: withCsrfHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify(payload)
    });
    if (!response.ok) {
      throw new Error(`User save failed: ${response.status}`);
    }
    window.location.href = "/users";
  } catch (error) {
    newUserStatus.textContent = "Could not save user.";
  }
}

createUserBtn.addEventListener("click", createUser);
newUserName.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    createUser();
  }
});
newUserPassword.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    createUser();
  }
});
newUserApiKey.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    createUser();
  }
});
