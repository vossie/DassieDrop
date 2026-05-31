const loginUsername = document.getElementById("loginUsername");
const loginPassword = document.getElementById("loginPassword");
const loginBtn = document.getElementById("loginBtn");
const loginStatus = document.getElementById("loginStatus");
const rememberUsername = document.getElementById("rememberUsername");
const rememberedUsernameKey = "dassiedrop.rememberedUsername";

function loadRememberedUsername() {
  try {
    const rememberedUsername = window.localStorage.getItem(rememberedUsernameKey) || "";
    if (!rememberedUsername) {
      return;
    }
    loginUsername.value = rememberedUsername;
    rememberUsername.checked = true;
    loginPassword.focus();
  } catch (error) {
    // Browser storage can be disabled. Login still works without username recall.
  }
}

function updateRememberedUsername() {
  try {
    const username = loginUsername.value.trim();
    if (rememberUsername.checked && username) {
      window.localStorage.setItem(rememberedUsernameKey, username);
      return;
    }
    window.localStorage.removeItem(rememberedUsernameKey);
  } catch (error) {
    // Ignore local storage failures; credentials are submitted normally.
  }
}

async function login() {
  loginStatus.textContent = "Checking…";
  try {
    const response = await fetch("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: loginUsername.value, password: loginPassword.value })
    });
    if (!response.ok) {
      loginStatus.textContent = "Wrong username or password.";
      return;
    }
    updateRememberedUsername();
    window.location.href = "/?workspace_hint=1";
  } catch (error) {
    loginStatus.textContent = "Login failed.";
  }
}

loginBtn.addEventListener("click", login);
loginUsername.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    loginPassword.focus();
  }
});
loginPassword.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    login();
  }
});

loadRememberedUsername();
