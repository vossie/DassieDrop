const loginUsername = document.getElementById("loginUsername");
const loginPassword = document.getElementById("loginPassword");
const loginTotpCode = document.getElementById("loginTotpCode");
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
  const payload = { username: loginUsername.value, password: loginPassword.value };
  if (!loginTotpCode.hidden) {
    payload.totp_code = loginTotpCode.value.trim();
  }
  try {
    const response = await fetch("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    if (!response.ok) {
      const text = await response.text();
      if (text.includes("Authenticator code required")) {
        loginTotpCode.hidden = false;
        loginTotpCode.focus();
        loginStatus.textContent = "Enter your authenticator code.";
        return;
      }
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
    if (loginTotpCode.hidden) {
      login();
    } else {
      loginTotpCode.focus();
    }
  }
});
loginTotpCode.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    login();
  }
});
loginTotpCode.addEventListener("input", () => {
  loginTotpCode.value = loginTotpCode.value.replace(/\D/g, "").slice(0, 6);
  if (loginTotpCode.value.length === 6) {
    login();
  }
});

loadRememberedUsername();
