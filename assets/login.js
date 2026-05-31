const loginUsername = document.getElementById("loginUsername");
const loginPassword = document.getElementById("loginPassword");
const loginBtn = document.getElementById("loginBtn");
const loginStatus = document.getElementById("loginStatus");

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
