function updatePasswordToggle(button, input) {
  const showing = input.type === "text";
  button.setAttribute("aria-label", showing ? "Hide password" : "Show password");
  button.setAttribute("title", showing ? "Hide password" : "Show password");
  button.setAttribute("aria-pressed", showing ? "true" : "false");
}

function passwordInputForToggle(button) {
  const targetId = button.getAttribute("data-password-toggle");
  if (targetId) {
    return document.getElementById(targetId);
  }
  const wrapper = button.closest(".password-field-wrap");
  return wrapper ? wrapper.querySelector("input") : null;
}

document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-password-toggle]");
  if (!button) {
    return;
  }
  const input = passwordInputForToggle(button);
  if (!input) {
    return;
  }
  input.type = input.type === "password" ? "text" : "password";
  updatePasswordToggle(button, input);
  input.focus();
});

for (const button of document.querySelectorAll("[data-password-toggle]")) {
  const input = passwordInputForToggle(button);
  if (input) {
    updatePasswordToggle(button, input);
  }
}
