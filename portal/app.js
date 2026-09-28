const form = document.getElementById("login-form");
const status = document.getElementById("status");
const mfaField = document.getElementById("mfa-field");
const useMfa = form.elements.namedItem("use_mfa");

useMfa.addEventListener("change", () => {
  mfaField.classList.toggle("hidden", !useMfa.checked);
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  status.className = "status";
  status.textContent = "Signing in…";
  const body = {
    username: form.username.value.trim(),
    password: form.password.value,
    country: form.country.value,
    use_mfa: Boolean(useMfa.checked),
    mfa_code: form.mfa_code.value.trim() || null,
  };
  try {
    const response = await fetch("/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(body),
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.detail || `Request failed (${response.status})`);
    }
    status.className = data.ok ? "status ok" : "status err";
    status.textContent = `${data.message} Event #${data.event_id}.`;
    if (data.ok) {
      form.password.value = "";
      form.mfa_code.value = "";
    }
  } catch (error) {
    status.className = "status err";
    status.textContent = error.message;
  }
});
