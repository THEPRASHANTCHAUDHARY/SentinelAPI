(() => {
  const base = (window.SENTINEL_API_URL || "http://127.0.0.1:8000").replace(/\/$/, "");
  async function request(path, options = {}) {
    let response;
    try {
      response = await fetch(base + path, {
        ...options,
        credentials: "include",
        headers: { "Content-Type": "application/json", ...(options.headers || {}) }
      });
    } catch {
      throw new Error("SentinelAPI is unavailable. Start the local backend and retry.");
    }
    let data;
    try { data = await response.json(); }
    catch { throw new Error("SentinelAPI returned an invalid response."); }
    if (!response.ok) {
      const detail = data.detail;
      throw new Error(typeof detail === "string" ? detail : "Check your details and try again.");
    }
    return data;
  }

  const auth = {
    signUp: data => request("/api/auth/signup", { method: "POST", body: JSON.stringify(data) }),
    signIn: data => request("/api/auth/signin", { method: "POST", body: JSON.stringify(data) }),
    signOut: () => request("/api/auth/logout", { method: "POST", body: "{}" }),
    async getCurrentUser() {
      const result = await request("/api/auth/me");
      return result.authenticated ? result.user : null;
    },
    async requireAuth() {
      try {
        const user = await this.getCurrentUser();
        if (user) return user;
      } catch { /* The sign-in page will show the service error. */ }
      const page = location.pathname.split("/").pop() || "scan-your-api.html";
      location.assign("signin.html?next=" + encodeURIComponent(page));
      return null;
    }
  };
  window.SentinelAuth = auth;

  function addLink(nav, text, href, attributes = {}) {
    const link = document.createElement("a");
    link.textContent = text;
    link.href = href;
    link.dataset.authGenerated = "true";
    Object.entries(attributes).forEach(([key, value]) => link.setAttribute(key, value));
    nav.append(link);
    return link;
  }

  function updateCurrentPageNavigation(nav, user) {
    const page = location.pathname.split("/").pop() || "main.html";
    const route = page === "see-security-workflow.html" ? "how-it-works.html" : page;
    nav.querySelectorAll("a").forEach(link => link.classList.remove("active"));
    const activeLink = [...nav.querySelectorAll("a")].find(link => {
      if (route === "scan-your-api.html" && !user) return false;
      try { return new URL(link.href, location.href).pathname.split("/").pop() === route; }
      catch { return false; }
    });
    if (activeLink) activeLink.classList.add("active");
  }

  async function updateNavigation() {
    const nav = document.querySelector(".nav-links");
    if (!nav) return;
    nav.querySelectorAll("[data-auth-generated]").forEach(link => link.remove());
    const page = location.pathname.split("/").pop() || "main.html";
    if (page === "signin.html" || page === "signup.html") {
      nav.querySelectorAll("a").forEach(link => link.classList.remove("active"));
      return;
    }
    const cta = document.querySelector(".nav-cta");
    let user = null;
    try { user = await auth.getCurrentUser(); } catch { user = null; }
    if (!user) {
      addLink(nav, "Sign In", "signin.html");
      addLink(nav, "Sign Up", "signup.html");
      if (cta) cta.textContent = "Start scanning \u2197";
      updateCurrentPageNavigation(nav, null);
      return;
    }
    const account = addLink(nav, user.name, "scan-your-api.html", { title: user.email, "aria-label": user.name + " - " + user.email });
    account.dataset.authUser = "true";
    const logout = addLink(nav, "Log Out", "main.html", { "aria-label": "Log out" });
    logout.dataset.authLogout = "true";
    if (cta) cta.textContent = "Scan your API \u2197";
    updateCurrentPageNavigation(nav, user);
  }

  function showMessage(form, message, isError = true) {
    const box = form.querySelector("[data-auth-message]");
    if (!box) return;
    box.textContent = message;
    box.hidden = !message;
    box.dataset.kind = isError ? "error" : "success";
  }

  function safeNext() {
    const requested = new URLSearchParams(location.search).get("next") || "scan-your-api.html";
    const allowed = new Set([
      "main.html", "scanner.html", "capabilities.html", "how-it-works.html",
      "scan-your-api.html", "see-security-workflow.html"
    ]);
    return allowed.has(requested.split("?")[0].split("#")[0]) ? requested : "scan-your-api.html";
  }

  document.querySelectorAll("[data-auth-form]").forEach(form => {
    form.addEventListener("submit", async event => {
      event.preventDefault();
      const submit = form.querySelector("[type=submit]");
      if (!form.reportValidity()) return;
      const formType = form.dataset.authForm;
      const values = Object.fromEntries(new FormData(form).entries());
      showMessage(form, "");
      if (submit) { submit.disabled = true; submit.dataset.originalText = submit.textContent; submit.textContent = "PLEASE WAIT"; }
      try {
        if (formType === "signup") {
          await auth.signUp({
            name: values.name,
            email: values.email,
            password: values.password,
            confirm_password: values.confirm_password
          });
          form.reset();
          showMessage(form, "Account created. Sign in to continue.", false);
        } else {
          await auth.signIn({ email: values.email, password: values.password });
          location.replace(safeNext());
        }
      } catch (error) {
        showMessage(form, error.message || "Unable to complete that request.");
      } finally {
        if (submit) { submit.disabled = false; submit.textContent = submit.dataset.originalText || submit.textContent; }
      }
    });
  });

  document.addEventListener("click", async event => {
    const logout = event.target.closest("[data-auth-logout]");
    if (!logout) return;
    event.preventDefault();
    logout.textContent = "Signing out";
    logout.removeAttribute("data-auth-logout");
    try {
      await auth.signOut();
      location.assign("main.html");
    } catch (error) {
      logout.textContent = "Log Out";
      logout.dataset.authLogout = "true";
      window.alert(error.message || "Unable to log out. Try again.");
    }
  });

  updateNavigation();
  const registered = new URLSearchParams(location.search).has("registered");
  if (registered) {
    const form = document.querySelector('[data-auth-form="signin"]');
    if (form) showMessage(form, "Account created. Sign in to continue.", false);
  }
})();