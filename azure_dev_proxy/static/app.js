"use strict";

const api = "/:config";
const editable = document.documentElement.dataset.editable === "true";
const forwardOrigin = document.querySelector('meta[name="azure-dev-proxy-forward-origin"]').content;
let csrf = document.querySelector('meta[name="azure-dev-proxy-csrf"]').content;
const status = document.getElementById("status");

function message(text, error = false) {
  status.textContent = text;
  status.classList.toggle("error", error);
}

function rows(id, rules, actions = []) {
  const body = document.getElementById(id);
  body.replaceChildren();
  for (const rule of rules) {
    const row = document.createElement("tr");
    for (const text of [rule.host, rule.resource ?? "Destination HTTPS origin"]) {
      const cell = document.createElement("td");
      cell.textContent = text;
      row.append(cell);
    }
    if (actions.length) {
      const cell = document.createElement("td");
      for (const action of actions) {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "secondary";
        button.textContent = action.label;
        button.setAttribute("aria-label", `${action.label} for ${rule.host}`);
        button.addEventListener("click", () => save(action.method, {host: rule.host}, action.persisted));
        cell.append(button);
      }
      row.append(cell);
    }
    body.append(row);
  }
  if (!rules.length) {
    const row = body.insertRow();
    const cell = row.insertCell();
    cell.colSpan = actions.length ? 3 : 2;
    cell.textContent = "No rules configured.";
  }
}

function render(config) {
  const canPersist = editable && config.persistence_available;
  rows("base-rules", config.base_rules, canPersist
    ? [{label: "Delete persisted", method: "DELETE", persisted: true}] : []);
  const temporaryActions = editable ? [{label: "Remove temporary", method: "DELETE"}] : [];
  if (canPersist) temporaryActions.unshift({label: "Save to persisted", method: "POST", persisted: true});
  rows("overrides", config.overrides, temporaryActions);
  rows("effective-rules", config.effective_rules);
}

async function refresh() {
  // A socket-triggered restart changes the CSRF token; never retain a stale one.
  if (editable) {
    const page = await fetch("/", {cache: "no-store", credentials: "same-origin"});
    if (!page.ok) throw new Error("Could not refresh the local session.");
    const html = new DOMParser().parseFromString(await page.text(), "text/html");
    csrf = html.querySelector('meta[name="azure-dev-proxy-csrf"]').content;
  }
  const result = await fetch(api, {cache: "no-store", credentials: "same-origin"});
  if (!result.ok) throw new Error("Could not read host mappings.");
  render(await result.json());
}

async function save(method, value, persisted = false) {
  if (!editable) {
    location.assign(document.getElementById("edit-link").href);
    return;
  }
  try {
    await refresh();
    const result = await fetch(persisted ? `${api}/persisted` : api, {
      method,
      credentials: "same-origin",
      headers: {"Content-Type": "application/json", "X-Azure-Proxy-CSRF": csrf},
      body: JSON.stringify(value),
    });
    if (!result.ok) throw new Error((await result.text()).trim());
    render(await result.json());
    message(persisted
      ? "Persisted configuration saved to disk and applied."
      : "Temporary overrides updated. They disappear on process exit, including idle shutdown.");
  } catch (error) {
    message(error.message, true);
  }
}

document.getElementById("navigate").addEventListener("submit", (event) => {
  event.preventDefault();
  try {
    const raw = document.getElementById("destination").value.trim();
    const value = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`;
    const url = new URL(value);
    if (!/^https?:\/\//i.test(value) || !["http:", "https:"].includes(url.protocol) || url.username || url.password || raw.includes("\\")) {
      throw new Error("Enter an HTTP(S) URL without credentials or backslashes.");
    }
    location.assign(`${forwardOrigin}/${url.protocol}//${url.host}${url.pathname}${url.search}${url.hash}`);
  } catch (error) {
    message(error.message, true);
  }
});

document.getElementById("override").addEventListener("submit", (event) => {
  event.preventDefault();
  save("POST", {
    host: document.getElementById("hostname").value.trim(),
    resource: document.getElementById("resource").value.trim() || null,
  });
});

document.querySelector("details").addEventListener("toggle", async (event) => {
  if (!event.target.open) return;
  try {
    await refresh();
    message("");
  } catch (error) {
    message(error.message, true);
  }
});
