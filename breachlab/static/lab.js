// BreachLab's own script (not part of the Quillbook exercise).
(() => {
  const nativeConfirm = window.confirm.bind(window);

  // XSS detection: a payload that manages to call alert(), confirm() or prompt() proves that
  // script ran on the page. Tell the lab which page it happened on, then behave as usual.
  for (const name of ["alert", "confirm", "prompt"]) {
    const native = window[name].bind(window);
    window[name] = (...args) => {
      fetch("/lab/xss", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path: location.pathname }),
        keepalive: true,
      })
        .then((response) => response.json())
        .then((result) => result.captured && announce(result))
        .catch(() => {});
      return native(...args);
    };
  }

  function announce({ captured, flag, url }) {
    const element = (tag, properties) => Object.assign(document.createElement(tag), properties);
    const banner = element("p", { className: "flagbanner" });
    banner.append("Flag captured: ", element("strong", { textContent: captured }), " ");
    banner.append(element("code", { textContent: flag }), " ", element("a", { href: url, textContent: "Now fix it" }));
    document.getElementById("lab-announce")?.append(banner);
  }

  document.addEventListener("submit", (event) => {
    const message = event.submitter?.dataset.confirm;
    if (message && !nativeConfirm(message)) return event.preventDefault();
    // Slow checks (the race check takes a second): show that it is running and ignore a second click.
    const button = event.submitter;
    if (!button?.dataset.busy) return;
    if (button.getAttribute("aria-disabled") === "true") return event.preventDefault();
    button.dataset.idle = button.textContent;
    button.textContent = button.dataset.busy;
    button.setAttribute("aria-disabled", "true");
  });
  // Coming back with the Back button restores the page as it was left, busy label included.
  window.addEventListener("pageshow", () => {
    for (const button of document.querySelectorAll("[data-busy][aria-disabled]")) {
      button.textContent = button.dataset.idle;
      button.removeAttribute("aria-disabled");
    }
  });
})();
