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
    if (message && !nativeConfirm(message)) event.preventDefault();
  });
})();
