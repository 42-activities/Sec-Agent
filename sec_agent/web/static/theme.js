/* Theme: "auto" follows the OS; the header toggle can force light or dark (remembered per browser).
   Loaded synchronously in <head> so the page never flashes the wrong theme. */
(function () {
  var KEY = "sec-agent-theme", root = document.documentElement, ORDER = ["auto", "light", "dark"];
  var LABEL = { auto: "Auto", light: "Light", dark: "Dark" };
  var current = "auto";
  try { current = localStorage.getItem(KEY) || "auto"; } catch (e) {}
  if (ORDER.indexOf(current) < 0) current = "auto";

  function apply() {
    if (current === "auto") root.removeAttribute("data-theme");
    else root.setAttribute("data-theme", current);
  }
  apply();

  document.addEventListener("DOMContentLoaded", function () {
    var nav = document.querySelector("header nav");
    if (!nav) return;
    var btn = document.createElement("button");
    btn.type = "button";
    btn.className = "theme-toggle";
    function render() {
      btn.textContent = "Theme: " + LABEL[current];
      btn.setAttribute("aria-label", "Color theme: " + LABEL[current] + ". Click to change.");
    }
    btn.addEventListener("click", function () {
      current = ORDER[(ORDER.indexOf(current) + 1) % ORDER.length];
      try { current === "auto" ? localStorage.removeItem(KEY) : localStorage.setItem(KEY, current); } catch (e) {}
      apply();
      render();
    });
    render();
    nav.appendChild(btn);
  });
})();
