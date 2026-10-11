/* Top navigation by mode. A block in the centre of the header lists the modes; hovering
   (or focusing, or tapping on a touch screen) a mode shows its pages. The page's own <nav>
   keeps only Rules (shared by every mode) and the theme toggle. Without JS the plain links
   in each page's <nav> still work. */
(function () {
  var MODES = [
    { key: "hr", label: "HR", pages: [
      ["/demo-hr", "Demo HR", "CV screening — Sec-Agent off vs on"],
      ["/hr-dashboard", "HR runs", "Every screening run and review decision"]] },
    { key: "general", label: "General", pages: [
      ["/", "Controller", "Run any scenario through Sec-Agent"],
      ["/soc", "SOC", "Security events and incidents"]] },
    { key: "batch", label: "Batch", pages: [
      ["/batch", "Batch", "Screen many prompts and measure accuracy"]] },
  ];
  var KEY = "sec-agent-mode";
  var path = location.pathname.replace(/\/+$/, "") || "/";
  var current = null;
  MODES.forEach(function (m) { m.pages.forEach(function (p) { if (p[0] === path) current = m.key; }); });
  try {
    if (current) localStorage.setItem(KEY, current);
    else current = localStorage.getItem(KEY);   // Rules / legal pages: show the mode you came from
  } catch (e) {}

  var header = document.querySelector("header"), nav = header && header.querySelector("nav");
  if (!nav) return;
  nav.querySelectorAll("a").forEach(function (a) { if (a.getAttribute("href") !== "/rules") a.remove(); });

  var box = document.createElement("div");
  box.className = "modes";
  box.setAttribute("role", "navigation");
  box.setAttribute("aria-label", "Modes");
  var cap = document.createElement("span");
  cap.className = "modes-cap";
  cap.textContent = "Mode";
  box.appendChild(cap);

  var touch = window.matchMedia && window.matchMedia("(hover: none)").matches;
  function closeAll(except) {
    box.querySelectorAll(".mode.open").forEach(function (m) {
      if (m !== except) { m.classList.remove("open"); m.firstChild.setAttribute("aria-expanded", "false"); }
    });
  }

  MODES.forEach(function (m) {
    var item = document.createElement("div");
    item.className = "mode" + (m.key === current ? " on" : "");
    var top = document.createElement("a");
    top.href = m.pages[0][0];
    top.className = "mode-btn";
    top.textContent = m.label;
    top.setAttribute("aria-haspopup", "true");
    top.setAttribute("aria-expanded", "false");
    if (m.key === current) top.setAttribute("aria-current", "true");
    var menu = document.createElement("div");
    menu.className = "mode-menu";
    m.pages.forEach(function (p) {
      var a = document.createElement("a");
      a.href = p[0];
      if (p[0] === path) { a.className = "on"; a.setAttribute("aria-current", "page"); }
      var b = document.createElement("b"); b.textContent = p[1];
      var s = document.createElement("small"); s.textContent = p[2];
      a.append(b, s);
      menu.appendChild(a);
    });
    // Touch screens have no hover: the first tap opens the menu, a tap on a page navigates.
    top.addEventListener("click", function (e) {
      if (touch && !item.classList.contains("open")) {
        e.preventDefault(); closeAll(item); item.classList.add("open"); top.setAttribute("aria-expanded", "true");
      }
    });
    item.addEventListener("mouseenter", function () { top.setAttribute("aria-expanded", "true"); });
    item.addEventListener("mouseleave", function () { top.setAttribute("aria-expanded", "false"); });
    item.append(top, menu);
    box.appendChild(item);
  });

  document.addEventListener("click", function (e) { if (!box.contains(e.target)) closeAll(); });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && box.contains(document.activeElement)) { closeAll(); document.activeElement.blur(); }
  });
  header.classList.add("has-modes");
  header.insertBefore(box, nav);
})();
