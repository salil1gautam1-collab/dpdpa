/* TrackVault front-end niceties. Served as a static file because the CSP
   (script-src 'self') rightly blocks inline scripts. Everything here is
   progressive enhancement — the app is fully functional without it. */
(function () {
  "use strict";

  var reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* Live-panel sweep: highlight assessment rows in sequence, like a scan. */
  var rows = document.querySelectorAll(".ops-row");
  if (rows.length && !reduced) {
    var i = 0;
    setInterval(function () {
      rows.forEach(function (r) { r.classList.remove("scanning"); });
      rows[i % rows.length].classList.add("scanning");
      i++;
    }, 1500);
  }

  /* Scroll-reveal: .reveal elements rise in as they enter the viewport. */
  var els = document.querySelectorAll(".reveal");
  if (!els.length) return;
  if (!("IntersectionObserver" in window) || reduced) {
    els.forEach(function (e) { e.classList.add("in"); });
    return;
  }
  var io = new IntersectionObserver(function (entries) {
    entries.forEach(function (en) {
      if (en.isIntersecting) { en.target.classList.add("in"); io.unobserve(en.target); }
    });
  }, { threshold: 0.12, rootMargin: "0px 0px -40px 0px" });
  els.forEach(function (e) { io.observe(e); });

  /* Safety net: never leave content hidden if the observer can't run. */
  setTimeout(function () {
    els.forEach(function (e) { e.classList.add("in"); });
  }, 1600);
})();
