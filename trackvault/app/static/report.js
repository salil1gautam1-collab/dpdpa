/* Print button for the report / gap-assessment documents.
   Lives in a static file because the CSP (script-src 'self') blocks inline
   onclick handlers — the button is inert without this. */
(function () {
  "use strict";
  var btn = document.getElementById("printBtn");
  if (btn) {
    btn.addEventListener("click", function () { window.print(); });
  }
})();
