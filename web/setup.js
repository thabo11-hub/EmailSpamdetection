// Step 1 of the setup: copies the app's code (embedded in the page at build time) to the clipboard.
// Nothing is sent anywhere: the page's security policy blocks every connection.
'use strict';
(function () {
  var btn = document.getElementById('copy');
  var code = document.getElementById('appcode');
  var msg = document.getElementById('copied');
  if (!btn || !code || !msg) return;

  function copied() {
    msg.textContent = 'Copied. Now do step 2.';
    msg.hidden = false;
    btn.textContent = 'Copied';
    setTimeout(function () { btn.textContent = 'Copy again'; }, 2500);
  }
  // Older browsers: select the code on the page and use the classic copy command.
  function fallback() {
    var box = document.getElementById('code');
    if (box) box.open = true;
    code.removeAttribute('readonly');
    code.focus();
    code.select();
    code.setSelectionRange(0, code.value.length);
    var ok = false;
    try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
    code.setAttribute('readonly', '');
    if (ok) { copied(); return; }
    msg.textContent = 'Your browser blocked the copy button. The code is selected below: tap Copy.';
    msg.hidden = false;
  }
  btn.addEventListener('click', function () {
    if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(code.value).then(copied, fallback);
    else fallback();
  });
})();
