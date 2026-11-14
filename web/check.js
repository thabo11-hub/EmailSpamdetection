// The public checker. Uses the same rules as the app (detect.js is src/Detect.gs, copied at build).
// Pasted text is only ever shown with textContent, so a pasted email cannot run code on this page.
(function () {
  'use strict';
  var LABELS = {
    dangerous: ['Dangerous', 'Do not click links, open attachments or reply. Delete it, or report it as phishing in Gmail.'],
    suspicious: ['Check first', 'Something here looks off. Contact the company through its own app or website, not through this email.'],
    clean: ['No warning signs found', 'That is not a guarantee. If it asks for passwords, PINs, OTPs or payment, check with the company directly.']
  };
  function el(tag, text, cls) { var e = document.createElement(tag); if (text) e.textContent = text; if (cls) e.className = cls; return e; }
  function val(id) { return String(document.getElementById(id).value || ''); }

  document.getElementById('form').addEventListener('submit', function (ev) {
    ev.preventDefault();
    var from = parseAddress_(val('from'));
    var m = {
      fromName: from.name, fromEmail: from.email, replyTo: parseAddress_(val('replyto')).email, subject: val('subject'),
      text: val('body').slice(0, 20000), html: '', auth: val('auth').slice(0, 5000),
      attachments: val('attachments').split(',').map(function (s) { return { name: s.trim() }; }).filter(function (a) { return a.name; }).slice(0, 20)
    };
    var r = scoreMessage_(m, {}, DEFAULT_SETTINGS);
    var out = document.getElementById('result');
    out.replaceChildren();
    out.appendChild(el('p', LABELS[r.level][0], 'verdict ' + r.level));
    out.appendChild(el('p', LABELS[r.level][1]));
    if (r.reasons.length) {
      out.appendChild(el('p', 'What we found:'));
      var ul = el('ul', '', 'reasons');
      r.reasons.slice(0, 12).forEach(function (why) { ul.appendChild(el('li', why)); });
      out.appendChild(ul);
    }
    if (!m.auth) out.appendChild(el('p', 'Tip: add the Authentication-Results line under "More checks" to tell whether the sender address is forged.', 'help'));
    out.classList.remove('hidden');
    out.scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
  document.getElementById('clear').addEventListener('click', function () {
    var out = document.getElementById('result');
    out.replaceChildren(); out.classList.add('hidden');
  });
}());
