/* Cup O' Cheese shared scripts (served with a content-hash ?v=, cached 1 year). */
/* 30-second clip cap: shared recorder timer + chosen-file duration check. */
window.CocClip = (function () {
  var LIMIT = 30, FILE_SLACK = 0.5;
  var TOO_LONG = "Whoa, that's a long one! Keep it under 30 seconds.";
  function fmt(s) { s = Math.max(0, Math.floor(s)); return Math.floor(s / 60) + ":" + ("0" + (s % 60)).slice(-2); }
  function startTimer(onTick, onLimit) {
    var t0 = Date.now(), fired = false;
    onTick(0, fmt(0) + " / " + fmt(LIMIT));
    var id = setInterval(function () {
      var el = (Date.now() - t0) / 1000;
      if (el >= LIMIT) {
        el = LIMIT;
        if (!fired) { fired = true; clearInterval(id); onTick(el, fmt(el) + " / " + fmt(LIMIT)); onLimit(); return; }
      }
      onTick(el, fmt(el) + " / " + fmt(LIMIT));
    }, 200);
    return { stop: function () { clearInterval(id); return Math.min(LIMIT, (Date.now() - t0) / 1000); } };
  }
  /* cb(ok, seconds|null). Unknown duration (e.g. some webm) is allowed; the server double-checks. */
  function checkFile(file, cb) {
    if (!file) { cb(true, null); return; }
    var url = URL.createObjectURL(file), a = new Audio(), done = false;
    function finish(ok, d) { if (done) return; done = true; URL.revokeObjectURL(url); cb(ok, d); }
    a.preload = "metadata";
    a.addEventListener("loadedmetadata", function () {
      var d = a.duration;
      if (!isFinite(d) || isNaN(d) || d <= 0) { finish(true, null); return; }
      finish(d <= LIMIT + FILE_SLACK, d);
    });
    a.addEventListener("error", function () { finish(true, null); });
    setTimeout(function () { finish(true, null); }, 8000);
    a.src = url;
  }
  return { LIMIT: LIMIT, TOO_LONG: TOO_LONG, fmt: fmt, startTimer: startTimer, checkFile: checkFile };
})();

(function () {
  document.addEventListener("click", function (e) {
    var btn = e.target.closest(".post-menu-btn");
    var menus = document.querySelectorAll(".post-menu.open");
    if (btn) {
      e.preventDefault();
      e.stopPropagation();
      var menu = btn.closest(".post-menu");
      var wasOpen = menu.classList.contains("open");
      menus.forEach(function (m) {
        m.classList.remove("open");
        var b = m.querySelector(".post-menu-btn");
        if (b) b.setAttribute("aria-expanded", "false");
      });
      if (!wasOpen) {
        menu.classList.add("open");
        btn.setAttribute("aria-expanded", "true");
      }
      return;
    }
    if (!e.target.closest(".post-menu")) {
      menus.forEach(function (m) {
        m.classList.remove("open");
        var b = m.querySelector(".post-menu-btn");
        if (b) b.setAttribute("aria-expanded", "false");
      });
    }
  });
})();

(function () {
  document.addEventListener("submit", function (e) {
    var form = e.target;
    if (!form.classList || !form.classList.contains("reaction-bar")) return;
    var btn = e.submitter;
    if (!btn || !btn.value || !window.fetch) return; /* fall back to normal POST */
    e.preventDefault();
    var fd = new FormData();
    fd.append("emoji", btn.value);
    form.classList.add("rx-busy");
    fetch(form.action, { method: "POST", body: fd, credentials: "same-origin",
                         headers: { "X-Requested-With": "fetch", "Accept": "application/json" } })
      .then(function (r) { if (r.status === 401) { window.location.href = "/login"; throw 0; } return r.json(); })
      .then(function (d) {
        if (!d || !d.ok) throw 0;
        if (d.self_reacted) {
          var key = form.action.match(/\/react\/(post|board)\/(\d+)/);
          if (key) document.querySelectorAll('[data-geek="' + key[1] + ':' + key[2] + '"]').forEach(function (el) {
            el.classList.add("self-reacted");
            if (el.querySelector(".geek-badge")) return;
            var b = document.createElement("div");
            b.className = "geek-badge";
            b.innerHTML = '<span aria-hidden="true">🤓</span> I liked my own squeak, I must be a geek!';
            var anchor = el.querySelector(".post-card-head, .squeak-meta");
            if (anchor) anchor.parentNode.insertBefore(b, anchor); else el.insertBefore(b, el.firstChild);
          });
        }
        var tmp = document.createElement("div");
        tmp.innerHTML = d.html;
        var fresh = tmp.firstElementChild;
        if (fresh) form.replaceWith(fresh); else form.classList.remove("rx-busy");
      })
      .catch(function () { form.classList.remove("rx-busy"); });
  });
  /* who-reacted sheet */
  function closeWho() { var b = document.querySelector(".who-backdrop"); if (b) b.remove(); }
  document.addEventListener("keydown", function (e) { if (e.key === "Escape") closeWho(); });
  document.addEventListener("click", function (e) {
    var t = e.target.closest ? e.target.closest(".rx-who") : null;
    if (t) {
      e.preventDefault();
      fetch(t.getAttribute("data-who"), { credentials: "same-origin", headers: { "Accept": "application/json" } })
        .then(function (r) { if (r.status === 401) { window.location.href = "/login"; throw 0; } return r.json(); })
        .then(function (d) {
          if (!d || !d.ok) return;
          closeWho();
          var bd = document.createElement("div"); bd.className = "who-backdrop";
          var sh = document.createElement("div"); sh.className = "who-sheet";
          sh.setAttribute("role", "dialog"); sh.setAttribute("aria-label", "Who reacted");
          sh.innerHTML = d.html; bd.appendChild(sh); document.body.appendChild(bd);
          bd.addEventListener("click", function (ev) { if (ev.target === bd || ev.target.closest(".who-close")) closeWho(); });
        }).catch(function () {});
      return;
    }
  });
  /* close open pickers when clicking elsewhere */
  document.addEventListener("click", function (e) {
    document.querySelectorAll(".rx-picker[open]").forEach(function (d) {
      if (!d.contains(e.target)) d.removeAttribute("open");
    });
  });
})();

if ("serviceWorker" in navigator) {
  window.addEventListener("load", function () {
    navigator.serviceWorker.register("/sw.js", { scope: "/" }).catch(function () {});
  });
}
