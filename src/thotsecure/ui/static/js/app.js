/* Thot Secure — comportements de la console embarquée.
   Zéro dépendance : pas de CDN, pas de framework, utilisable en réseau cloisonné. */
(function () {
  "use strict";

  /* --- Confirmation avant toute opération sensible ------------------------------- */
  document.addEventListener("submit", function (event) {
    var form = event.target;
    if (!form || !form.dataset || !form.dataset.confirm) return;
    if (!window.confirm(form.dataset.confirm)) {
      event.preventDefault();
    }
  });

  /* --- Copie des adresses de don -------------------------------------------------- */
  document.addEventListener("click", function (event) {
    var target = event.target;
    if (!target || !target.dataset || !target.dataset.copy) return;
    var value = target.dataset.copy;
    var notice = function (text) {
      var original = target.textContent;
      target.textContent = text;
      setTimeout(function () { target.textContent = original; }, 1600);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(value).then(
        function () { notice("Copié ✓"); },
        function () { notice("Copie impossible"); }
      );
    } else {
      var area = document.createElement("textarea");
      area.value = value;
      document.body.appendChild(area);
      area.select();
      try { document.execCommand("copy"); notice("Copié ✓"); }
      catch (error) { notice("Copie impossible"); }
      document.body.removeChild(area);
    }
  });

  /* --- Flux temps réel ------------------------------------------------------------ */
  var feed = document.getElementById("live-feed");
  var status = document.getElementById("live-status");
  if (!feed) return;

  var tenantId = feed.dataset.tenant || "";
  var maxLines = 200;
  var reconnectDelay = 1000;
  var socket = null;
  var closedByPage = false;

  function setStatus(text, cssClass) {
    if (!status) return;
    status.textContent = text;
    status.className = "pill " + (cssClass || "");
  }

  function appendLine(kind, text, cssClass) {
    var line = document.createElement("div");
    line.className = "live-line";
    var time = document.createElement("time");
    time.textContent = new Date().toLocaleTimeString();
    var label = document.createElement("span");
    label.className = "kind";
    label.textContent = kind;
    var body = document.createElement("span");
    if (cssClass) body.className = cssClass;
    /* textContent (jamais innerHTML) : les charges utiles contiennent des attaques. */
    body.textContent = text;
    line.appendChild(time);
    line.appendChild(label);
    line.appendChild(body);
    feed.insertBefore(line, feed.firstChild);
    while (feed.childElementCount > maxLines) {
      feed.removeChild(feed.lastChild);
    }
  }

  function describe(frame) {
    var data = frame.data || {};
    if (frame.type === "event") {
      return [data.kind || "événement", " " + (data.src_ip || "") + " " + (data.path || data.check || "")].join("");
    }
    if (frame.type === "finding") {
      return "[" + (data.severity || "") + "] " + (data.risk_score || "") + " " + (data.title || "");
    }
    if (frame.type === "action") {
      return (data.playbook || "") + " → " + (data.status || "") + " " + (data.target || "");
    }
    if (frame.type === "audit") {
      return (data.actor || "") + " " + (data.action || "");
    }
    return JSON.stringify(data);
  }

  function connect() {
    fetch("/ui/ws-token", { credentials: "same-origin" })
      .then(function (response) {
        if (!response.ok) throw new Error("jeton indisponible");
        return response.json();
      })
      .then(function (payload) {
        var scheme = window.location.protocol === "https:" ? "wss" : "ws";
        var url = scheme + "://" + window.location.host + "/api/v1/ws/stream"
          + "?token=" + encodeURIComponent(payload.token)
          + "&tenant_id=" + encodeURIComponent(tenantId);
        socket = new WebSocket(url);

        socket.onopen = function () {
          reconnectDelay = 1000;
          setStatus("connecté", "pill-ok");
        };
        socket.onmessage = function (message) {
          var frame;
          try { frame = JSON.parse(message.data); } catch (error) { return; }
          if (frame.type === "hello") {
            appendLine("session", "flux ouvert (" + (frame.data.role || "") + ")", "muted");
            return;
          }
          if (frame.type === "heartbeat") return;
          var cssClass = frame.type === "finding" && frame.data && frame.data.severity === "critical"
            ? "sev-critical" : "";
          appendLine(frame.type, describe(frame), cssClass);
        };
        socket.onclose = function () {
          if (closedByPage) return;
          setStatus("reconnexion…", "pill-warn");
          setTimeout(connect, reconnectDelay);
          reconnectDelay = Math.min(reconnectDelay * 2, 30000);
        };
        socket.onerror = function () {
          setStatus("erreur de flux", "pill-bad");
        };
      })
      .catch(function () {
        setStatus("flux indisponible", "pill-bad");
        setTimeout(connect, reconnectDelay);
        reconnectDelay = Math.min(reconnectDelay * 2, 30000);
      });
  }

  window.addEventListener("beforeunload", function () {
    closedByPage = true;
    if (socket) socket.close();
  });

  connect();
})();
