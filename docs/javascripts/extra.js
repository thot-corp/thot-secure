/* =============================================================================
   Thot Secure — améliorations de la documentation (léger, sans dépendance)
   -----------------------------------------------------------------------------
   Ce script ne fait que quatre choses, et rien d'autre :

     1. Bannière d'annonce renvoyant vers la feuille de route (refermable).
        Elle s'affiche sous l'en-tête, jamais comme appel au don.
     2. Lien discret « Soutenir le projet » en pied de page (vers support.md).
     3. Durcissement des liens externes (rel="noopener noreferrer").
     4. Bouton de copie de secours si le thème n'expose pas `content.code.copy`.

   Choix de mise en œuvre : les URL des deux liens sont *reprises de la
   navigation* générée par MkDocs (donc relatives et toujours correctes, quelle
   que soit la profondeur de la page et la version du thème). Aucune URL n'est
   reconstruite à la main, et rien n'est injecté si la page cible est absente de
   la navigation : en cas de doute, le script ne fait rien plutôt que de casser.
   ============================================================================= */

(function () {
  "use strict";

  /* --- Réglages ------------------------------------------------------------ */

  var ANNOUNCEMENT = {
    // Texte de la bannière : à maintenir en cohérence avec docs/roadmap.md.
    text:
      "Feuille de route : PostgreSQL/TimescaleDB, ancrage externe de l'audit et connecteurs supplémentaires à l'étude.",
    linkLabel: "Feuille de route", // libellé exact de l'entrée de navigation
    storageKey: "thotsecure.announcement.roadmap.dismissed"
  };

  var SUPPORT = {
    label: "Soutenir le projet", // libellé exact de l'entrée de navigation
    prefix: "Soutenir le projet"
  };

  /* --- Utilitaires --------------------------------------------------------- */

  function ready(fn) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", fn);
    } else {
      fn();
    }
  }

  function readFlag(key) {
    try {
      return window.localStorage.getItem(key) === "1";
    } catch (e) {
      return false;
    }
  }

  function writeFlag(key) {
    try {
      window.localStorage.setItem(key, "1");
    } catch (e) {
      /* navigation privée ou stockage refusé : la bannière réapparaîtra */
    }
  }

  /* Retrouve le href d'une page cible dans la navigation déjà générée. */
  function findNavHref(label) {
    var links = document.querySelectorAll(".md-nav a[href], .md-tabs a[href], a.md-nav__link[href]");
    var i;
    for (i = 0; i < links.length; i++) {
      if ((links[i].textContent || "").trim() === label) {
        return links[i].getAttribute("href");
      }
    }
    return null;
  }

  /* --- 1. Bannière d'annonce ---------------------------------------------- */

  function addAnnouncement() {
    if (document.querySelector(".thotsecure-banner")) {
      return; // déjà présente (bannière native du thème ou injection précédente)
    }
    var header = document.querySelector(".md-header");
    if (!header || readFlag(ANNOUNCEMENT.storageKey)) {
      return;
    }

    var banner = document.createElement("div");
    banner.className = "thotsecure-banner md-banner";

    var inner = document.createElement("div");
    inner.className = "thotsecure-banner__inner";

    var text = document.createElement("span");
    text.appendChild(document.createTextNode(ANNOUNCEMENT.text + " "));
    inner.appendChild(text);

    var href = findNavHref(ANNOUNCEMENT.linkLabel);
    if (href) {
      var link = document.createElement("a");
      link.setAttribute("href", href);
      link.textContent = ANNOUNCEMENT.linkLabel;
      inner.appendChild(link);
    }

    var dismiss = document.createElement("button");
    dismiss.type = "button";
    dismiss.className = "thotsecure-banner__dismiss";
    dismiss.setAttribute("aria-label", "Masquer cette annonce");
    dismiss.title = "Masquer cette annonce";
    dismiss.appendChild(document.createTextNode("\u00d7"));
    dismiss.addEventListener("click", function () {
      writeFlag(ANNOUNCEMENT.storageKey);
      banner.parentNode.removeChild(banner);
    });
    inner.appendChild(dismiss);

    banner.appendChild(inner);
    header.parentNode.insertBefore(banner, header.nextSibling);
  }

  /* --- 2. Lien de pied de page « Soutenir le projet » --------------------- */

  function augmentFooter() {
    if (document.querySelector(".thotsecure-support")) {
      return; // déjà présent
    }
    var host = document.querySelector(".md-copyright") || document.querySelector(".md-footer-meta__inner");
    if (!host) {
      return;
    }
    var href = findNavHref(SUPPORT.label);
    if (!href) {
      return;
    }

    var wrap = document.createElement("div");
    wrap.className = "thotsecure-support";

    var link = document.createElement("a");
    link.setAttribute("href", href);
    link.textContent = SUPPORT.prefix + " (hébergement, certificats, audits)";
    wrap.appendChild(link);

    host.appendChild(wrap);
  }

  /* --- 3. Liens externes --------------------------------------------------- */

  function hardenExternalLinks() {
    var links = document.querySelectorAll("a[href^='http://'], a[href^='https://']");
    var i;
    for (i = 0; i < links.length; i++) {
      var link = links[i];
      if (link.hostname && link.hostname !== window.location.hostname) {
        link.setAttribute("target", "_blank");
        link.setAttribute("rel", "noopener noreferrer");
      }
    }
  }

  /* --- 4. Copie de code (repli) ------------------------------------------- */

  function addCopyFallback() {
    if (!navigator.clipboard || !document.querySelectorAll) {
      return;
    }
    var blocks = document.querySelectorAll(".md-typeset .highlight > pre");
    var i;
    for (i = 0; i < blocks.length; i++) {
      (function (pre) {
        var container = pre.parentNode;
        if (container.querySelector(".md-clipboard, .thotsecure-copy")) {
          return; // le thème fournit déjà son bouton
        }
        var button = document.createElement("button");
        button.type = "button";
        button.className = "thotsecure-copy";
        button.textContent = "Copier";
        button.addEventListener("click", function () {
          navigator.clipboard.writeText(pre.innerText || pre.textContent || "").then(
            function () {
              button.textContent = "Copié";
              window.setTimeout(function () {
                button.textContent = "Copier";
              }, 2000);
            },
            function () {
              button.textContent = "Échec";
            }
          );
        });
        container.appendChild(button);
      })(blocks[i]);
    }
  }

  /* --- Démarrage ----------------------------------------------------------- */

  ready(function () {
    addAnnouncement();
    augmentFooter();
    hardenExternalLinks();
    addCopyFallback();
  });
})();
