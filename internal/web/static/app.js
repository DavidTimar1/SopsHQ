// SopsHQ panel - minimal progressive enhancement only. No framework, no deps.
(function () {
  "use strict";

  // ---- confirm destructive actions before submitting their form ----
  document.addEventListener("submit", function (e) {
    var form = e.target;
    if (form.classList && form.classList.contains("confirm")) {
      var msg = form.getAttribute("data-confirm") || "Are you sure?";
      if (!window.confirm(msg)) {
        e.preventDefault();
      }
    }
  });

  // ---- copy-to-clipboard buttons ----
  // A .copy-btn with data-copy-target="<id>" copies that element's <code> text
  // (joined by newlines when it holds several, e.g. all recovery codes), so the
  // operator can grab the 2FA key or every code at once. Purely client-side; it
  // reads the values already on the page and never sends them anywhere.
  //
  // The panel is reached over plain HTTP on a Tailscale address, which is not a
  // secure context, so navigator.clipboard is undefined there. When it is missing,
  // fall back to a hidden textarea + execCommand("copy") so the button still works.
  function flashCopied(btn) {
    var prev = btn.getAttribute("data-copy-label");
    if (prev === null) {
      prev = btn.textContent;
      btn.setAttribute("data-copy-label", prev);
    }
    btn.textContent = "Copied";
    setTimeout(function () { btn.textContent = prev; }, 1200);
  }

  // execCopy copies text without the async Clipboard API: it drops a hidden,
  // off-screen textarea holding the text, selects it, asks the document to copy the
  // selection, then removes the textarea. Returns true when the copy succeeded.
  function execCopy(text) {
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.top = "-1000px";
    ta.style.left = "-1000px";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    var ok = false;
    try {
      ta.focus();
      ta.select();
      ta.setSelectionRange(0, ta.value.length);
      ok = document.execCommand("copy");
    } catch (err) {
      ok = false;
    }
    document.body.removeChild(ta);
    return ok;
  }

  document.addEventListener("click", function (e) {
    var btn = e.target && e.target.closest ? e.target.closest(".copy-btn") : null;
    if (!btn) return;
    var target = document.getElementById(btn.getAttribute("data-copy-target"));
    if (!target) return;
    var codes = target.matches("code") ? [target] : target.querySelectorAll("code");
    var text = Array.prototype.map.call(codes, function (c) { return c.textContent.trim(); }).join("\n");
    if (!text) { text = target.textContent.trim(); }
    if (!text) return;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () {
        flashCopied(btn);
      }, function () {
        if (execCopy(text)) flashCopied(btn);
      });
      return;
    }
    if (execCopy(text)) flashCopied(btn);
  });

  function csrf() {
    var m = document.querySelector('meta[name="csrf"]');
    return m ? m.getAttribute("content") : "";
  }

  function $(id) { return document.getElementById(id); }

  // ---- sidebar toggle ----
  // Desktop: collapse/expand the fixed sidebar (persisted; also applied before first paint
  // by the inline head script). Phones: open/close the off-canvas sidebar overlay.
  (function sidebar() {
    var btn = $("sidebar-toggle");
    var root = document.documentElement;
    if (!btn) return;
    var desktop = window.matchMedia("(min-width: 769px)");
    btn.addEventListener("click", function () {
      if (desktop.matches) {
        var collapsed = root.classList.toggle("sidebar-collapsed");
        try { localStorage.setItem("sopshq-sidebar", collapsed ? "collapsed" : "open"); } catch (e) {}
      } else {
        root.classList.toggle("sidebar-open");
      }
    });
    // On a phone, tapping a link or clicking outside closes the overlay.
    document.addEventListener("click", function (e) {
      if (desktop.matches || !root.classList.contains("sidebar-open")) return;
      if (e.target.closest("#sidebar-toggle")) return;
      if (e.target.closest(".app-sidebar") && !e.target.closest("a")) return;
      root.classList.remove("sidebar-open");
    });
    desktop.addEventListener("change", function () { root.classList.remove("sidebar-open"); });
  })();

  // ---- mark the current page's sidebar link active ----
  (function navActive() {
    var links = document.querySelectorAll(".app-sidebar .nav-link");
    if (!links.length) return;
    var path = location.pathname;
    links.forEach(function (a) {
      var href = a.getAttribute("href");
      if (!href || href.indexOf("?") !== -1) return;
      var match = href === "/" ? path === "/" : (path === href || path.indexOf(href + "/") === 0);
      if (match) { a.classList.add("active"); a.setAttribute("aria-current", "page"); }
    });
  })();

  // ---- dark / light theme toggle (Bootstrap data-bs-theme) ----
  // The saved theme is applied to <html data-bs-theme> before first paint (inline head
  // script). This flips + persists it and swaps the sun/moon icon (showing the icon for
  // the theme you would switch TO).
  (function themeToggle() {
    var root = document.documentElement;
    function syncIcons() {
      var dark = root.getAttribute("data-bs-theme") === "dark";
      document.querySelectorAll(".theme-toggle .icon-moon").forEach(function (e) { e.classList.toggle("d-none", dark); });
      document.querySelectorAll(".theme-toggle .icon-sun").forEach(function (e) { e.classList.toggle("d-none", !dark); });
    }
    syncIcons();
    document.addEventListener("click", function (e) {
      if (!e.target.closest(".theme-toggle")) return;
      var next = root.getAttribute("data-bs-theme") === "dark" ? "light" : "dark";
      root.setAttribute("data-bs-theme", next);
      try { localStorage.setItem("sopshq-theme", next); } catch (e2) {}
      syncIcons();
    });
  })();

  // ---- OS-aware default suggestions when adding an OS user ----
  // Set the key-store base placeholder to match the selected machine's OS.
  (function osUserDefaults() {
    var sel = $("osu-machine");
    if (!sel) return;
    function apply() {
      var opt = sel.options[sel.selectedIndex];
      var os = opt ? opt.getAttribute("data-os") : "";
      var base = $("osu-keybase");
      if (os === "windows") {
        base.placeholder = "key-store base on an encrypted volume (e.g. Z:\\keys\\sops)";
      } else if (os === "linux") {
        base.placeholder = "key-store base (e.g. ~/.sops or /srv/sopshq-keys/sops)";
      } else {
        base.placeholder = "key-store base (e.g. ~/.sops)";
      }
    }
    sel.addEventListener("change", apply);
    apply();
  })();

  // ---- folder-picker modal (browses the LOCAL machine's filesystem) ----
  // A "Browse" button names a target text input and a machine <select>. Browsing
  // only works for the machine this panel runs on; for any other machine the path
  // must be typed (the panel cannot see a remote machine's disk).
  (function folderPicker() {
    var buttons = document.querySelectorAll("button.browse");
    if (!buttons.length) return;

    function machineIsLocal(selectID) {
      var sel = selectID ? $(selectID) : null;
      if (!sel) return true; // no machine select -> assume local (this node)
      var opt = sel.options[sel.selectedIndex];
      return !!(opt && opt.getAttribute("data-local") === "1");
    }

    function open(targetID, selectID) {
      if (!machineIsLocal(selectID)) {
        window.alert("Folder browsing works only for the machine this panel runs on. " +
          "For another machine, type the path as it exists on that machine.");
        return;
      }
      var target = $(targetID);
      var start = (target && target.value.trim()) || "";
      var backdrop = document.createElement("div");
      backdrop.className = "fp-backdrop";
      backdrop.innerHTML =
        '<div class="fp-dialog" role="dialog" aria-modal="true">' +
        '<h2>Choose a folder on this machine</h2>' +
        '<div class="cur mono"></div>' +
        '<div class="err hidden"></div>' +
        '<div class="listing"></div>' +
        '<div class="fp-actions">' +
        '<button type="button" class="btn btn-sm btn-link cancel">Cancel</button>' +
        '<button type="button" class="btn btn-sm btn-primary use">Use this folder</button>' +
        '</div></div>';
      document.body.appendChild(backdrop);

      var cur = backdrop.querySelector(".cur");
      var err = backdrop.querySelector(".err");
      var listing = backdrop.querySelector(".listing");
      var current = "";

      function close() { document.body.removeChild(backdrop); }
      backdrop.addEventListener("click", function (e) { if (e.target === backdrop) close(); });
      backdrop.querySelector(".cancel").addEventListener("click", close);
      backdrop.querySelector(".use").addEventListener("click", function () {
        if (target) target.value = current;
        close();
      });

      function load(path) {
        err.classList.add("hidden");
        fetch("/fs/list?path=" + encodeURIComponent(path || ""), { credentials: "same-origin" })
          .then(function (r) { return r.json(); })
          .then(function (data) {
            if (data.error) { err.textContent = data.error; err.classList.remove("hidden"); return; }
            current = data.path;
            cur.textContent = data.path;
            listing.innerHTML = "";
            if (data.parent !== undefined && data.parent !== null) {
              addRow("up", "(parent folder)", data.parent);
            }
            (data.dirs || []).forEach(function (d) { addRow("dir", d.name, d.path); });
            if (!(data.dirs || []).length) {
              var none = document.createElement("div");
              none.className = "err";
              none.textContent = "(no sub-folders)";
              listing.appendChild(none);
            }
          })
          .catch(function () { err.textContent = "Could not list folders."; err.classList.remove("hidden"); });
      }

      function addRow(kind, label, path) {
        var b = document.createElement("button");
        b.type = "button";
        b.className = kind;
        b.textContent = label;
        b.addEventListener("click", function () { load(path); });
        listing.appendChild(b);
      }

      load(start);
    }

    buttons.forEach(function (b) {
      b.addEventListener("click", function () {
        open(b.getAttribute("data-target"), b.getAttribute("data-machine"));
      });
    });
  })();

  // ---- Quick add: show the project vs global section based on the scope radio ----
  (function quickAddScope() {
    var form = $("quick-add");
    if (!form) return;
    var proj = form.querySelector(".qa-project");
    var glob = form.querySelector(".qa-global");
    function apply() {
      var sel = form.querySelector('input[name="scope"]:checked');
      var v = sel ? sel.value : "project";
      if (proj) proj.classList.toggle("hidden", v !== "project");
      if (glob) glob.classList.toggle("hidden", v !== "global");
    }
    form.querySelectorAll('input[name="scope"]').forEach(function (radio) {
      radio.addEventListener("change", apply);
    });
    apply();
  })();

  // ---- Backups: show only the fields for the chosen destination type ----
  // The add-destination form carries one field group per type (.dst-local,
  // .dst-ftp, .dst-telegram); the type <select> reveals the matching group and
  // hides the rest. The server still ignores fields irrelevant to the chosen type,
  // so this is presentation only.
  (function backupDestType() {
    var sel = $("backup-dest-type");
    var form = $("backup-dest-add");
    if (!sel || !form) return;
    var groups = form.querySelectorAll(".dst");
    function apply() {
      var want = "dst-" + sel.value;
      groups.forEach(function (g) {
        g.classList.toggle("hidden", !g.classList.contains(want));
      });
    }
    sel.addEventListener("change", apply);
    apply();
  })();

  // ---- OS users: reveal the secure-drive folder input when the box is ticked ----
  // Ticking "store on a secure drive" reveals the real-folder input and dims the
  // plain keystore field (the secure folder becomes the keystore). Presentation
  // only; the server decides which value to store.
  (function osuSecureDrive() {
    var form = $("osu-form");
    if (!form) return;
    var box = $("osu-use-secure");
    var secure = form.querySelector(".osu-secure");
    var keybase = form.querySelector(".osu-keybase");
    if (!box || !secure) return;
    function apply() {
      secure.classList.toggle("hidden", !box.checked);
      if (keybase) keybase.classList.toggle("text-body-secondary", box.checked);
    }
    box.addEventListener("change", apply);
    apply();
  })();

  // ---- reuse picker: load the cross-project catalog on demand and let the
  //      operator tick values to copy into this project (bulk add) ----
  (function reusePicker() {
    var picker = document.querySelector("details.reuse-picker");
    if (!picker) return;
    var rows = picker.querySelector(".reuse-rows");
    var loaded = false;
    picker.addEventListener("toggle", function () {
      if (!picker.open || loaded) return;
      loaded = true;
      fetch("/secrets/catalog.json", { credentials: "same-origin" })
        .then(function (r) { if (!r.ok) throw new Error("load"); return r.json(); })
        .then(function (groups) { render(rows, groups); })
        .catch(function () {
          rows.removeAttribute("data-loading");
          rows.textContent = "Could not load the secrets catalog.";
        });
    });

    // render builds the picker as the SAME flat secrets table (Value / Name /
    // Project / Machine / User / Key / Path / Uses) with a leading checkbox column,
    // then enhances it with DataTables (no paging, so every checkbox submits with
    // the form). Built with DOM APIs + textContent so names/paths can't inject markup.
    function render(container, groups) {
      container.removeAttribute("data-loading");
      container.textContent = "";
      var usages = [];
      (groups || []).forEach(function (g) {
        (g.usages || []).forEach(function (u) { usages.push({ u: u, count: g.count }); });
      });
      if (!usages.length) {
        container.textContent = "No reusable secrets found on this machine.";
        return;
      }
      var table = document.createElement("table");
      table.className = "table table-striped table-hover align-middle dt dt-nopage";
      table.style.width = "100%";
      var thead = document.createElement("thead");
      thead.innerHTML =
        "<tr><th class='no-sort'></th><th class='no-sort'>Value</th><th>Name</th>" +
        "<th class='filter'>Project</th><th class='filter'>Machine</th>" +
        "<th class='filter'>User</th><th class='filter'>Key</th><th>Path</th><th>Uses</th></tr>";
      table.appendChild(thead);
      var tbody = document.createElement("tbody");
      usages.forEach(function (row, idx) {
        var u = row.u;
        var pick = u.project_id + "|" + u.name;
        var tr = document.createElement("tr");

        tr.appendChild(td(function (cell) {
          var c = document.createElement("input");
          c.type = "checkbox"; c.name = "pick"; c.value = pick; c.className = "form-check-input";
          c.id = "reuse-pick-" + idx;
          c.setAttribute("aria-label", "Copy " + u.name + " from " + u.project);
          cell.appendChild(c);
        }));
        tr.appendChild(td(function (cell) {
          cell.className = "secret-val";
          var m = document.createElement("span"); m.className = "masked"; m.textContent = "**********";
          var s = document.createElement("span"); s.className = "shown hidden";
          var b = document.createElement("button");
          b.type = "button"; b.className = "btn btn-sm btn-outline-secondary secret-toggle secret-show"; b.textContent = "Show";
          b.setAttribute("data-project", u.project_id); b.setAttribute("data-name", u.name);
          cell.appendChild(m); cell.appendChild(s); cell.appendChild(b);
        }));
        tr.appendChild(textTd(u.name, "mono"));
        tr.appendChild(textTd(u.project, ""));
        tr.appendChild(textTd(u.machine, ""));
        tr.appendChild(textTd(u.user, ""));
        tr.appendChild(textTd(u.key, ""));
        tr.appendChild(textTd(u.path, "mono"));
        tr.appendChild(textTd(String(row.count), ""));
        tbody.appendChild(tr);
      });
      table.appendChild(tbody);
      container.appendChild(table);
      if (window.SopsHQTable) { window.SopsHQTable.init(table, { paging: false }); }
    }

    function td(fill) { var c = document.createElement("td"); fill(c); return c; }
    function textTd(text, cls) {
      var c = document.createElement("td");
      if (cls) c.className = cls;
      c.textContent = text == null ? "" : text;
      return c;
    }
  })();

  // ---- Audit page: from/to date-range filter on the Time column ----
  // Registers a DataTables custom range filter scoped to the audit table only, so
  // other ".dt" tables are unaffected. It hooks jQuery ready so it runs AFTER dt.js
  // has enhanced the table (dt.js loads first, so its ready callback runs first).
  (function auditDateFilter() {
    if (typeof window.jQuery === "undefined" || !window.jQuery.fn || !window.jQuery.fn.DataTable) {
      return;
    }
    var $ = window.jQuery;
    $(function () {
      var from = document.getElementById("audit-from");
      var to = document.getElementById("audit-to");
      var tableEl = document.getElementById("audit-table");
      if (!from || !to || !tableEl) return;
      var dt = $(tableEl).DataTable();
      var TIME_COL = 0; // the audit table's first column is the Time cell

      // ISO date strings ("YYYY-MM-DD") compare lexically in chronological order, so
      // a string range test on the first 10 chars of the Time cell needs no parsing.
      // The check is scoped to the audit table by node so it leaves other tables alone.
      function inRange(settings, data) {
        if (settings.nTable !== tableEl) return true;
        var rowDate = (data[TIME_COL] || "").slice(0, 10);
        var lo = from.value, hi = to.value;
        if (lo && rowDate < lo) return false;
        if (hi && rowDate > hi) return false;
        return true;
      }
      $.fn.dataTable.ext.search.push(inRange);

      from.addEventListener("change", function () { dt.draw(); });
      to.addEventListener("change", function () { dt.draw(); });
      var clear = document.getElementById("audit-filter-clear");
      if (clear) {
        clear.addEventListener("click", function () {
          from.value = ""; to.value = ""; dt.draw();
        });
      }
      dt.draw();
    });
  })();

  // ---- DB page: fix DataTables column widths on a tab shown after load ----
  // DataTables sizes columns from the rendered width, but a Bootstrap tab that
  // starts hidden has zero width, so its table renders with squashed columns until
  // re-measured. When a DB tab is shown, re-run columns.adjust() on its table.
  // Only runs on the DB page (guarded by #db-tabs) and only if jQuery + DataTables
  // are present.
  (function dbTabs() {
    if (typeof window.jQuery === "undefined" || !window.jQuery.fn || !window.jQuery.fn.DataTable) {
      return;
    }
    var $ = window.jQuery;
    var tabs = document.getElementById("db-tabs");
    if (!tabs) return;
    tabs.addEventListener("shown.bs.tab", function (e) {
      var sel = e.target.getAttribute("data-bs-target");
      var pane = sel ? document.querySelector(sel) : null;
      if (!pane) return;
      var table = pane.querySelector("table.dt");
      if (table && $.fn.dataTable.isDataTable(table)) {
        $(table).DataTable().columns.adjust();
      }
    });
  })();

  // ---- Map page: load a view's tree as JSON, render it with expand/collapse,
  //      show a leaf's read-only detail, and drive the view editor ----
  // Names + record ids only ever cross the wire here (the server never puts a
  // secret value in /map/tree), so this is presentation of non-secret structure.
  (function mapPage() {
    var page = $("map-page");
    if (!page) return;
    var treeBox = $("map-tree");
    var detail = $("map-detail");
    var views = $("map-views");
    if (!treeBox || !detail || !views) return;

    // ---- tree loading + rendering ----
    function loadTree(viewID) {
      treeBox.dataset.active = viewID;
      treeBox.textContent = "";
      var loading = document.createElement("p");
      loading.className = "text-body-secondary small m-2";
      loading.textContent = "Loading...";
      treeBox.appendChild(loading);
      fetch("/map/tree?view=" + encodeURIComponent(viewID), { credentials: "same-origin" })
        .then(function (r) { return r.json(); })
        .then(function (data) {
          treeBox.textContent = "";
          var nodes = (data && data.nodes) || [];
          if (!nodes.length) {
            var empty = document.createElement("p");
            empty.className = "text-body-secondary small m-2";
            empty.textContent = "This view is empty - no records match this grouping yet.";
            treeBox.appendChild(empty);
            return;
          }
          treeBox.appendChild(renderLevel(nodes, 0));
        })
        .catch(function () {
          treeBox.textContent = "";
          var err = document.createElement("p");
          err.className = "text-danger small m-2";
          err.textContent = "Could not load this view.";
          treeBox.appendChild(err);
        });
    }

    function renderLevel(nodes, depth) {
      var ul = document.createElement("ul");
      ul.className = "map-children" + (depth === 0 ? " map-root" : "");
      nodes.forEach(function (n) { ul.appendChild(renderNode(n, depth)); });
      return ul;
    }

    function renderNode(node, depth) {
      var li = document.createElement("li");
      li.className = "map-node";
      var row = document.createElement("div");
      row.className = "map-row";
      var label = document.createElement("span");
      label.className = "map-label";
      label.textContent = node.label;

      if (node.kind === "leaf") {
        row.className += " map-leaf";
        row.setAttribute("role", "button");
        row.setAttribute("tabindex", "0");
        var bullet = document.createElement("span");
        bullet.className = "map-bullet";
        row.appendChild(bullet);
        row.appendChild(label);
        row.addEventListener("click", function () { showDetail(node, row); });
        li.appendChild(row);
        return li;
      }

      // grouping node: caret + collapsible children (top level open, rest closed).
      row.className += " map-group";
      row.setAttribute("role", "button");
      var caret = document.createElement("span");
      caret.className = "map-caret";
      row.appendChild(caret);
      row.appendChild(label);
      li.appendChild(row);

      var kids = renderLevel(node.children || [], depth + 1);
      var open = depth === 0;
      if (open) { row.classList.add("open"); } else { kids.classList.add("hidden"); }
      li.appendChild(kids);
      row.addEventListener("click", function () {
        var nowOpen = row.classList.toggle("open");
        kids.classList.toggle("hidden", !nowOpen);
      });
      return li;
    }

    // ---- right-pane read-only detail for a clicked leaf ----
    var attrLabels = {
      Project: "Project", Machine: "Machine", OSUser: "OS user", Path: "Path",
      Key: "Key", SecretName: "Secret name", GlobalSet: "Global set"
    };
    function showDetail(node, row) {
      treeBox.querySelectorAll(".map-row.selected").forEach(function (e) { e.classList.remove("selected"); });
      if (row) row.classList.add("selected");
      detail.textContent = "";
      var h = document.createElement("h2");
      h.className = "h6";
      h.textContent = node.label;
      detail.appendChild(h);
      var dl = document.createElement("dl");
      dl.className = "row mb-0 small";
      addField(dl, "Type", attrLabels[node.attr] || node.attr);
      if (node.attr === "Project" && node.ref) {
        var dd = addField(dl, "Open", null);
        var a = document.createElement("a");
        a.href = "/projects/" + node.ref;
        a.textContent = "Project page";
        dd.appendChild(a);
      } else if (node.ref) {
        addField(dl, node.attr === "SecretName" ? "Name" : (node.attr === "Path" ? "Path" : "Reference"), node.ref);
      }
      detail.appendChild(dl);
      var note = document.createElement("p");
      note.className = "text-body-secondary small mt-3 mb-0";
      note.textContent = "Read-only. Open the record's own page to make changes.";
      detail.appendChild(note);
    }
    function addField(dl, label, value) {
      var dt = document.createElement("dt");
      dt.className = "col-4 text-body-secondary fw-normal";
      dt.textContent = label;
      var dd = document.createElement("dd");
      dd.className = "col-8 mb-1";
      if (value != null) dd.textContent = value;
      dl.appendChild(dt);
      dl.appendChild(dd);
      return dd;
    }

    // ---- view switching (pills) ----
    var editBtn = $("map-edit-view");
    var deleteForm = $("map-delete-form");
    function updateToolbar(pill) {
      var custom = pill && pill.dataset.custom === "1";
      if (editBtn) editBtn.classList.toggle("d-none", !custom);
      if (deleteForm) {
        deleteForm.classList.toggle("d-none", !custom);
        if (custom) deleteForm.setAttribute("action", "/map/views/" + pill.dataset.view + "/delete");
      }
    }
    function activePill() { return views.querySelector(".map-view-pill.active"); }
    function setActive(pill) {
      views.querySelectorAll(".map-view-pill").forEach(function (p) { p.classList.remove("active"); });
      pill.classList.add("active");
      updateToolbar(pill);
      closeEditor();
      loadTree(pill.dataset.view);
    }
    views.addEventListener("click", function (e) {
      var pill = e.target.closest(".map-view-pill");
      if (pill) setActive(pill);
    });

    // ---- view editor ----
    var editor = $("map-editor");
    var form = $("map-editor-form");
    var levelList = $("map-level-list");
    var levelsInput = $("map-levels-input");
    var nameInput = $("map-name");
    var leafSelect = $("map-leaf");
    var editorTitle = $("map-editor-title");
    var defaultOrder = [];
    if (levelList) {
      levelList.querySelectorAll("li[data-key]").forEach(function (li) { defaultOrder.push(li.dataset.key); });
    }
    function closeEditor() { if (editor) editor.classList.add("d-none"); }
    function orderLevels(order, checkedSet) {
      var byKey = {};
      levelList.querySelectorAll("li[data-key]").forEach(function (li) { byKey[li.dataset.key] = li; });
      order.forEach(function (key) {
        var li = byKey[key];
        if (!li) return;
        levelList.appendChild(li);
        var box = li.querySelector(".lvl-include");
        if (box) box.checked = !!(checkedSet && checkedSet[key]);
      });
    }
    function openEditor(custom) {
      if (!editor) return;
      editor.classList.remove("d-none");
      if (custom) {
        form.setAttribute("action", "/map/views/" + custom.id);
        if (editorTitle) editorTitle.textContent = "Edit view";
        nameInput.value = custom.name;
        leafSelect.value = custom.leaf || "SecretName";
        var groupBy = (custom.groupby || "").split(",").filter(Boolean);
        var checked = {};
        groupBy.forEach(function (k) { checked[k] = true; });
        var rest = defaultOrder.filter(function (k) { return groupBy.indexOf(k) === -1; });
        orderLevels(groupBy.concat(rest), checked);
      } else {
        form.setAttribute("action", "/map/views");
        if (editorTitle) editorTitle.textContent = "New view";
        nameInput.value = "";
        leafSelect.value = "SecretName";
        orderLevels(defaultOrder, {});
      }
    }
    var newBtn = $("map-new-view");
    if (newBtn) newBtn.addEventListener("click", function () { openEditor(null); });
    if (editBtn) {
      editBtn.addEventListener("click", function () {
        var pill = activePill();
        if (!pill || pill.dataset.custom !== "1") return;
        openEditor({
          id: pill.dataset.view,
          name: (pill.textContent || "").trim(),
          groupby: pill.dataset.groupby || "",
          leaf: pill.dataset.leaf || ""
        });
      });
    }
    var closeBtn = $("map-editor-close");
    if (closeBtn) closeBtn.addEventListener("click", closeEditor);
    if (levelList) {
      levelList.addEventListener("click", function (e) {
        var up = e.target.closest(".lvl-up");
        var down = e.target.closest(".lvl-down");
        if (!up && !down) return;
        var li = e.target.closest("li[data-key]");
        if (!li) return;
        if (up && li.previousElementSibling) {
          levelList.insertBefore(li, li.previousElementSibling);
        } else if (down && li.nextElementSibling) {
          levelList.insertBefore(li.nextElementSibling, li);
        }
      });
    }
    if (form) {
      form.addEventListener("submit", function () {
        var ordered = [];
        levelList.querySelectorAll("li[data-key]").forEach(function (li) {
          var box = li.querySelector(".lvl-include");
          if (box && box.checked) ordered.push(li.dataset.key);
        });
        levelsInput.value = ordered.join(",");
      });
    }

    // ---- initial load ----
    var start = activePill() || views.querySelector(".map-view-pill");
    if (start) {
      start.classList.add("active");
      updateToolbar(start);
      loadTree(treeBox.dataset.active || start.dataset.view);
    }
  })();

  // ---- secret reveal: values are masked until the operator clicks Show ----
  // A delegated handler so it covers both server-rendered rows and rows added
  // dynamically (the reuse picker). Per-button "loaded" state lives on the element.
  (function secretReveal() {
    document.addEventListener("click", function (e) {
      var b = e.target.closest ? e.target.closest("button.secret-show") : null;
      if (!b) return;
      var row = b.closest("tr") || b.parentNode;
      var box = row.querySelector(".secret-val");
      if (!box) return;
      var masked = box.querySelector(".masked");
      var shown = box.querySelector(".shown");
      if (!shown.classList.contains("hidden")) { // currently shown -> hide
        shown.classList.add("hidden");
        masked.classList.remove("hidden");
        b.textContent = "Show";
        return;
      }
      function reveal() {
        masked.classList.add("hidden");
        shown.classList.remove("hidden");
        b.textContent = "Hide";
      }
      if (b.dataset.loaded === "1") { reveal(); return; }
      var body = new URLSearchParams();
      body.set("csrf", csrf());
      body.set("name", b.getAttribute("data-name"));
      // Project secrets build the URL from data-project; other surfaces (the global
      // secrets page) pass an explicit endpoint via data-reveal-url.
      var url = b.getAttribute("data-reveal-url") ||
        ("/projects/" + b.getAttribute("data-project") + "/secrets/reveal");
      fetch(url, {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString(),
      })
        .then(function (r) { return r.json(); })
        .then(function (data) {
          if (data.error) { shown.textContent = "(" + data.error + ")"; }
          else { shown.textContent = data.value; b.dataset.loaded = "1"; }
          reveal();
        })
        .catch(function () { shown.textContent = "(could not read secret)"; reveal(); });
    });
  })();

  // ---- Permissions page: list / tree / changes over the latest scan ----
  // Only non-secret structure crosses the wire (paths, owners, modes, ACL grants).
  // Path and name text is untrusted data from the scanned filesystem, so every cell
  // is built with textContent (never innerHTML) to keep it inert.
  (function permmapPage() {
    var page = $("permmap-page");
    if (!page) return;
    if (page.getAttribute("data-has-scan") !== "1") return;

    // Small DOM helpers.
    function el(tag, cls, text) {
      var n = document.createElement(tag);
      if (cls) n.className = cls;
      if (text != null) n.textContent = text;
      return n;
    }
    function badge(text, cls) { return el("span", "badge rounded-pill " + cls + " me-1", text); }
    function flagBadges(n) {
      var frag = document.createDocumentFragment();
      if (n.dangerous) frag.appendChild(badge("dangerous", "text-bg-danger"));
      if (n.world_writable) frag.appendChild(badge("world-writable", "text-bg-warning"));
      if (n.acl_override) frag.appendChild(badge("acl-override", "text-bg-info"));
      else if (n.has_acl) frag.appendChild(badge("acl", "text-bg-info"));
      return frag;
    }

    // ---- List tab ----
    var listBody = $("permmap-list-body");
    var listStatus = $("permmap-list-status");
    var search = $("permmap-search");
    var filterGroup = $("permmap-filters");
    var curFilter = "dangerous";

    function loadList() {
      var q = search ? search.value.trim() : "";
      listStatus.textContent = "Loading...";
      fetch("/permmap/data?filter=" + encodeURIComponent(curFilter) + "&q=" + encodeURIComponent(q),
        { credentials: "same-origin" })
        .then(function (r) { return r.json(); })
        .then(function (data) {
          listBody.textContent = "";
          var rows = data.entries || [];
          rows.forEach(function (e) {
            var tr = el("tr");
            tr.appendChild(el("td", "mono", e.path));
            tr.appendChild(el("td", null, e.type || ""));
            tr.appendChild(el("td", null, e.owner || ""));
            tr.appendChild(el("td", null, e.group || ""));
            tr.appendChild(el("td", "mono", e.mode || ""));
            tr.appendChild(el("td", "mono small", (e.acl || []).join(", ")));
            var flags = el("td");
            flags.appendChild(flagBadges(e));
            tr.appendChild(flags);
            listBody.appendChild(tr);
          });
          var msg = "Showing " + data.shown + " of " + data.total + " matching paths";
          if (data.total > data.limit) msg += " (capped at " + data.limit + " - narrow the filter or search)";
          listStatus.textContent = data.total === 0 ? "No matching paths." : msg + ".";
        })
        .catch(function () { listStatus.textContent = "Could not load the scan."; });
    }

    if (filterGroup) {
      filterGroup.addEventListener("click", function (e) {
        var btn = e.target.closest("button[data-filter]");
        if (!btn) return;
        curFilter = btn.getAttribute("data-filter");
        Array.prototype.forEach.call(filterGroup.querySelectorAll("button"), function (b) {
          b.classList.toggle("active", b === btn);
        });
        loadList();
      });
    }
    if (search) {
      var t = null;
      search.addEventListener("input", function () {
        if (t) clearTimeout(t);
        t = setTimeout(loadList, 250);
      });
    }
    loadList();

    // ---- Tree tab (lazy children per directory) ----
    var treeRoot = $("permmap-tree-root");
    function nodeRow(n) {
      var li = el("li", "permmap-node");
      var row = el("div", "permmap-row d-flex align-items-center gap-2");
      var caret = el("span", "permmap-caret", n.has_children ? "+" : "");
      caret.style.width = "1rem";
      caret.style.cursor = n.has_children ? "pointer" : "default";
      row.appendChild(caret);
      row.appendChild(el("span", "mono", n.name));
      var meta = el("span", "text-body-secondary small",
        (n.owner || "?") + ":" + (n.group || "?") + " " + (n.mode || ""));
      row.appendChild(meta);
      row.appendChild(flagBadges(n));
      li.appendChild(row);
      if (n.has_children) {
        var kids = el("ul", "permmap-children hidden");
        li.appendChild(kids);
        var loaded = false;
        caret.addEventListener("click", function () {
          var open = kids.classList.toggle("hidden") === false;
          caret.textContent = open ? "-" : "+";
          if (open && !loaded) {
            loaded = true;
            loadChildren(n.path, kids);
          }
        });
      }
      return li;
    }
    function loadChildren(path, into) {
      into.textContent = "";
      into.appendChild(el("li", "text-body-secondary small", "Loading..."));
      fetch("/permmap/tree?path=" + encodeURIComponent(path), { credentials: "same-origin" })
        .then(function (r) { return r.json(); })
        .then(function (data) {
          into.textContent = "";
          (data.nodes || []).forEach(function (n) { into.appendChild(nodeRow(n)); });
          if (!(data.nodes || []).length) into.appendChild(el("li", "text-body-secondary small", "(empty)"));
        })
        .catch(function () { into.textContent = ""; into.appendChild(el("li", "text-danger small", "Could not load.")); });
    }
    var treeTab = $("pm-tree-tab");
    if (treeTab && treeRoot) {
      treeTab.addEventListener("shown.bs.tab", function () {
        if (treeRoot.dataset.loaded === "1") return;
        treeRoot.dataset.loaded = "1";
        treeRoot.textContent = "";
        var ul = el("ul", "permmap-children permmap-root");
        treeRoot.appendChild(ul);
        loadChildren("", ul);
      });
    }

    // ---- Changes tab (diff vs baseline) ----
    var changesPane = $("pm-changes");
    var changesTab = $("pm-changes-tab");
    function section(title, count) {
      var h = el("h6", "mt-3", title + " (" + count + ")");
      return h;
    }
    function loadChanges() {
      changesPane.textContent = "";
      changesPane.appendChild(el("p", "text-body-secondary small m-2", "Loading..."));
      fetch("/permmap/diff", { credentials: "same-origin" })
        .then(function (r) { return r.json(); })
        .then(function (data) {
          changesPane.textContent = "";
          if (!data.has_baseline) {
            changesPane.appendChild(el("div", "alert alert-secondary",
              "No baseline set yet. Use Set baseline to capture the current scan as the reference."));
            return;
          }
          var d = data.diff || {};
          var added = d.added || [], removed = d.removed || [], changed = d.changed || [];
          if (!added.length && !removed.length && !changed.length) {
            changesPane.appendChild(el("div", "alert alert-success", "No changes since the baseline."));
            return;
          }
          if (added.length) {
            changesPane.appendChild(section("Added", added.length));
            var ua = el("ul", "list-unstyled mono small");
            added.forEach(function (e) { ua.appendChild(el("li", null, "+ " + e.path)); });
            changesPane.appendChild(ua);
          }
          if (removed.length) {
            changesPane.appendChild(section("Removed", removed.length));
            var ur = el("ul", "list-unstyled mono small");
            removed.forEach(function (e) { ur.appendChild(el("li", null, "- " + e.path)); });
            changesPane.appendChild(ur);
          }
          if (changed.length) {
            changesPane.appendChild(section("Changed", changed.length));
            changed.forEach(function (c) {
              changesPane.appendChild(el("div", "mono small mt-1", c.path));
              var ul = el("ul", "small");
              (c.attrs || []).forEach(function (a) {
                ul.appendChild(el("li", null, a.field + ": " + a.before + " -> " + a.after));
              });
              changesPane.appendChild(ul);
            });
          }
        })
        .catch(function () {
          changesPane.textContent = "";
          changesPane.appendChild(el("p", "text-danger small m-2", "Could not load the changes."));
        });
    }
    if (changesTab && changesPane) {
      changesTab.addEventListener("shown.bs.tab", function () {
        if (changesPane.dataset.loaded === "1") return;
        changesPane.dataset.loaded = "1";
        loadChanges();
      });
    }
  })();
})();
