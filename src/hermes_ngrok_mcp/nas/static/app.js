/* hermes-nas — file manager UI (vanilla JS, no dependency).
 *
 * Security notes: every user-controlled string (file names, server messages) is inserted with
 * textContent, never innerHTML. State-changing requests carry X-NAS-Request, which the server
 * requires as an anti-forgery check. Basic authentication is handled by the browser.
 */
"use strict";

(() => {
  const body = document.body;
  const TITLE = body.dataset.title || "NAS";
  const MAX_UPLOAD = Number(body.dataset.maxUpload) || Infinity;
  const BASE_HEADERS = { "ngrok-skip-browser-warning": "1" };
  const PARALLEL_UPLOADS = 2;
  const TEXT_PREVIEW_BYTES = 512 * 1024;
  const THUMBNAIL_MAX_BYTES = 12 * 1024 * 1024;
  const collator = new Intl.Collator("fr", { numeric: true, sensitivity: "base" });
  const dateFormat = new Intl.DateTimeFormat("fr-FR", { dateStyle: "medium", timeStyle: "short" });
  const shortDate = new Intl.DateTimeFormat("fr-FR", { day: "numeric", month: "short", year: "numeric" });
  const relative = new Intl.RelativeTimeFormat("fr", { numeric: "auto" });

  const $ = (id) => document.getElementById(id);
  const el = {
    topbar: document.querySelector(".topbar"),
    search: $("search"),
    searchToggle: $("search-toggle"),
    viewToggle: $("view-toggle"),
    themeToggle: $("theme-toggle"),
    mkdirBtn: $("mkdir-btn"),
    uploadBtn: $("upload-btn"),
    fileInput: $("file-input"),
    banner: $("banner"),
    bannerText: $("banner-text"),
    bannerRetry: $("banner-retry"),
    crumbs: $("crumbs"),
    storage: $("storage"),
    storageText: $("storage-text"),
    storageMeter: $("storage-meter"),
    storageBar: $("storage-bar"),
    browser: $("browser"),
    listHead: $("list-head"),
    entries: $("entries"),
    empty: $("empty"),
    emptyTitle: $("empty-title"),
    emptyText: $("empty-text"),
    footnote: $("footnote"),
    dropzone: $("dropzone"),
    dropzoneTarget: $("dropzone-target"),
    uploads: $("uploads"),
    uploadsTitle: $("uploads-title"),
    uploadsSub: $("uploads-sub"),
    uploadsBar: $("uploads-bar"),
    uploadsList: $("uploads-list"),
    uploadsClear: $("uploads-clear"),
    uploadsCollapse: $("uploads-collapse"),
    mkdirDialog: $("mkdir-dialog"),
    mkdirForm: $("mkdir-form"),
    mkdirWhere: $("mkdir-where"),
    mkdirName: $("mkdir-name"),
    mkdirError: $("mkdir-error"),
    mkdirCancel: $("mkdir-cancel"),
    mkdirSubmit: $("mkdir-submit"),
    viewer: $("viewer"),
    viewerName: $("viewer-name"),
    viewerMeta: $("viewer-meta"),
    viewerStage: $("viewer-stage"),
    viewerDownload: $("viewer-download"),
    viewerClose: $("viewer-close"),
    viewerPrev: $("viewer-prev"),
    viewerNext: $("viewer-next"),
    helpDialog: $("help-dialog"),
    helpBtn: $("help-btn"),
    toasts: $("toasts"),
  };

  // --- small helpers ----------------------------------------------------------------------------
  const store = {
    get(key, fallback) {
      try {
        return localStorage.getItem(`nas.${key}`) ?? fallback;
      } catch {
        return fallback;
      }
    },
    set(key, value) {
      try {
        localStorage.setItem(`nas.${key}`, value);
      } catch {
        /* private mode: preferences are not kept */
      }
    },
  };

  function h(tag, props = {}, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(props)) {
      if (value === undefined || value === null || value === false) continue;
      if (key === "class") node.className = value;
      else if (key === "text") node.textContent = value;
      else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
      else node.setAttribute(key, value === true ? "" : value);
    }
    for (const child of children.flat()) {
      if (child !== null && child !== undefined && child !== false) {
        node.append(child instanceof Node ? child : document.createTextNode(String(child)));
      }
    }
    return node;
  }

  function icon(name, cls = "icon") {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("class", cls);
    svg.setAttribute("aria-hidden", "true");
    const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
    use.setAttribute("href", `#i-${name}`);
    svg.append(use);
    return svg;
  }

  function setIcon(button, name) {
    button.querySelector("use").setAttribute("href", `#i-${name}`);
  }

  const qs = (params) => new URLSearchParams(params).toString();
  const downloadUrl = (path, inline = false) => `/api/download?${qs(inline ? { path, inline: "1" } : { path })}`;

  function formatSize(bytes) {
    if (bytes === null || bytes === undefined) return "—";
    const units = ["o", "Ko", "Mo", "Go", "To"];
    let value = bytes;
    let unit = 0;
    while (value >= 1024 && unit < units.length - 1) {
      value /= 1024;
      unit += 1;
    }
    const digits = unit === 0 || value >= 100 ? 0 : 1;
    return `${value.toLocaleString("fr-FR", { maximumFractionDigits: digits })} ${units[unit]}`;
  }

  function formatDate(epoch) {
    const date = new Date(epoch * 1000);
    const seconds = (date.getTime() - Date.now()) / 1000;
    const abs = Math.abs(seconds);
    if (abs < 60) return "à l'instant";
    if (abs < 3600) return relative.format(Math.round(seconds / 60), "minute");
    if (abs < 86400) return relative.format(Math.round(seconds / 3600), "hour");
    if (abs < 7 * 86400) return relative.format(Math.round(seconds / 86400), "day");
    return shortDate.format(date);
  }

  function formatDuration(seconds) {
    if (!Number.isFinite(seconds) || seconds < 0) return "";
    if (seconds < 60) return `${Math.ceil(seconds)} s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)} min ${String(Math.ceil(seconds % 60)).padStart(2, "0")} s`;
    return `${Math.floor(seconds / 3600)} h ${String(Math.floor((seconds % 3600) / 60)).padStart(2, "0")}`;
  }

  // --- file kinds --------------------------------------------------------------------------------
  const EXTENSIONS = {
    image: ["png", "jpg", "jpeg", "gif", "webp", "avif", "bmp", "heic", "heif", "tif", "tiff", "svg", "raw", "cr2", "nef", "arw", "dng"],
    video: ["mp4", "m4v", "mov", "mkv", "webm", "avi", "wmv", "ogv", "mpg", "mpeg", "ts", "m2ts", "3gp"],
    audio: ["mp3", "m4a", "aac", "flac", "wav", "ogg", "oga", "opus", "wma", "alac", "aiff"],
    archive: ["zip", "rar", "7z", "tar", "gz", "tgz", "bz2", "xz", "zst", "iso", "dmg"],
    pdf: ["pdf"],
    doc: ["doc", "docx", "odt", "rtf", "pages", "epub"],
    sheet: ["xls", "xlsx", "ods", "numbers"],
    slide: ["ppt", "pptx", "odp", "key"],
    code: ["py", "js", "ts", "jsx", "tsx", "json", "html", "css", "scss", "sh", "bash", "c", "h", "cpp", "rs", "go", "java", "kt", "rb", "php", "sql", "yaml", "yml", "toml", "xml", "ini", "conf", "cfg", "env"],
    text: ["txt", "md", "log", "csv", "tsv", "srt", "vtt", "nfo"],
  };
  const KIND_BY_EXT = new Map();
  for (const [kind, list] of Object.entries(EXTENSIONS)) for (const ext of list) KIND_BY_EXT.set(ext, kind);
  const KIND_ICONS = { image: "image", video: "video", audio: "audio", archive: "archive", pdf: "doc", doc: "doc", sheet: "doc", slide: "doc", code: "code", text: "doc", other: "file" };

  // Same lists as the server's inline whitelist: anything else is a download.
  const PREVIEW_IMAGE = new Set(["png", "jpg", "jpeg", "gif", "webp", "avif", "bmp"]);
  const PREVIEW_VIDEO = new Set(["mp4", "m4v", "webm", "ogv", "mov"]);
  const PREVIEW_AUDIO = new Set(["mp3", "m4a", "aac", "flac", "wav", "ogg", "oga"]);
  const PREVIEW_TEXT = new Set(["txt", "md", "log", "csv", "tsv", "json", "yaml", "yml", "toml", "ini", "conf", "cfg", "env", "py", "sh", "js", "ts", "css", "sql", "xml", "srt", "vtt", "nfo"]);

  function extensionOf(name) {
    const dot = name.lastIndexOf(".");
    return dot > 0 ? name.slice(dot + 1).toLowerCase() : "";
  }

  function describe(entry) {
    if (entry.kind === "dir") return { kind: "folder", icon: "folder", ext: "", preview: null };
    if (entry.kind === "symlink") return { kind: "other", icon: "link", ext: "", preview: null };
    const ext = extensionOf(entry.name);
    const kind = KIND_BY_EXT.get(ext) || "other";
    let preview = null;
    if (entry.kind === "file") {
      if (PREVIEW_IMAGE.has(ext)) preview = "image";
      else if (PREVIEW_VIDEO.has(ext)) preview = "video";
      else if (PREVIEW_AUDIO.has(ext)) preview = "audio";
      else if (PREVIEW_TEXT.has(ext)) preview = "text";
    }
    return { kind, icon: KIND_ICONS[kind], ext, preview };
  }

  // --- state ---------------------------------------------------------------------------------------
  const state = {
    path: null,
    entries: [],
    visible: [],
    disk: null,
    truncated: false,
    sort: { key: store.get("sortKey", "name"), dir: Number(store.get("sortDir", "1")) || 1 },
    view: store.get("view", "list"),
    filter: "",
    selected: -1,
    loadToken: 0,
    focusName: null,
  };

  // --- theme & view ----------------------------------------------------------------------------------
  const prefersDark = window.matchMedia("(prefers-color-scheme: dark)");

  function applyTheme() {
    const saved = store.get("theme", "");
    const theme = saved || (prefersDark.matches ? "dark" : "light");
    document.documentElement.dataset.theme = theme;
    setIcon(el.themeToggle, theme === "dark" ? "sun" : "moon");
    el.themeToggle.setAttribute("aria-label", theme === "dark" ? "Passer en thème clair" : "Passer en thème sombre");
  }

  el.themeToggle.addEventListener("click", () => {
    store.set("theme", document.documentElement.dataset.theme === "dark" ? "light" : "dark");
    applyTheme();
  });
  prefersDark.addEventListener("change", applyTheme);

  function applyView() {
    el.browser.classList.toggle("grid", state.view === "grid");
    setIcon(el.viewToggle, state.view === "grid" ? "list" : "grid");
    el.viewToggle.setAttribute("aria-label", state.view === "grid" ? "Afficher en liste" : "Afficher en grille");
  }

  function toggleView() {
    state.view = state.view === "grid" ? "list" : "grid";
    store.set("view", state.view);
    applyView();
    renderEntries();
  }

  el.viewToggle.addEventListener("click", toggleView);

  // --- API ---------------------------------------------------------------------------------------------
  class ApiError extends Error {
    constructor(status, message) {
      super(message);
      this.status = status;
    }
  }

  async function api(url, options = {}) {
    let response;
    try {
      response = await fetch(url, {
        credentials: "same-origin",
        cache: "no-store",
        ...options,
        headers: { ...BASE_HEADERS, ...(options.headers || {}) },
      });
    } catch {
      throw new ApiError(0, "Connexion impossible : le tunnel est peut-être fermé.");
    }
    if (!response.ok) {
      let message = `Erreur ${response.status}`;
      try {
        const data = await response.json();
        if (data && data.message) message = data.message;
      } catch {
        if (response.status === 401) message = "Session expirée : rechargez la page pour vous reconnecter.";
        else if (response.status >= 500) message = "Le NAS ne répond pas correctement. Réessayez dans un instant.";
      }
      throw new ApiError(response.status, translate(message));
    }
    return response.json();
  }

  // Server messages are in English (they are also read by the agent); show French ones to the user.
  const TRANSLATIONS = [
    [/does not exist/, "Cet élément n'existe pas (ou plus)."],
    [/Symbolic links are not followed/, "Les liens symboliques ne sont pas suivis."],
    [/Permission denied/, "Permission refusée sur le NAS."],
    [/already exists/, "Un élément porte déjà ce nom."],
    [/disk is full|Not enough free space/, "Espace disque insuffisant sur le NAS."],
    [/Files are limited to (.+)\./, (m) => `Fichier trop volumineux (limite : ${m[1]}).`],
    [/cannot contain '\/'/, "Un nom ne peut pas contenir « / » ni « \\ »."],
    [/control characters/, "Un nom ne peut pas contenir de caractères de contrôle."],
    [/start or end with a space/, "Un nom ne peut pas commencer ni finir par une espace."],
    [/too long/, "Ce nom est trop long."],
    [/reserved for uploads/, "Ce nom est réservé aux envois en cours."],
    [/other than '\.' or '\.\.'/, "Choisissez un nom non vide, différent de « . » et « .. »."],
    [/interrupted/, "L'envoi a été interrompu avant la fin."],
    [/anti-forgery/, "Requête refusée (protection anti-falsification)."],
    [/^Sign in\.|Wrong username or password/, "Session expirée : rechargez la page pour vous reconnecter."],
    [/No NAS tunnel is open/, "Le tunnel du NAS est fermé : demandez à Hermes de le rouvrir."],
    [/Too many wrong passwords/, "Trop de mots de passe erronés : réessayez dans quelques minutes."],
    [/^Access refused/, "Accès refusé."],
  ];

  function translate(message) {
    for (const [pattern, replacement] of TRANSLATIONS) {
      const match = message.match(pattern);
      if (match) return typeof replacement === "function" ? replacement(match) : replacement;
    }
    return message;
  }

  // --- navigation --------------------------------------------------------------------------------------
  function pathFromHash() {
    const raw = location.hash.replace(/^#\/?/, "");
    return raw
      .split("/")
      .filter(Boolean)
      .map((part) => {
        try {
          return decodeURIComponent(part);
        } catch {
          return part;
        }
      })
      .join("/");
  }

  const hashFor = (path) => `#/${path.split("/").filter(Boolean).map(encodeURIComponent).join("/")}`;
  const parentOf = (path) => path.split("/").slice(0, -1).join("/");
  const joinPath = (base, name) => (base ? `${base}/${name}` : name);

  function go(path) {
    const target = hashFor(path);
    if (location.hash === target) load(path);
    else location.hash = target;
  }

  window.addEventListener("hashchange", () => load(pathFromHash()));

  async function load(path, { keepSelection = false } = {}) {
    const token = ++state.loadToken;
    const sameFolder = path === state.path;
    if (!sameFolder) {
      state.filter = "";
      el.search.value = "";
      renderSkeleton();
    }
    try {
      const data = await api(`/api/list?${qs({ path })}`);
      if (token !== state.loadToken) return;
      hideBanner();
      const previousName = keepSelection ? state.visible[state.selected]?.name : null;
      state.path = data.path;
      state.entries = data.entries;
      state.disk = data.disk;
      state.truncated = data.truncated;
      state.selected = -1;
      renderCrumbs(data.breadcrumbs);
      renderStorage();
      renderEntries();
      const focus = state.focusName || previousName;
      state.focusName = null;
      if (focus) select(state.visible.findIndex((entry) => entry.name === focus), { scroll: true });
      document.title = data.path ? `${data.path.split("/").pop()} · ${TITLE}` : TITLE;
    } catch (error) {
      if (token !== state.loadToken) return;
      if (error.status === 404 && path) {
        toast(error.message, "error");
        go(parentOf(path));
        return;
      }
      showBanner(error.message, () => load(path));
      if (state.path === null) renderError(error.message);
    }
  }

  let refreshTimer = null;
  function scheduleRefresh() {
    clearTimeout(refreshTimer);
    refreshTimer = setTimeout(() => load(state.path ?? "", { keepSelection: true }), 350);
  }

  // --- rendering ----------------------------------------------------------------------------------------
  function renderCrumbs(breadcrumbs) {
    el.crumbs.replaceChildren();
    const all = [{ name: TITLE, path: "" }, ...breadcrumbs];
    all.forEach((crumb, index) => {
      const current = index === all.length - 1;
      if (index > 0) el.crumbs.append(icon("chevron", "crumb-sep"));
      const link = h(
        "a",
        { class: `crumb${current ? " current" : ""}`, href: hashFor(crumb.path), "aria-current": current ? "page" : null, title: crumb.name },
        index === 0 ? icon("home") : null,
        h("span", { text: crumb.name }),
      );
      enableDropTarget(link, crumb.path);
      el.crumbs.append(link);
    });
    el.crumbs.scrollLeft = el.crumbs.scrollWidth;
  }

  function renderStorage() {
    const disk = state.disk;
    if (!disk || !disk.total) {
      el.storage.hidden = true;
      return;
    }
    const used = disk.total - disk.free;
    const ratio = Math.min(1, Math.max(0, used / disk.total));
    el.storage.hidden = false;
    el.storageText.textContent = `${formatSize(disk.free)} libres sur ${formatSize(disk.total)}`;
    el.storageBar.style.setProperty("width", `${(ratio * 100).toFixed(1)}%`);
    el.storageMeter.classList.toggle("warn", ratio > 0.9);
    el.storageMeter.setAttribute("aria-valuenow", String(Math.round(ratio * 100)));
  }

  function sortEntries(entries) {
    const { key, dir } = state.sort;
    return [...entries].sort((a, b) => {
      const folderFirst = (a.kind === "dir" ? 0 : 1) - (b.kind === "dir" ? 0 : 1);
      if (folderFirst) return folderFirst;
      let result = 0;
      if (key === "size") result = (a.size ?? -1) - (b.size ?? -1);
      else if (key === "modified") result = a.modified - b.modified;
      if (!result) result = collator.compare(a.name, b.name);
      return result * dir;
    });
  }

  function renderSortHeaders() {
    for (const button of el.listHead.querySelectorAll(".sortable")) {
      const active = button.dataset.sort === state.sort.key;
      button.classList.toggle("asc", active && state.sort.dir === 1);
      button.classList.toggle("desc", active && state.sort.dir === -1);
      button.setAttribute("aria-sort", active ? (state.sort.dir === 1 ? "ascending" : "descending") : "none");
    }
  }

  function highlight(name) {
    const span = h("span", { class: "name", title: name });
    const needle = state.filter.trim().toLocaleLowerCase("fr");
    const index = needle ? name.toLocaleLowerCase("fr").indexOf(needle) : -1;
    if (index < 0) {
      span.textContent = name;
    } else {
      span.append(name.slice(0, index), h("mark", { text: name.slice(index, index + needle.length) }), name.slice(index + needle.length));
    }
    return span;
  }

  function fileIcon(entry, info) {
    const box = h("span", { class: `ficon k-${info.kind}` }, icon(info.icon));
    if (info.ext && entry.kind === "file") box.append(h("span", { class: "ext", text: info.ext.slice(0, 5) }));
    if (state.view === "grid" && info.preview === "image" && entry.size <= THUMBNAIL_MAX_BYTES) {
      const img = h("img", { alt: "", loading: "lazy", decoding: "async", src: downloadUrl(entry.path, true) });
      img.addEventListener("load", () => img.classList.add("loaded"));
      img.addEventListener("error", () => img.remove());
      box.append(img);
    }
    return box;
  }

  function renderEntries() {
    applyView();
    renderSortHeaders();
    const needle = state.filter.trim().toLocaleLowerCase("fr");
    const filtered = needle ? state.entries.filter((e) => e.name.toLocaleLowerCase("fr").includes(needle)) : state.entries;
    state.visible = sortEntries(filtered);
    if (state.selected >= state.visible.length) state.selected = -1;

    const items = state.visible.map((entry, index) => renderEntry(entry, index));
    el.entries.replaceChildren(...items);
    el.listHead.hidden = state.visible.length === 0;

    const isEmpty = state.visible.length === 0;
    el.empty.hidden = !isEmpty;
    if (isEmpty && needle) {
      el.emptyTitle.textContent = "Aucun résultat";
      el.emptyText.textContent = `Rien ne correspond à « ${state.filter.trim()} » dans ce dossier.`;
    } else if (isEmpty) {
      el.emptyTitle.textContent = "Ce dossier est vide";
      el.emptyText.replaceChildren("Glissez des fichiers ici, ou utilisez le bouton ", h("strong", { text: "Envoyer" }), ".");
    }
    const folders = state.visible.filter((e) => e.kind === "dir").length;
    const files = state.visible.length - folders;
    const parts = [];
    if (folders) parts.push(`${folders} dossier${folders > 1 ? "s" : ""}`);
    if (files) parts.push(`${files} fichier${files > 1 ? "s" : ""}`);
    if (state.truncated) parts.push("liste tronquée aux 10 000 premiers éléments");
    el.footnote.textContent = parts.join(" · ");
    el.footnote.hidden = parts.length === 0;
  }

  function renderEntry(entry, index) {
    const info = describe(entry);
    const disabled = entry.kind !== "dir" && entry.kind !== "file";
    const item = h("li", {
      class: `entry${disabled ? " disabled" : ""}${index === state.selected ? " selected" : ""}`,
      "data-index": String(index),
    });
    item.style.setProperty("--i", String(index));
    const meta = entry.kind === "file" ? `${formatSize(entry.size)} · ${formatDate(entry.modified)}` : formatDate(entry.modified);
    const label = h("span", { class: "label-wrap" }, highlight(entry.name), h("span", { class: "meta", text: meta }));
    let main;
    if (entry.kind === "dir") {
      main = h("a", { class: "entry-main", href: hashFor(entry.path) }, fileIcon(entry, info), label);
      enableDropTarget(item, entry.path);
    } else if (entry.kind === "file") {
      main = h(
        info.preview ? "button" : "a",
        info.preview
          ? { class: "entry-main", type: "button", onclick: () => openViewer(entry) }
          : { class: "entry-main", href: downloadUrl(entry.path), download: entry.name },
        fileIcon(entry, info),
        label,
      );
    } else {
      main = h(
        "span",
        { class: "entry-main", title: entry.kind === "symlink" ? "Les liens symboliques ne sont pas suivis" : "Fichier spécial non disponible" },
        fileIcon(entry, info),
        label,
      );
    }
    main.addEventListener("focus", () => select(index));
    const action =
      entry.kind === "file"
        ? h("a", { class: "icon-btn act", href: downloadUrl(entry.path), download: entry.name, "aria-label": `Télécharger ${entry.name}`, title: "Télécharger" }, icon("download"))
        : entry.kind === "dir"
          ? h("a", { class: "icon-btn act", href: hashFor(entry.path), "aria-label": `Ouvrir ${entry.name}`, title: "Ouvrir", tabindex: "-1" }, icon("chevron"))
          : h("span", { class: "act" });
    item.append(
      main,
      h("span", { class: "size", text: entry.kind === "file" ? formatSize(entry.size) : "—" }),
      h("span", { class: "date", text: formatDate(entry.modified), title: dateFormat.format(new Date(entry.modified * 1000)) }),
      action,
    );
    return item;
  }

  function renderSkeleton() {
    el.empty.hidden = true;
    el.footnote.hidden = true;
    const rows = Array.from({ length: 7 }, (_, i) =>
      h(
        "li",
        { class: "entry skeleton", "aria-hidden": "true" },
        h("span", { class: "entry-main" }, h("span", { class: "ficon" }), h("span", { class: "bar", style: null })),
        h("span", { class: "size" }, h("span", { class: "bar" })),
        h("span", { class: "date" }, h("span", { class: "bar" })),
        h("span"),
      ),
    );
    rows.forEach((row, i) => row.querySelector(".entry-main .bar").style.setProperty("width", `${38 + ((i * 17) % 40)}%`));
    el.entries.replaceChildren(...rows);
  }

  function renderError(message) {
    el.entries.replaceChildren();
    el.empty.hidden = false;
    el.emptyTitle.textContent = "Impossible d'afficher ce dossier";
    el.emptyText.textContent = message;
  }

  // --- selection & keyboard --------------------------------------------------------------------------------
  function select(index, { scroll = false, focus = false } = {}) {
    const items = el.entries.children;
    if (state.selected >= 0 && items[state.selected]) items[state.selected].classList.remove("selected");
    state.selected = index;
    if (index < 0 || !items[index]) return;
    items[index].classList.add("selected");
    if (scroll) items[index].scrollIntoView({ block: "nearest" });
    if (focus) items[index].querySelector(".entry-main")?.focus({ preventScroll: true });
  }

  function gridColumns() {
    if (state.view !== "grid") return 1;
    const columns = getComputedStyle(el.entries).gridTemplateColumns.split(" ").filter(Boolean).length;
    return Math.max(1, columns);
  }

  function moveSelection(delta) {
    if (!state.visible.length) return;
    const start = state.selected < 0 ? (delta > 0 ? -1 : state.visible.length) : state.selected;
    const next = Math.min(state.visible.length - 1, Math.max(0, start + delta));
    select(next, { scroll: true, focus: true });
  }

  function activateSelection() {
    const entry = state.visible[state.selected];
    if (!entry) return;
    if (entry.kind === "dir") go(entry.path);
    else if (entry.kind === "file") {
      if (describe(entry).preview) openViewer(entry);
      else triggerDownload(entry);
    }
  }

  function triggerDownload(entry) {
    const link = h("a", { href: downloadUrl(entry.path), download: entry.name });
    document.body.append(link);
    link.click();
    link.remove();
  }

  const anyDialogOpen = () => document.querySelector("dialog[open]") !== null;

  document.addEventListener("keydown", (event) => {
    if (event.defaultPrevented || event.metaKey || event.ctrlKey || event.altKey) {
      if (event.altKey && event.key === "ArrowUp" && !anyDialogOpen() && state.path) {
        event.preventDefault();
        go(parentOf(state.path));
      }
      return;
    }
    if (el.viewer.open) {
      if (event.key === "ArrowRight") viewerStep(1);
      else if (event.key === "ArrowLeft") viewerStep(-1);
      return;
    }
    if (anyDialogOpen()) return;
    const typing = event.target instanceof HTMLInputElement;
    if (typing) {
      if (event.key === "Escape") {
        closeSearch();
        el.search.blur();
      } else if (event.key === "ArrowDown" || event.key === "Enter") {
        event.preventDefault();
        el.search.blur();
        if (event.key === "Enter" && state.visible.length === 1) {
          select(0);
          activateSelection();
        } else moveSelection(1);
      }
      return;
    }
    // Enter on a focused row is handled natively (link or button), not twice.
    if (event.key === "Enter" && event.target.closest?.("a, button")) return;
    const columns = gridColumns();
    switch (event.key) {
      case "/":
        event.preventDefault();
        openSearch();
        break;
      case "ArrowDown":
        event.preventDefault();
        moveSelection(columns);
        break;
      case "ArrowUp":
        event.preventDefault();
        moveSelection(-columns);
        break;
      case "ArrowRight":
        if (columns > 1) {
          event.preventDefault();
          moveSelection(1);
        }
        break;
      case "ArrowLeft":
        if (columns > 1) {
          event.preventDefault();
          moveSelection(-1);
        }
        break;
      case "Enter":
        if (state.selected >= 0) {
          event.preventDefault();
          activateSelection();
        }
        break;
      case "Backspace":
        if (state.path) {
          event.preventDefault();
          state.focusName = state.path.split("/").pop();
          go(parentOf(state.path));
        }
        break;
      case "Escape":
        select(-1);
        break;
      case "u":
      case "U":
        el.fileInput.click();
        break;
      case "n":
      case "N":
        event.preventDefault();
        openMkdir();
        break;
      case "v":
      case "V":
        toggleView();
        break;
      case "d":
      case "D": {
        const entry = state.visible[state.selected];
        if (entry && entry.kind === "file") triggerDownload(entry);
        break;
      }
      case "?":
        el.helpDialog.showModal();
        break;
      default:
    }
  });

  // --- search ---------------------------------------------------------------------------------------------------
  function openSearch() {
    el.topbar.classList.add("searching");
    setIcon(el.searchToggle, "close");
    el.search.focus();
    el.search.select();
  }

  function closeSearch() {
    el.search.value = "";
    state.filter = "";
    renderEntries();
    el.topbar.classList.remove("searching");
    setIcon(el.searchToggle, "search");
  }

  el.search.addEventListener("input", () => {
    state.filter = el.search.value;
    state.selected = -1;
    renderEntries();
  });
  el.search.addEventListener("blur", () => {
    if (!el.search.value) {
      el.topbar.classList.remove("searching");
      setIcon(el.searchToggle, "search");
    }
  });
  // pointerdown: act before the input's blur, which would otherwise close the search first
  el.searchToggle.addEventListener("pointerdown", (event) => event.preventDefault());
  el.searchToggle.addEventListener("click", () => {
    if (el.topbar.classList.contains("searching")) closeSearch();
    else openSearch();
  });

  el.listHead.addEventListener("click", (event) => {
    const button = event.target.closest(".sortable");
    if (!button) return;
    const key = button.dataset.sort;
    state.sort = { key, dir: state.sort.key === key ? -state.sort.dir : key === "name" ? 1 : -1 };
    store.set("sortKey", state.sort.key);
    store.set("sortDir", String(state.sort.dir));
    renderEntries();
  });

  // --- banner & toasts -------------------------------------------------------------------------------------------
  let bannerRetry = null;
  function showBanner(message, retry) {
    el.bannerText.textContent = message;
    bannerRetry = retry;
    el.banner.hidden = false;
  }
  function hideBanner() {
    el.banner.hidden = true;
  }
  el.bannerRetry.addEventListener("click", () => bannerRetry && bannerRetry());

  function toast(message, kind = "info", timeout = 4200) {
    const node = h("div", { class: `toast ${kind}`, role: kind === "error" ? "alert" : "status" }, icon(kind === "error" ? "alert" : "check"), h("span", { text: message }));
    el.toasts.append(node);
    while (el.toasts.children.length > 4) el.toasts.firstElementChild.remove();
    setTimeout(() => {
      node.classList.add("leaving");
      setTimeout(() => node.remove(), 220);
    }, timeout);
  }

  // --- new folder -------------------------------------------------------------------------------------------------
  function validateName(name) {
    if (!name.trim()) return "Donnez un nom au dossier.";
    if (name === "." || name === "..") return "Ce nom n'est pas autorisé.";
    if (/[/\\]/.test(name)) return "Un nom ne peut pas contenir « / » ni « \\ ».";
    // eslint-disable-next-line no-control-regex
    if (/[\u0000-\u001f\u007f]/.test(name)) return "Un nom ne peut pas contenir de caractères de contrôle.";
    if (name !== name.trim()) return "Un nom ne peut pas commencer ni finir par une espace.";
    if (new TextEncoder().encode(name).length > 255) return "Ce nom est trop long.";
    if (state.entries.some((e) => e.name === name)) return "Un élément porte déjà ce nom ici.";
    return "";
  }

  function openMkdir() {
    el.mkdirWhere.textContent = `Dans ${state.path ? `« ${state.path.split("/").pop()} »` : TITLE}`;
    el.mkdirName.value = "";
    el.mkdirName.removeAttribute("aria-invalid");
    el.mkdirError.textContent = "";
    el.mkdirSubmit.disabled = false;
    el.mkdirDialog.showModal();
    el.mkdirName.focus();
  }

  el.mkdirBtn.addEventListener("click", openMkdir);
  el.mkdirCancel.addEventListener("click", () => el.mkdirDialog.close());
  el.mkdirName.addEventListener("input", () => {
    el.mkdirName.removeAttribute("aria-invalid");
    el.mkdirError.textContent = "";
  });

  el.mkdirForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const name = el.mkdirName.value;
    const problem = validateName(name);
    if (problem) {
      el.mkdirName.setAttribute("aria-invalid", "true");
      el.mkdirError.textContent = problem;
      el.mkdirName.focus();
      return;
    }
    el.mkdirSubmit.disabled = true;
    try {
      await createFolder(state.path ?? "", name);
      el.mkdirDialog.close();
      toast(`Dossier « ${name} » créé`, "success");
      state.focusName = name;
      load(state.path ?? "");
    } catch (error) {
      el.mkdirName.setAttribute("aria-invalid", "true");
      el.mkdirError.textContent = error.message;
    } finally {
      el.mkdirSubmit.disabled = false;
    }
  });

  function createFolder(path, name) {
    return api("/api/mkdir", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-NAS-Request": "1" },
      body: JSON.stringify({ path, name }),
    });
  }

  // --- viewer --------------------------------------------------------------------------------------------------------
  let viewerEntry = null;

  function previewables() {
    return state.visible.filter((e) => e.kind === "file" && describe(e).preview);
  }

  async function openViewer(entry) {
    viewerEntry = entry;
    const info = describe(entry);
    const list = previewables();
    const position = list.findIndex((e) => e.path === entry.path);
    el.viewerName.textContent = entry.name;
    el.viewerMeta.textContent = `${formatSize(entry.size)} · ${dateFormat.format(new Date(entry.modified * 1000))}${list.length > 1 ? ` · ${position + 1}/${list.length}` : ""}`;
    el.viewerDownload.href = downloadUrl(entry.path);
    el.viewerDownload.setAttribute("download", entry.name);
    el.viewerPrev.hidden = el.viewerNext.hidden = list.length < 2;
    el.viewerStage.replaceChildren(h("div", { class: "spinner", role: "progressbar", "aria-label": "Chargement" }));
    if (!el.viewer.open) el.viewer.showModal();
    const index = state.visible.indexOf(entry);
    if (index >= 0) select(index);

    const src = downloadUrl(entry.path, true);
    const failed = () => {
      if (viewerEntry !== entry) return;
      el.viewerStage.replaceChildren(
        h("div", { class: "viewer-note" }, "Aperçu indisponible pour ce fichier. ", h("a", { href: downloadUrl(entry.path), download: entry.name, text: "Le télécharger" })),
      );
    };
    if (info.preview === "image") {
      const img = h("img", { alt: entry.name, src });
      img.addEventListener("load", () => viewerEntry === entry && el.viewerStage.replaceChildren(img));
      img.addEventListener("error", failed);
    } else if (info.preview === "video" || info.preview === "audio") {
      const media = h(info.preview, { src, controls: true, autoplay: true, preload: "metadata", playsinline: true });
      media.addEventListener("error", failed);
      el.viewerStage.replaceChildren(media);
    } else if (info.preview === "text") {
      try {
        const response = await fetch(src, { headers: { ...BASE_HEADERS, Range: `bytes=0-${TEXT_PREVIEW_BYTES - 1}` }, credentials: "same-origin" });
        if (!response.ok) throw new Error(String(response.status));
        const text = new TextDecoder("utf-8", { fatal: false }).decode(await response.arrayBuffer());
        if (viewerEntry !== entry) return;
        const nodes = [h("pre", { text })];
        if (entry.size > TEXT_PREVIEW_BYTES) nodes.push(h("p", { class: "viewer-note", text: `Aperçu limité aux ${formatSize(TEXT_PREVIEW_BYTES)} premiers octets.` }));
        el.viewerStage.replaceChildren(h("div", { class: "viewer-doc" }, ...nodes));
      } catch {
        failed();
      }
    }
  }

  function viewerStep(delta) {
    const list = previewables();
    if (list.length < 2 || !viewerEntry) return;
    const index = list.findIndex((e) => e.path === viewerEntry.path);
    openViewer(list[(index + delta + list.length) % list.length]);
  }

  function closeViewer() {
    viewerEntry = null;
    el.viewerStage.replaceChildren(); // stops media playback
    if (el.viewer.open) el.viewer.close();
  }

  el.viewerClose.addEventListener("click", closeViewer);
  el.viewer.addEventListener("close", () => {
    viewerEntry = null;
    el.viewerStage.replaceChildren();
    el.entries.children[state.selected]?.querySelector(".entry-main")?.focus({ preventScroll: true });
  });
  el.viewerPrev.addEventListener("click", () => viewerStep(-1));
  el.viewerNext.addEventListener("click", () => viewerStep(1));
  el.viewerStage.addEventListener("click", (event) => {
    if (event.target === el.viewerStage) closeViewer();
  });
  let touchStart = null;
  el.viewerStage.addEventListener("touchstart", (event) => (touchStart = event.touches[0].clientX), { passive: true });
  el.viewerStage.addEventListener("touchend", (event) => {
    if (touchStart === null) return;
    const dx = event.changedTouches[0].clientX - touchStart;
    touchStart = null;
    if (Math.abs(dx) > 60) viewerStep(dx < 0 ? 1 : -1);
  });

  el.helpBtn.addEventListener("click", () => el.helpDialog.showModal());

  // --- uploads --------------------------------------------------------------------------------------------------------
  const uploads = [];
  let activeUploads = 0;
  let uploadSeq = 0;

  function enqueue(files, path) {
    let added = 0;
    for (const file of files) {
      if (file.size > MAX_UPLOAD) {
        toast(`« ${file.name} » dépasse la taille maximale (${formatSize(MAX_UPLOAD)}).`, "error", 6000);
        continue;
      }
      uploads.push({ id: ++uploadSeq, file, path, name: file.name, loaded: 0, status: "queued", speed: 0, error: "", node: null });
      added += 1;
    }
    if (!added) return;
    el.uploads.hidden = false;
    el.uploads.classList.remove("collapsed");
    renderUploads();
    pump();
  }

  function pump() {
    while (activeUploads < PARALLEL_UPLOADS) {
      const next = uploads.find((u) => u.status === "queued");
      if (!next) break;
      startUpload(next);
    }
    renderUploadSummary();
  }

  function startUpload(upload) {
    activeUploads += 1;
    upload.status = "uploading";
    upload.loaded = 0;
    upload.error = "";
    const xhr = new XMLHttpRequest();
    upload.xhr = xhr;
    let lastTime = performance.now();
    let lastLoaded = 0;
    xhr.open("PUT", `/api/upload?${qs({ path: upload.path, name: upload.name })}`);
    xhr.setRequestHeader("X-NAS-Request", "1");
    xhr.setRequestHeader("ngrok-skip-browser-warning", "1");
    xhr.setRequestHeader("Content-Type", "application/octet-stream");
    xhr.upload.addEventListener("progress", (event) => {
      const now = performance.now();
      const elapsed = (now - lastTime) / 1000;
      if (elapsed >= 0.4) {
        const instant = (event.loaded - lastLoaded) / elapsed;
        upload.speed = upload.speed ? upload.speed * 0.7 + instant * 0.3 : instant;
        lastTime = now;
        lastLoaded = event.loaded;
      }
      upload.loaded = event.loaded;
      renderUpload(upload);
      renderUploadSummary();
    });
    xhr.addEventListener("load", () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        let result = {};
        try {
          result = JSON.parse(xhr.responseText);
        } catch {
          /* the upload succeeded anyway */
        }
        upload.status = "done";
        upload.loaded = upload.file.size;
        if (result.name && result.name !== upload.name) {
          upload.savedAs = result.name;
          toast(`« ${upload.name} » existait déjà : enregistré sous « ${result.name} ».`, "info", 6000);
        }
        if (upload.path === state.path) scheduleRefresh();
      } else {
        upload.status = "error";
        let message = `Erreur ${xhr.status}`;
        try {
          message = JSON.parse(xhr.responseText).message || message;
        } catch {
          if (xhr.status === 401) message = "Session expirée : rechargez la page.";
          else if (xhr.status === 413) message = "Fichier refusé : trop volumineux.";
        }
        upload.error = translate(message);
      }
      finishUpload(upload);
    });
    xhr.addEventListener("error", () => {
      upload.status = "error";
      upload.error = "Connexion interrompue.";
      finishUpload(upload);
    });
    xhr.addEventListener("abort", () => {
      upload.status = "cancelled";
      finishUpload(upload);
    });
    xhr.send(upload.file);
    renderUpload(upload);
  }

  function finishUpload(upload) {
    upload.xhr = null;
    activeUploads = Math.max(0, activeUploads - 1);
    renderUpload(upload);
    pump();
    if (!uploads.some((u) => u.status === "queued" || u.status === "uploading")) {
      const done = uploads.filter((u) => u.status === "done").length;
      const failed = uploads.filter((u) => u.status === "error").length;
      if (done && !failed) toast(done > 1 ? `${done} fichiers envoyés` : "Fichier envoyé", "success");
      else if (failed) toast(`${failed} envoi${failed > 1 ? "s" : ""} en échec`, "error");
    }
  }

  function cancelUpload(upload) {
    if (upload.status === "uploading" && upload.xhr) upload.xhr.abort();
    else if (upload.status === "queued") {
      upload.status = "cancelled";
      renderUpload(upload);
      renderUploadSummary();
    }
  }

  function retryUpload(upload) {
    upload.status = "queued";
    upload.loaded = 0;
    renderUpload(upload);
    pump();
  }

  function renderUploads() {
    for (const upload of uploads) {
      if (!upload.node) {
        upload.node = h("li", { class: "up" });
        el.uploadsList.append(upload.node);
      }
      renderUpload(upload);
    }
    renderUploadSummary();
  }

  function renderUpload(upload) {
    const node = upload.node;
    if (!node) return;
    const info = describe({ kind: "file", name: upload.name });
    const total = upload.file.size;
    const ratio = total ? upload.loaded / total : upload.status === "done" ? 1 : 0;
    let status;
    if (upload.status === "queued") status = "En attente…";
    else if (upload.status === "uploading") {
      const remaining = upload.speed > 0 ? (total - upload.loaded) / upload.speed : NaN;
      status = `${formatSize(upload.loaded)} / ${formatSize(total)}${upload.speed > 0 ? ` · ${formatSize(upload.speed)}/s · ${formatDuration(remaining)}` : ""}`;
    } else if (upload.status === "done") status = upload.savedAs ? `Enregistré sous « ${upload.savedAs} »` : `Envoyé · ${formatSize(total)}`;
    else if (upload.status === "cancelled") status = "Annulé";
    else status = upload.error || "Échec";
    const destination = upload.path ? ` → ${upload.path}` : "";
    const bar = h("span");
    bar.style.setProperty("width", `${Math.round(ratio * 100)}%`);
    const finished = upload.status === "done";
    const failed = upload.status === "error" || upload.status === "cancelled";
    const button = finished
      ? h("span", { class: "icon-btn small", "aria-hidden": "true" }, icon("check"))
      : failed
        ? h("button", { class: "icon-btn small", type: "button", "aria-label": `Réessayer ${upload.name}`, title: "Réessayer", onclick: () => retryUpload(upload) }, icon("retry"))
        : h("button", { class: "icon-btn small", type: "button", "aria-label": `Annuler ${upload.name}`, title: "Annuler", onclick: () => cancelUpload(upload) }, icon("close"));
    node.className = `up ${upload.status}`;
    node.replaceChildren(
      h("span", { class: `ficon k-${info.kind}` }, icon(info.icon)),
      h("div", { class: "up-body" }, h("div", { class: "up-name", text: upload.name, title: `${upload.name}${destination}` }), h("div", { class: "up-bar" }, bar), h("div", { class: "up-status", text: status })),
      button,
    );
  }

  function renderUploadSummary() {
    const pending = uploads.filter((u) => u.status === "queued" || u.status === "uploading");
    const counted = uploads.filter((u) => u.status !== "cancelled");
    const total = counted.reduce((sum, u) => sum + u.file.size, 0);
    const loaded = counted.reduce((sum, u) => sum + (u.status === "done" ? u.file.size : u.loaded), 0);
    const done = uploads.filter((u) => u.status === "done").length;
    el.uploadsTitle.textContent = pending.length ? `Envoi de ${pending.length} fichier${pending.length > 1 ? "s" : ""}` : "Envois terminés";
    el.uploadsSub.textContent = `${done}/${counted.length} · ${formatSize(loaded)} sur ${formatSize(total)}`;
    el.uploadsBar.style.setProperty("width", `${total ? Math.round((loaded / total) * 100) : 100}%`);
    el.uploadsClear.hidden = pending.length > 0;
  }

  el.uploadsClear.addEventListener("click", () => {
    for (let i = uploads.length - 1; i >= 0; i -= 1) {
      if (uploads[i].status !== "queued" && uploads[i].status !== "uploading") {
        uploads[i].node?.remove();
        uploads.splice(i, 1);
      }
    }
    if (!uploads.length) el.uploads.hidden = true;
    else renderUploadSummary();
  });

  el.uploadsCollapse.addEventListener("click", () => {
    const collapsed = el.uploads.classList.toggle("collapsed");
    el.uploadsCollapse.setAttribute("aria-expanded", String(!collapsed));
    el.uploadsCollapse.setAttribute("aria-label", collapsed ? "Déplier" : "Réduire");
  });

  window.addEventListener("beforeunload", (event) => {
    if (uploads.some((u) => u.status === "uploading" || u.status === "queued")) {
      event.preventDefault();
      event.returnValue = "";
    }
  });

  el.uploadBtn.addEventListener("click", () => el.fileInput.click());
  el.fileInput.addEventListener("change", () => {
    enqueue([...el.fileInput.files], state.path ?? "");
    el.fileInput.value = "";
  });

  // --- drag & drop (files and whole folders) -------------------------------------------------------------------------------
  let dragDepth = 0;
  let dropPath = null;
  const hasFiles = (event) => [...(event.dataTransfer?.types || [])].includes("Files");

  function enableDropTarget(node, path) {
    node.addEventListener("dragover", (event) => {
      if (!hasFiles(event)) return;
      event.preventDefault();
      event.stopPropagation();
      dropPath = path;
      node.classList.add("drop-target");
      el.dropzoneTarget.textContent = `dans « ${path ? path.split("/").pop() : TITLE} »`;
    });
    node.addEventListener("dragleave", () => node.classList.remove("drop-target"));
    node.addEventListener("drop", () => node.classList.remove("drop-target"));
  }

  window.addEventListener("dragenter", (event) => {
    if (!hasFiles(event) || anyDialogOpen()) return;
    event.preventDefault();
    dragDepth += 1;
    el.dropzone.hidden = false;
  });
  window.addEventListener("dragover", (event) => {
    if (!hasFiles(event)) return;
    event.preventDefault();
    if (dropPath === null || !event.target.closest?.(".drop-target")) {
      dropPath = null;
      el.dropzoneTarget.textContent = `dans « ${state.path ? state.path.split("/").pop() : TITLE} »`;
    }
  });
  window.addEventListener("dragleave", () => {
    dragDepth = Math.max(0, dragDepth - 1);
    if (!dragDepth) el.dropzone.hidden = true;
  });
  window.addEventListener("drop", async (event) => {
    if (!hasFiles(event)) return;
    event.preventDefault();
    dragDepth = 0;
    el.dropzone.hidden = true;
    const target = dropPath ?? state.path ?? "";
    dropPath = null;
    for (const node of document.querySelectorAll(".drop-target")) node.classList.remove("drop-target");
    const items = [...(event.dataTransfer.items || [])];
    const entries = items.map((item) => (item.webkitGetAsEntry ? item.webkitGetAsEntry() : null));
    if (entries.some((entry) => entry && entry.isDirectory)) {
      await dropTree(entries.filter(Boolean), target);
    } else {
      enqueue([...event.dataTransfer.files], target);
    }
  });

  const readEntries = (reader) => new Promise((resolve, reject) => reader.readEntries(resolve, reject));
  const entryFile = (entry) => new Promise((resolve, reject) => entry.file(resolve, reject));

  async function dropTree(entries, base) {
    const batches = new Map();
    let folders = 0;
    async function walk(entry, path) {
      if (entry.isFile) {
        const file = await entryFile(entry);
        if (!batches.has(path)) batches.set(path, []);
        batches.get(path).push(file);
      } else if (entry.isDirectory) {
        try {
          await createFolder(path, entry.name);
          folders += 1;
        } catch (error) {
          if (error.status !== 409) throw error; // an existing folder is simply reused
        }
        const childPath = joinPath(path, entry.name);
        const reader = entry.createReader();
        for (let batch = await readEntries(reader); batch.length; batch = await readEntries(reader)) {
          for (const child of batch) await walk(child, childPath);
        }
      }
    }
    try {
      for (const entry of entries) await walk(entry, base);
    } catch (error) {
      toast(error.message || "Impossible de lire le dossier déposé.", "error", 6000);
    }
    if (folders) toast(`${folders} dossier${folders > 1 ? "s" : ""} créé${folders > 1 ? "s" : ""}`, "success");
    for (const [path, files] of batches) enqueue(files, path);
    if (base === state.path) scheduleRefresh();
  }

  // --- start ------------------------------------------------------------------------------------------------------------------
  applyTheme();
  applyView();
  load(pathFromHash());
})();
