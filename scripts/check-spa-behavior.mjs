// Behavioral check for the SPA's inline script: the server tells a client
// when it dropped events (`server.gap`, `server.lagged`), and the page has to
// refetch instead of showing a transcript that silently lost a turn.
//
// The SPA is one static HTML file with no build step and no test runner, so
// this loads the script into a stubbed DOM and drives the event handler.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const html = readFileSync(join(root, "crates/freedas-web/assets/index.html"), "utf8");
const script = html.split("<script>")[1]?.split("</script>")[0];
if (!script) throw new Error("no inline script in index.html");

const STRINGS = new Set(["value", "placeholder", "title", "type", "className", "id", "name"]);
const LISTS = new Set(["children", "options", "files"]);
const elements = new Map();

function makeElement(id) {
  const state = { textContent: "", innerHTML: "", hidden: false, disabled: false, open: false };
  const base = {
    dataset: {},
    style: {},
    classList: { add() {}, remove() {}, toggle() {}, contains: () => false },
    addEventListener() {},
    removeEventListener() {},
    append() {},
    appendChild() {},
    remove() {},
    replaceChildren() {},
    setAttribute() {},
    removeAttribute() {},
    querySelectorAll: () => [],
    closest: () => null,
    focus() {},
    blur() {},
    click() {},
    showModal() {
      state.open = true;
    },
    close() {
      state.open = false;
    },
    scrollIntoView() {},
    getBoundingClientRect: () => ({ top: 0, left: 0, width: 0, height: 0 }),
  };
  return new Proxy(base, {
    get(target, prop) {
      if (prop in target) return target[prop];
      if (typeof prop === "string" && STRINGS.has(prop)) return "";
      if (typeof prop === "string" && LISTS.has(prop)) return [];
      if (prop in state) return state[prop];
      return () => undefined;
    },
    set(target, prop, value) {
      if (prop in state) {
        state[prop] = value;
        return true;
      }
      return true;
    },
  });
}

function element(id) {
  if (!elements.has(id)) elements.set(id, makeElement(id));
  return elements.get(id);
}

globalThis.document = {
  getElementById: element,
  createElement: () => makeElement("created"),
  querySelectorAll: () => [],
  addEventListener() {},
  title: "",
  body: makeElement("body"),
  documentElement: makeElement("html"),
};
globalThis.window = {
  addEventListener() {},
  removeEventListener() {},
  location: { hash: "#/", pathname: "/" },
  localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
};
globalThis.location = { hash: "#/", pathname: "/" };
globalThis.localStorage = globalThis.window.localStorage;

const calls = [];
globalThis.fetch = async (url, options = {}) => {
  calls.push({ url: String(url), method: options.method || "GET", body: options.body });
  return {
    ok: true,
    status: 200,
    headers: { get: () => "application/json" },
    json: async () => ({}),
    text: async () => "",
  };
};

let source = null;
globalThis.EventSource = class {
  constructor(url) {
    this.url = url;
    source = this;
  }
  close() {}
  addEventListener() {}
};

new Function(`${script}\nglobalThis.__spa = { connect, state, resyncSession };`)();

const { connect, state } = globalThis.__spa;
state.hasEvents = true;
connect();
if (!source) throw new Error("the SPA never opened an event stream");
if (typeof source.onmessage !== "function") throw new Error("the SPA set no message handler");

function urlsSince(mark) {
  return calls.slice(mark).map((call) => call.url);
}

// A dropped event must send the client back to the server.
for (const type of ["server.lagged", "server.gap"]) {
  const mark = calls.length;
  await source.onmessage({ data: JSON.stringify({ type, dropped: 3 }) });
  const urls = urlsSince(mark);
  if (!urls.some((url) => url.includes("/session"))) {
    throw new Error(`a ${type} event must refetch the session list, got ${JSON.stringify(urls)}`);
  }
}

// Streamed text lands in the live area.
state.current = "ses_1";
await source.onmessage({
  data: JSON.stringify({
    type: "message.part.delta",
    sessionID: "ses_1",
    text: "hello world",
  }),
});
if (!element("live-text").textContent.includes("hello world")) {
  throw new Error(`the delta did not reach the transcript: ${element("live-text").textContent}`);
}

// A permission ask opens the modal with what the tool wants.
await source.onmessage({
  data: JSON.stringify({
    type: "permission.asked",
    sessionID: "ses_1",
    permissionID: "perm_1",
    action: "bash",
    resource: "git push",
  }),
});
const body = element("perm-body").textContent;
if (!body.includes("bash") || !body.includes("git push")) {
  throw new Error(`the permission modal does not name the ask: ${body}`);
}
if (!element("perm-dialog").open) {
  throw new Error("the permission modal did not open");
}

// The answer closes it again.
await source.onmessage({
  data: JSON.stringify({ type: "permission.replied", sessionID: "ses_1", permissionID: "perm_1" }),
});
if (element("perm-dialog").open) {
  throw new Error("the permission modal stayed open after the reply");
}

console.log("SPA event handling OK");
