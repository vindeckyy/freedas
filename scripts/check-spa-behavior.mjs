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

const STRINGS = new Set(["textContent", "innerHTML", "value", "placeholder", "title", "type", "className", "id", "name"]);
const LISTS = new Set(["children", "options", "files"]);
const node = () =>
  new Proxy(
    {
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
      close() {},
      showModal() {},
      scrollIntoView() {},
      getBoundingClientRect: () => ({ top: 0, left: 0, width: 0, height: 0 }),
    },
    {
      get(target, prop) {
        if (prop in target) return target[prop];
        if (typeof prop === "string" && STRINGS.has(prop)) return "";
        if (typeof prop === "string" && LISTS.has(prop)) return [];
        return () => undefined;
      },
      set() {
        return true;
      },
    },
  );

const calls = [];
let sources = [];
globalThis.document = {
  getElementById: () => node(),
  createElement: () => node(),
  querySelectorAll: () => [],
  addEventListener() {},
  title: "",
  body: node(),
  documentElement: node(),
};
globalThis.window = {
  addEventListener() {},
  removeEventListener() {},
  location: { hash: "#/", pathname: "/" },
  localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
};
globalThis.location = { hash: "#/", pathname: "/" };
globalThis.localStorage = globalThis.window.localStorage;
globalThis.fetch = async (url) => {
  calls.push(String(url));
  return {
    ok: true,
    status: 200,
    headers: { get: () => "application/json" },
    json: async () => ({}),
    text: async () => "",
  };
};
globalThis.EventSource = class {
  constructor(url) {
    this.url = url;
    sources.push(this);
  }
  close() {}
  addEventListener() {}
};

new Function(`${script}\nglobalThis.__spa = { connect, state, resyncSession };`)();

const { connect, state } = globalThis.__spa;
state.hasEvents = true;
connect();
const es = sources[0];
if (!es) throw new Error("the SPA never opened an event stream");
if (typeof es.onmessage !== "function") throw new Error("the SPA set no message handler");

const before = calls.length;
await es.onmessage({ data: JSON.stringify({ type: "server.lagged" }) });
const after = calls.slice(before);
if (!after.some((url) => url.includes("/session"))) {
  throw new Error(`a lagged event must refetch the session list, got ${JSON.stringify(after)}`);
}

const beforeGap = calls.length;
await es.onmessage({ data: JSON.stringify({ type: "server.gap" }) });
const afterGap = calls.slice(beforeGap);
if (!afterGap.some((url) => url.includes("/session"))) {
  throw new Error(`a gap event must refetch the session list, got ${JSON.stringify(afterGap)}`);
}

console.log(`SPA event handling OK (${after.length + afterGap.length} refetches)`);
