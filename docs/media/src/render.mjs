// Renders a recorded scenario (capture.sh) as an animated GIF and a still PNG of a terminal window.
// Every frame is a Chromium screenshot of terminal.html; ffmpeg assembles the GIF.
//   node docs/media/src/render.mjs docs/media/src/hero.json docs/media/hero           -> hero.gif + hero.png
//   node docs/media/src/render.mjs docs/media/src/sites.json docs/media/sites --still  -> sites.png, sized to its content
// Typing and the pauses between commands are animated; a wait longer than MAX_WAIT_MS is cut to
// that length (the README says so). The output text itself is the recorded one, unchanged.
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright-core";

const [, , scenarioPath, outBase, mode] = process.argv;
if (!scenarioPath || !outBase) {
  console.error("usage: render.mjs <scenario.json> <out-base> [--still]");
  process.exit(2);
}
const stillOnly = mode === "--still";
const here = dirname(fileURLToPath(import.meta.url));
const WIDTH = 1180;
const HEIGHT = 720;
const TYPE_MS = 28; // per frame, two characters each
const MAX_WAIT_MS = 1800;
const SPIN_MS = 90;
const HOLD_MS = 2600;
const FINAL_HOLD_MS = 5000;

const steps = JSON.parse(readFileSync(scenarioPath, "utf8"));
const page_html = readFileSync(join(here, "terminal.html"), "utf8");

const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

const COLORS = {
  30: "#5c6370",
  31: "#e06c75",
  32: "#98c379",
  33: "#e5c07b",
  34: "#61afef",
  35: "#c678dd",
  36: "#56b6c2",
  37: "#abb2bf",
  90: "#7f848e",
  91: "#e06c75",
  92: "#98c379",
  93: "#e5c07b",
  94: "#61afef",
  95: "#c678dd",
  96: "#56b6c2",
  97: "#ffffff",
};

/** jq's ANSI colors to spans. */
function ansiToHtml(text) {
  let out = "";
  let open = false;
  const re = /\x1b\[([0-9;]*)m/g;
  let last = 0;
  const push = (codes) => {
    if (open) out += "</span>";
    open = false;
    let bold = false;
    let color = null;
    for (const c of codes) {
      if (c === 1) bold = true;
      else if (c === 0 || c === 39) {
        /* default */
      } else if (COLORS[c]) color = COLORS[c];
    }
    if (bold && color === "#5c6370") color = COLORS[90];
    if (bold || color) {
      out += `<span style="${bold ? "font-weight:600;" : ""}${color ? `color:${color};` : ""}">`;
      open = true;
    }
  };
  for (const m of text.matchAll(re)) {
    out += esc(text.slice(last, m.index));
    last = m.index + m[0].length;
    push(m[1] === "" ? [0] : m[1].split(";").map(Number));
  }
  out += esc(text.slice(last));
  if (open) out += "</span>";
  return out;
}

/** The command line, lightly highlighted: the program, its subcommand, flags and quoted strings. */
function commandHtml(cmd) {
  return esc(cmd)
    .replace(/^api-anything (\w+)/, '<b class="prog">api-anything</b> <b class="sub">$1</b>')
    .replace(/(\s)(--[a-z0-9-]+)/g, '$1<span class="flag">$2</span>')
    .replace(/(&#39;|')((?:(?!\1).)*)\1/g, '<span class="str">$1$2$1</span>')
    .replace(/ \| (jq)/, ' <span class="pipe">|</span> <b class="sub">$1</b>');
}

const SPIN = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/** Frames: each is { html, ms } where html is the terminal's inner content. */
function frames() {
  const list = [];
  let history = "";
  const prompt = '<span class="prompt">❯</span> ';
  for (const step of steps) {
    const cmd = step.cmd.replace(/ \| jq -C /, " | jq ");
    for (let i = 2; i <= cmd.length + 1; i += 2) {
      const typed = cmd.slice(0, Math.min(i, cmd.length));
      list.push({
        html: `${history}<div class="line">${prompt}${commandHtml(typed)}<span class="cursor"></span></div>`,
        ms: TYPE_MS,
      });
    }
    const waitMs = Math.min(step.ms, MAX_WAIT_MS);
    const spins = Math.max(1, Math.round(waitMs / SPIN_MS));
    for (let s = 0; s < spins; s++) {
      list.push({
        html: `${history}<div class="line">${prompt}${commandHtml(cmd)}</div><div class="line dim">${SPIN[s % SPIN.length]} ${step.ms >= MAX_WAIT_MS ? "headless Chrome is loading the page for each example" : "sending"}</div>`,
        ms: SPIN_MS,
      });
    }
    history += `<div class="line">${prompt}${commandHtml(cmd)}</div><pre class="out">${ansiToHtml(step.out)}</pre>${step.ms >= 50 ? `<div class="time">${(step.ms / 1000).toFixed(1)} s</div>` : '<div class="time"></div>'}`;
    list.push({ html: `${history}<div class="line">${prompt}<span class="cursor"></span></div>`, ms: HOLD_MS });
  }
  list[list.length - 1].ms = FINAL_HOLD_MS;
  return list;
}

const dir = mkdtempSync(join(tmpdir(), "render-"));
const browser = await chromium.launch({ executablePath: process.env.API_ANYTHING_CHROME || undefined });
try {
  const all = frames();
  const page = await browser.newPage({ viewport: { width: WIDTH, height: HEIGHT }, deviceScaleFactor: 1 });
  await page.setContent(page_html);
  const listLines = [];
  for (let i = 0; i < (stillOnly ? 0 : all.length); i++) {
    await page.evaluate((html) => {
      const el = document.getElementById("screen");
      el.innerHTML = html;
      el.scrollTop = el.scrollHeight;
    }, all[i].html);
    const file = join(dir, `f${String(i).padStart(4, "0")}.png`);
    await page.screenshot({ path: file, type: "png" });
    listLines.push(`file '${file}'`, `duration ${(all[i].ms / 1000).toFixed(3)}`);
  }
  // the still: the final screen at 2x for a crisp README image; the window grows to fit it
  const still = await browser.newPage({ viewport: { width: WIDTH, height: 200 }, deviceScaleFactor: 2 });
  await still.setContent(page_html);
  await still.evaluate(
    (html) => {
      document.body.classList.add("auto");
      document.getElementById("screen").innerHTML = html;
    },
    all[all.length - 1].html,
  );
  await still.screenshot({ path: `${outBase}.png`, type: "png", fullPage: true });
  if (stillOnly) {
    console.log(`${resolve(outBase)}.png`);
  } else {
    listLines.push(`file '${join(dir, `f${String(all.length - 1).padStart(4, "0")}.png`)}'`);
    writeFileSync(join(dir, "list.txt"), `${listLines.join("\n")}\n`);
    const r = spawnSync(
      "ffmpeg",
      [
        "-y",
        "-loglevel",
        "error",
        "-f",
        "concat",
        "-safe",
        "0",
        "-i",
        join(dir, "list.txt"),
        "-fps_mode",
        "passthrough",
        "-vf",
        "split[a][b];[a]palettegen=max_colors=192:stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=5:diff_mode=rectangle",
        "-loop",
        "0",
        `${outBase}.gif`,
      ],
      { stdio: "inherit" },
    );
    if (r.status !== 0) throw new Error("ffmpeg failed");
    console.log(`${all.length} frames -> ${resolve(outBase)}.gif, ${resolve(outBase)}.png`);
  }
} finally {
  await browser.close();
  rmSync(dir, { recursive: true, force: true });
}
