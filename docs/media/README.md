# Recordings

The GIF and the stills in the README were made on 2026-10-10 from the Rust binary (`cargo build
--release` at the commit that added them) against the live sites, with Chromium 1194 (the
Playwright build) as the Chrome. Each command ran once in a fresh `API_ANYTHING_HOME`, and the
text you see is what it printed. Only the typing is animated, and a wait longer than 1.8 s
(headless Chrome loading the page for each `add` example, 7 s) is shown cut to that length.
They are dated results: they don't show that a site answers the same way today.

| file | what it shows | commands |
|---|---|---|
| `hero.gif`, `hero.png` | teach Hacker News an operation, call it, then three bundled sites | `src/hero.txt` |
| `teach.png` | the first two commands of the hero, as a still | `src/hero.txt` (first two lines) |
| `sites.png` | `sites` and `ops goodreads` | `src/sites.txt` |
| `errors.png` | a wrong argument, a missing parameter and a rate limit | `src/errors.txt` |

`jq` only formats the output. Without it, each command prints one line of JSON.

## Re-record

```sh
cd rust && cargo build --release && cd ..
export API_ANYTHING_CHROME=/path/to/chrome     # optional; Google Chrome is found on its own
docs/media/src/capture.sh docs/media/src/hero.txt docs/media/src/hero.json
node docs/media/src/render.mjs docs/media/src/hero.json docs/media/hero            # hero.gif + hero.png
jq '.[:2]' docs/media/src/hero.json > docs/media/src/teach.json
node docs/media/src/render.mjs docs/media/src/teach.json docs/media/teach --still  # a still, sized to its content
```

`capture.sh` runs each line of the command file for real and records its output and timing as
JSON. `render.mjs` draws each frame as an HTML terminal window (`terminal.html`) in headless
Chromium through the repository's `playwright-core`, and `ffmpeg` assembles the GIF. The
benchmark charts and the agent race video in this directory come from the upstream project's
[benchmark](../../bench/README.md).
