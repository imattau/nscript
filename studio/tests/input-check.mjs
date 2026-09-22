import { chromium } from "playwright-core";

const chrome = process.env.CHROME_PATH;
const browser = await chromium.launch({ executablePath: chrome, headless: true });
const page = await browser.newPage();
const errors = [];
page.on("console", (msg) => {
  if (msg.type() === "error") errors.push(`console.error: ${msg.text()}`);
});
page.on("pageerror", (err) => errors.push(`pageerror: ${err.message}`));
page.on("response", (response) => {
  if (response.status() >= 400) {
    errors.push(`http ${response.status()} ${response.url()}`);
  }
});

await page.goto("http://localhost:4173/", { waitUntil: "networkidle" });
await page.waitForTimeout(1200);

const editorHost = page.locator("#editor .monaco-editor");
const marker = "marker_abc_123";
if ((await editorHost.count()) === 0) {
  console.log("FAIL: editor did not render");
  console.log("errors:", errors);
  process.exit(1);
}
await editorHost.click();
await page.keyboard.type(marker);
await page.waitForTimeout(400);

const text = await page.evaluate(() => {
  const el = document.querySelector(".view-lines");
  return el ? el.textContent : null;
});

const problems = await page.textContent("#problems-panel");
const buildButton = await page.locator("#build-button").count();
console.log("input accepted:", text?.includes(marker) ? "yes" : "no");
console.log("problems panel:", JSON.stringify(problems?.slice(0, 40)));
console.log("build button present:", buildButton > 0);
console.log("errors:", errors.length ? errors : "none");
await browser.close();
process.exit(text?.includes(marker) ? 0 : 1);