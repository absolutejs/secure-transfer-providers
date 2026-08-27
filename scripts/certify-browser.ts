import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { chromium, type Browser } from "playwright";

type CertificationResult = { readonly error?: string; readonly ok: boolean };

const root = new URL("..", import.meta.url).pathname;
const output = await mkdtemp(join(tmpdir(), "absolute-secure-transfer-"));
let browser: Browser | undefined;
try {
  const build = await Bun.build({
    entrypoints: [join(root, "webcrypto/tests/browser.ts")],
    minify: true,
    outdir: output,
    target: "browser",
  });
  if (!build.success)
    throw new AggregateError(build.logs, "Browser certification build failed.");
  browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  await page.route("https://certification.absolutejs.invalid/", (route) =>
    route.fulfill({ body: "<!doctype html>", contentType: "text/html" }),
  );
  await page.goto("https://certification.absolutejs.invalid/");
  await page.addScriptTag({
    content: await readFile(join(output, "browser.js"), "utf8"),
  });
  const result = await page.evaluate(async () => {
    const scope = globalThis as typeof globalThis & {
      __absoluteSecureTransferCertification?: Promise<CertificationResult>;
    };
    return (
      scope.__absoluteSecureTransferCertification ??
      Promise.resolve({ error: "Certification promise missing.", ok: false })
    );
  });
  if (!result.ok)
    throw new Error(`Browser certification failed: ${result.error}`);
  process.stdout.write(
    "secure-transfer-webcrypto: Chromium certification passed\n",
  );
} finally {
  await browser?.close();
  await rm(output, { force: true, recursive: true });
}
