#!/usr/bin/env node
import { check } from "../src/archive.mjs";
import {
  checkPagesSite,
  stagePagesArchive,
  verifyPagesSite,
} from "../src/pages.mjs";

const args = process.argv.slice(2);
function option(name, required = true) {
  const index = args.indexOf(`--${name}`);
  if (index < 0 && !required) return undefined;
  check(
    index >= 0 && args[index + 1] && !args[index + 1].startsWith("--"),
    "MISSING_OPTION"
  );
  return args[index + 1];
}
async function main() {
  if (!args.length || args.includes("--help")) {
    console.log(`pages stage --archive SEALED_DIRECTORY --site DEDICATED_CHECKOUT/public --public-synthetic [--retained-ref COMMIT]
pages check --site DEDICATED_CHECKOUT/public [--retained-ref COMMIT]
pages verify --site DEDICATED_CHECKOUT/public --origin https://OWNER.github.io/REPO/ [--retained-ref COMMIT]

Stage is offline and add-only. It never commits, pushes, creates a repository or deploys.
The default retained ref is HEAD; after initial publication pin the last verified
published commit. Keep every earlier release in public/. A complete site check must
pass before uploading only public/ as the Pages artifact. Verify anonymously fetches
every release file with exact byte digests and browser-compatible MIME types.
Only inspected and explicitly approved public synthetic materials are supported.`);
    return;
  }
  const site = option("site"),
    retainedRef = option("retained-ref", false) ?? "HEAD";
  let result;
  if (args[0] === "stage")
    result = await stagePagesArchive(option("archive"), site, {
      retainedRef,
      publicSynthetic: args.includes("--public-synthetic"),
    });
  else if (args[0] === "check") {
    const checked = await checkPagesSite(site, { retainedRef });
    result = {
      site: checked.site,
      retainedCommit: checked.retainedCommit,
      retainedFiles: checked.retainedFiles,
      releases: checked.releases.map((r) => r.releaseId),
      files: checked.inventory.size,
    };
  } else if (args[0] === "verify")
    result = await verifyPagesSite(site, option("origin"), { retainedRef });
  else throw new Error("UNKNOWN_COMMAND");
  console.log(JSON.stringify(result));
}
main().catch((error) => {
  const code = /^[A-Z][A-Z0-9_]+$/.test(error.message)
    ? error.message
    : "PAGES_OPERATION_FAILED";
  console.error(JSON.stringify({ error: { code } }));
  process.exitCode = 1;
});
