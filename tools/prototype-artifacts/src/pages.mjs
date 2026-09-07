import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  lstat,
  mkdir,
  readdir,
  readFile,
  realpath,
  rename,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import {
  check,
  contentType,
  MAX_FILE_BYTES,
  parseManifest,
  safePath,
  sha256,
} from "./archive.mjs";

const exec = promisify(execFile);
const hashPattern = /^[a-f0-9]{64}$/;
// Leave headroom below the provider's 1 GB published-site limit. Never prune releases.
export const MAX_SITE_BYTES = 900 * 1024 * 1024;
export const MAX_SITE_FILES = 25000;
export const LANDING = Buffer.from(
  '<!doctype html><html lang="en"><meta charset="utf-8"><title>Prototype artifacts</title><h1>Public synthetic prototype artifacts</h1><p>Open the exact release URL supplied by the experimentation platform.</p></html>\n'
);
const controls = new Map([
  [".nojekyll", Buffer.alloc(0)],
  ["index.html", LANDING],
]);

async function statOrNull(file) {
  try {
    return await lstat(file);
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
}
async function regularBytes(file, limit = MAX_FILE_BYTES) {
  const stat = await lstat(file);
  check(
    stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1,
    "PAGES_LINK_OR_SPECIAL_FILE"
  );
  check(stat.size <= limit, "PAGES_FILE_LIMIT_EXCEEDED");
  const bytes = await readFile(file);
  check(bytes.length === stat.size, "PAGES_FILE_CHANGED_DURING_READ");
  return bytes;
}
async function git(root, args, options = {}) {
  return (
    await exec("git", ["-C", root, ...args], {
      encoding: "utf8",
      maxBuffer: 8 * 1024 * 1024,
      ...options,
    })
  ).stdout;
}
async function context(site, retainedRef = "HEAD") {
  const parent = await realpath(path.dirname(path.resolve(site)));
  const root = await realpath(
    (await git(parent, ["rev-parse", "--show-toplevel"])).trim()
  );
  check(
    root === parent && path.basename(site) === "public",
    "PAGES_DEDICATED_CHECKOUT_REQUIRED"
  );
  check(
    typeof retainedRef === "string" &&
      /^[A-Za-z0-9][A-Za-z0-9._/-]*$/.test(retainedRef),
    "INVALID_RETAINED_REF"
  );
  let retainedCommit;
  try {
    retainedCommit = (
      await git(root, ["rev-parse", "--verify", `${retainedRef}^{commit}`])
    ).trim();
  } catch {
    // Only a new repository without HEAD may start with no retained baseline.
    check(
      retainedRef === "HEAD" &&
        !(await git(root, ["rev-parse", "--verify", "HEAD"], {}).then(
          () => true,
          () => false
        )),
      "RETAINED_REF_NOT_FOUND"
    );
    check(
      !(await git(root, ["for-each-ref", "--format=%(refname)"])).trim(),
      "RETAINED_REF_NOT_FOUND"
    );
    retainedCommit = null;
  }
  return { root, site: path.join(root, "public"), retainedCommit };
}

/** Compare all previously committed public paths before any local staging mutation. */
async function assertRetained(ctx) {
  if (!ctx.retainedCommit) return 0;
  const entries = (
    await git(ctx.root, [
      "ls-tree",
      "-r",
      "-z",
      "--full-tree",
      ctx.retainedCommit,
      "--",
      "public/",
    ])
  )
    .split("\0")
    .filter(Boolean);
  check(entries.length <= MAX_SITE_FILES, "PAGES_SITE_LIMIT_EXCEEDED");
  for (const entry of entries) {
    const match = /^(100644) blob ([a-f0-9]{40,64})\t(public\/.+)$/.exec(entry);
    check(match, "PAGES_RETAINED_LINK_OR_MODE");
    const rel = match[3].slice("public/".length);
    check(rel === ".nojekyll" || safePath(rel), "PAGES_UNSAFE_RETAINED_PATH");
    const file = path.join(ctx.site, rel);
    check(await statOrNull(file), "PAGES_RETAINED_FILE_REMOVED");
    const previous = await git(ctx.root, ["cat-file", "blob", match[2]], {
      encoding: "buffer",
    });
    const current = await regularBytes(file);
    check(current.equals(previous), "PAGES_RETAINED_FILE_CHANGED");
  }
  return entries.length;
}

function validateTree(manifest, objects) {
  const tree = createHash("sha256");
  for (const file of manifest.files) {
    const bytes = objects.get(file.sha256);
    check(
      bytes && bytes.length === file.bytes && sha256(bytes) === file.sha256,
      "OBJECT_DIGEST_MISMATCH"
    );
    tree.update(file.path).update("\0").update(bytes).update("\0");
  }
  check(
    tree.digest("hex") === manifest.artifactDigest,
    "ARTIFACT_DIGEST_MISMATCH"
  );
  let build;
  try {
    build = JSON.parse(
      objects
        .get(
          manifest.files.find((f) => f.path === "platform-build.json").sha256
        )
        .toString("utf8")
    );
  } catch {
    throw new Error("INVALID_BUILD_PROVENANCE");
  }
  check(
    build.commit === manifest.sourceCommit && build.contractVersion === 1,
    "SOURCE_COMMIT_MISMATCH"
  );
}

export async function readSealedArchive(directory) {
  check(
    (await lstat(directory)).isDirectory() &&
      !(await lstat(directory)).isSymbolicLink(),
    "INVALID_ARCHIVE_DIRECTORY"
  );
  const root = await realpath(directory);
  const bytes = await regularBytes(
    path.join(root, "manifest.json"),
    1024 * 1024
  );
  const releaseId = sha256(bytes),
    manifest = parseManifest(bytes, releaseId),
    objects = new Map();
  check(
    (await lstat(path.join(root, "objects"))).isDirectory() &&
      !(await lstat(path.join(root, "objects"))).isSymbolicLink(),
    "PAGES_LINK_OR_SPECIAL_FILE"
  );
  const expected = new Set(manifest.files.map((f) => f.sha256));
  const actual = await readdir(path.join(root, "objects"));
  check(
    actual.length === expected.size &&
      actual.every((name) => expected.has(name)),
    "UNREFERENCED_OBJECT"
  );
  check(
    (await readdir(root)).sort().join(",") === "manifest.json,objects",
    "UNEXPECTED_ARCHIVE_FILE"
  );
  for (const digest of expected)
    objects.set(digest, await regularBytes(path.join(root, "objects", digest)));
  validateTree(manifest, objects);
  return { releaseId, manifest, bytes, objects };
}

async function scan(site) {
  const inventory = new Map();
  inventory.directories = new Set();
  if (!(await statOrNull(site))) return inventory;
  let total = 0;
  async function walk(directory, relative = "") {
    const stat = await lstat(directory);
    check(
      stat.isDirectory() && !stat.isSymbolicLink(),
      "PAGES_LINK_OR_SPECIAL_FILE"
    );
    for (const name of (await readdir(directory)).sort()) {
      const rel = relative ? `${relative}/${name}` : name;
      check(rel === ".nojekyll" || safePath(rel), "PAGES_UNSAFE_PATH");
      const file = path.join(directory, name),
        child = await lstat(file);
      check(!child.isSymbolicLink(), "PAGES_LINK_OR_SPECIAL_FILE");
      if (child.isDirectory()) {
        check(
          rel === "releases" ||
            rel === "manifests" ||
            /^releases\/[a-f0-9]{64}(\/.*)?$/.test(rel),
          "PAGES_UNEXPECTED_DIRECTORY"
        );
        inventory.directories.add(rel);
        await walk(file, rel);
      } else {
        const bytes = await regularBytes(file);
        total += bytes.length;
        check(
          total <= MAX_SITE_BYTES && inventory.size < MAX_SITE_FILES,
          "PAGES_SITE_LIMIT_EXCEEDED"
        );
        inventory.set(rel, bytes);
      }
    }
  }
  await walk(site);
  return inventory;
}

/** Validate closed file inventory, source provenance, file digests and full artifact trees. */
async function inspectSite(site, { incoming, initialize = false } = {}) {
  const inventory = await scan(site),
    expected = new Set(),
    releases = [];
  for (const [name, bytes] of controls) {
    expected.add(name);
    check(
      (initialize && !inventory.has(name)) ||
        inventory.get(name)?.equals(bytes),
      "PAGES_CONTROL_FILE_CHANGED"
    );
  }
  const ids = [...inventory.keys()]
    .filter((name) => /^manifests\/[a-f0-9]{64}\.json$/.test(name))
    .map((name) => path.posix.basename(name, ".json"));
  // A process interrupted between the atomic release rename and manifest write may
  // finish only the same fully verified archive. Other orphan files fail closed.
  if (
    incoming &&
    !ids.includes(incoming.releaseId) &&
    inventory.directories.has(`releases/${incoming.releaseId}`)
  )
    ids.push(incoming.releaseId);
  for (const id of ids.sort()) {
    const manifestPath = `manifests/${id}.json`,
      raw = inventory.get(manifestPath) ?? incoming.bytes;
    const manifest = parseManifest(raw, id),
      objects = new Map();
    expected.add(manifestPath);
    for (const file of manifest.files) {
      const name = `releases/${id}/${file.path}`,
        bytes = inventory.get(name);
      check(bytes, "PAGES_RELEASE_FILE_MISSING");
      expected.add(name);
      check(
        bytes.length === file.bytes && sha256(bytes) === file.sha256,
        "OBJECT_DIGEST_MISMATCH"
      );
      objects.set(file.sha256, bytes);
    }
    validateTree(manifest, objects);
    releases.push({ releaseId: id, manifest, bytes: raw });
  }
  check(
    [...inventory.keys()].every((name) => expected.has(name)),
    "PAGES_UNEXPECTED_FILE"
  );
  const expectedDirectories = new Set(["releases", "manifests"]);
  for (const file of expected) {
    for (
      let directory = path.posix.dirname(file);
      directory !== ".";
      directory = path.posix.dirname(directory)
    )
      expectedDirectories.add(directory);
  }
  check(
    [...inventory.directories].every((name) => expectedDirectories.has(name)),
    "PAGES_UNEXPECTED_DIRECTORY"
  );
  return { inventory, releases };
}

export async function checkPagesSite(site, { retainedRef = "HEAD" } = {}) {
  const ctx = await context(site, retainedRef);
  // Scan first so retained paths cannot be reached through an intermediate symlink.
  const checked = await inspectSite(ctx.site);
  const retainedFiles = await assertRetained(ctx);
  check(checked.releases.length > 0, "PAGES_EMPTY_SITE");
  return { ...ctx, ...checked, retainedFiles };
}

/** Add sealed public bytes only. This never commits, pushes, configures or deploys Pages. */
export async function stagePagesArchive(
  directory,
  site,
  { publicSynthetic = false, retainedRef = "HEAD" } = {}
) {
  check(publicSynthetic === true, "PUBLIC_SYNTHETIC_APPROVAL_REQUIRED");
  const archive = await readSealedArchive(directory),
    ctx = await context(site, retainedRef);
  const current = await inspectSite(ctx.site, {
    incoming: archive,
    initialize: true,
  });
  const retainedFiles = await assertRetained(ctx);
  const additions = new Map([
    [`manifests/${archive.releaseId}.json`, archive.bytes],
  ]);
  for (const file of archive.manifest.files)
    additions.set(
      `releases/${archive.releaseId}/${file.path}`,
      archive.objects.get(file.sha256)
    );
  for (const [name, bytes] of controls) additions.set(name, bytes);
  let total = [...current.inventory.values()].reduce((n, b) => n + b.length, 0),
    count = current.inventory.size;
  for (const [name, bytes] of additions) {
    if (current.inventory.has(name))
      check(
        current.inventory.get(name).equals(bytes),
        "PAGES_RETAINED_FILE_CHANGED"
      );
    else {
      total += bytes.length;
      count++;
    }
  }
  check(
    total <= MAX_SITE_BYTES && count <= MAX_SITE_FILES,
    "PAGES_SITE_LIMIT_EXCEEDED"
  );
  // Construct outside public. Interrupted preparation is never uploaded.
  const temporary = path.join(ctx.root, `.pages-stage-${archive.releaseId}`);
  if (!(await statOrNull(path.join(ctx.site, "releases", archive.releaseId)))) {
    await mkdir(temporary); // An existing preparation requires operator inspection.
    for (const file of archive.manifest.files) {
      await mkdir(path.dirname(path.join(temporary, file.path)), {
        recursive: true,
      });
      await writeFile(
        path.join(temporary, file.path),
        archive.objects.get(file.sha256),
        { flag: "wx", mode: 0o644 }
      );
    }
    await mkdir(path.join(ctx.site, "releases"), { recursive: true });
    await rename(temporary, path.join(ctx.site, "releases", archive.releaseId));
  }
  await mkdir(path.join(ctx.site, "manifests"), { recursive: true });
  for (const [name, bytes] of [
    [`manifests/${archive.releaseId}.json`, archive.bytes],
    ...controls,
  ]) {
    if (!(await statOrNull(path.join(ctx.site, name))))
      await writeFile(path.join(ctx.site, name), bytes, {
        flag: "wx",
        mode: 0o644,
      });
  }
  const verified = await checkPagesSite(ctx.site, { retainedRef });
  return {
    site: ctx.site,
    releaseId: archive.releaseId,
    artifactDigest: archive.manifest.artifactDigest,
    retainedCommit: ctx.retainedCommit,
    retainedFiles,
    releases: verified.releases.length,
    files: verified.inventory.size,
  };
}

export function pagesOrigin(value) {
  check(
    typeof value === "string" &&
      /^https:\/\/[A-Za-z0-9.-]+(?::443)?(?:\/[A-Za-z0-9_-]+)*\/?$/.test(value),
    "INVALID_PAGES_ORIGIN"
  );
  const url = new URL(value);
  check(
    url.protocol === "https:" &&
      !url.username &&
      !url.password &&
      !url.search &&
      !url.hash &&
      (!url.port || url.port === "443"),
    "INVALID_PAGES_ORIGIN"
  );
  return url.href.endsWith("/") ? url.href : `${url.href}/`;
}

function mimeMatches(name, actual) {
  if (typeof actual !== "string") return false;
  const parts = actual
    .toLowerCase()
    .split(";")
    .map((v) => v.trim());
  const expected = contentType(name).split(";")[0];
  const allowed =
    expected === "text/javascript"
      ? ["text/javascript", "application/javascript"]
      : expected === "image/x-icon"
        ? ["image/x-icon", "image/vnd.microsoft.icon"]
        : [expected];
  // Pages sets MIME by extension. Only equivalent registered types and optional
  // UTF-8 are accepted; raw text HTML and fallback HTML JavaScript are rejected.
  return (
    allowed.includes(parts[0]) &&
    parts.slice(1).every((p) => /^charset=(?:utf-8|"utf-8")$/.test(p))
  );
}

async function readResponse(response, maxBytes) {
  const chunks = [],
    reader = response.body?.getReader();
  if (!reader) return Buffer.alloc(0);
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      check(size <= maxBytes, "HOSTED_DIGEST_MISMATCH");
      chunks.push(value);
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  return Buffer.concat(chunks);
}

/** Anonymous all-release readback. No redirect, credentials, HTML rewrite or digest normalization. */
export async function verifyPagesSite(
  site,
  origin,
  { retainedRef = "HEAD", fetchImpl = fetch } = {}
) {
  const base = pagesOrigin(origin),
    checked = await checkPagesSite(site, { retainedRef }),
    files = [];
  for (const [name, expected] of checked.inventory) {
    if (name === ".nojekyll") continue; // Build control, not a browser asset.
    const url = new URL(name, base).href;
    let response;
    try {
      response = await fetchImpl(url, {
        redirect: "error",
        credentials: "omit",
        headers: { "accept-encoding": "identity" },
        signal: AbortSignal.timeout(20000),
      });
    } catch {
      throw new Error("HOSTED_READBACK_FAILED");
    }
    check(
      response.status === 200 &&
        !response.redirected &&
        mimeMatches(name, response.headers.get("content-type")),
      "HOSTED_READBACK_FAILED"
    );
    const body = await readResponse(response, expected.length);
    check(
      body.length === expected.length && sha256(body) === sha256(expected),
      "HOSTED_DIGEST_MISMATCH"
    );
    files.push({
      path: name,
      bytes: expected.length,
      sha256: sha256(expected),
      contentType: response.headers.get("content-type"),
    });
  }
  return {
    origin: base,
    retainedCommit: checked.retainedCommit,
    verifiedAt: new Date().toISOString(),
    releases: checked.releases.map(({ releaseId, manifest }) => ({
      releaseId,
      artifactDigest: manifest.artifactDigest,
      artifactUrl: new URL(`releases/${releaseId}/index.html`, base).href,
    })),
    hostedFilesVerified: files.length,
    files,
  };
}
