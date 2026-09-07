import { createHash } from "node:crypto";
import { lstat, readdir, readFile, realpath } from "node:fs/promises";
import path from "node:path";

export const STORE_NAME = "public-synthetic-artifacts-v1";
export const MAX_FILE_BYTES = 4 * 1024 * 1024;
export const MAX_TOTAL_BYTES = 64 * 1024 * 1024;
export const MAX_FILES = 2000;
export const sha256 = (bytes) =>
  createHash("sha256").update(bytes).digest("hex");
const types = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".webp": "image/webp",
  ".ico": "image/x-icon",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
};
export function check(condition, code) {
  if (!condition) throw new Error(code);
}
export function safePath(value) {
  return (
    typeof value === "string" &&
    value.length <= 240 &&
    /^[A-Za-z0-9_-][A-Za-z0-9_./-]*$/.test(value) &&
    value.split("/").every((part) => part && !part.startsWith("."))
  );
}
export function contentType(name) {
  return types[path.posix.extname(name)];
}
const digestPattern = /^[a-f0-9]{64}$/;

export function parseManifest(raw, releaseId) {
  check(
    raw.length <= 1024 * 1024 &&
      digestPattern.test(releaseId) &&
      sha256(raw) === releaseId,
    "MANIFEST_DIGEST_MISMATCH"
  );
  let m;
  try {
    m = JSON.parse(Buffer.from(raw).toString("utf8"));
  } catch {
    throw new Error("INVALID_MANIFEST");
  }
  check(
    m?.version === 1 &&
      m.visibility === "public-synthetic" &&
      /^[a-f0-9]{40}$/.test(m.sourceCommit) &&
      digestPattern.test(m.artifactDigest),
    "INVALID_MANIFEST"
  );
  check(
    Array.isArray(m.files) && m.files.length > 0 && m.files.length <= MAX_FILES,
    "INVALID_FILE_INVENTORY"
  );
  let total = 0;
  const seen = new Set();
  for (const f of m.files) {
    check(
      f &&
        safePath(f.path) &&
        !seen.has(f.path) &&
        contentType(f.path) &&
        f.contentType === contentType(f.path) &&
        digestPattern.test(f.sha256) &&
        Number.isSafeInteger(f.bytes) &&
        f.bytes >= 0 &&
        f.bytes <= MAX_FILE_BYTES,
      "INVALID_FILE_INVENTORY"
    );
    seen.add(f.path);
    total += f.bytes;
  }
  check(
    seen.has("index.html") &&
      seen.has("platform-build.json") &&
      total <= MAX_TOTAL_BYTES,
    "INCOMPLETE_RELEASE"
  );
  return m;
}

/** Seal an explicitly approved public/synthetic dist. Never build or execute prototype source. */
export async function sealDirectory(
  directory,
  { sourceCommit, publicSynthetic = false }
) {
  check(publicSynthetic === true, "PUBLIC_SYNTHETIC_APPROVAL_REQUIRED");
  check(/^[a-f0-9]{40}$/.test(sourceCommit), "INVALID_SOURCE_COMMIT");
  check(
    (await lstat(directory)).isDirectory() &&
      !(await lstat(directory)).isSymbolicLink(),
    "INVALID_BUILD_DIRECTORY"
  );
  const root = await realpath(directory);
  const objects = new Map(),
    files = [],
    tree = createHash("sha256");
  let total = 0;
  async function walk(relative = "") {
    for (const name of (await readdir(path.join(root, relative))).sort()) {
      const rel = relative ? `${relative}/${name}` : name;
      check(safePath(rel), "UNSAFE_BUILD_PATH");
      const file = path.join(root, rel),
        stat = await lstat(file);
      check(!stat.isSymbolicLink(), "BUILD_LINK_REJECTED");
      if (stat.isDirectory()) {
        await walk(rel);
        continue;
      }
      check(stat.isFile() && contentType(rel), "UNSUPPORTED_BUILD_FILE");
      check(
        stat.size <= MAX_FILE_BYTES && files.length < MAX_FILES,
        "BUILD_LIMIT_EXCEEDED"
      );
      const bytes = await readFile(file);
      check(bytes.length === stat.size, "BUILD_CHANGED_DURING_READ");
      total += bytes.length;
      check(total <= MAX_TOTAL_BYTES, "BUILD_LIMIT_EXCEEDED");
      const hash = sha256(bytes);
      objects.set(hash, bytes);
      files.push({
        path: rel,
        sha256: hash,
        bytes: bytes.length,
        contentType: contentType(rel),
      });
      // Same tree digest algorithm as the portable platform candidate CLI.
      tree.update(rel);
      tree.update("\0");
      tree.update(bytes);
      tree.update("\0");
    }
  }
  await walk();
  const metadata = files.find((f) => f.path === "platform-build.json");
  check(metadata, "MISSING_BUILD_PROVENANCE");
  let provenance;
  try {
    provenance = JSON.parse(objects.get(metadata.sha256).toString("utf8"));
  } catch {
    throw new Error("INVALID_BUILD_PROVENANCE");
  }
  check(
    provenance.commit === sourceCommit && provenance.contractVersion === 1,
    "SOURCE_COMMIT_MISMATCH"
  );
  const manifest = {
    version: 1,
    visibility: "public-synthetic",
    sourceCommit,
    artifactDigest: tree.digest("hex"),
    files,
  };
  const bytes = Buffer.from(JSON.stringify(manifest));
  const releaseId = sha256(bytes);
  parseManifest(bytes, releaseId);
  return { releaseId, manifest, bytes, objects };
}

/** Read back every content-addressed write. Identical retries are safe; never replace conflicting bytes. */
async function putVerified(store, key, bytes) {
  const existing = await store.get(key, {
    type: "arrayBuffer",
    consistency: "strong",
  });
  if (existing !== null)
    check(Buffer.from(existing).equals(bytes), "STORED_CONTENT_CONFLICT");
  else await store.set(key, Uint8Array.from(bytes).buffer);
  const persisted = await store.get(key, {
    type: "arrayBuffer",
    consistency: "strong",
  });
  check(
    persisted !== null && Buffer.from(persisted).equals(bytes),
    "STORED_CONTENT_VERIFICATION_FAILED"
  );
}

export async function publishArchive(store, archive) {
  const manifest = parseManifest(archive.bytes, archive.releaseId);
  const tree = createHash("sha256");
  for (const file of manifest.files) {
    const bytes = archive.objects.get(file.sha256);
    check(
      bytes && bytes.length === file.bytes && sha256(bytes) === file.sha256,
      "OBJECT_DIGEST_MISMATCH"
    );
    tree.update(file.path);
    tree.update("\0");
    tree.update(bytes);
    tree.update("\0");
  }
  check(
    tree.digest("hex") === manifest.artifactDigest,
    "ARTIFACT_DIGEST_MISMATCH"
  );
  for (const [digest, bytes] of archive.objects) {
    check(
      manifest.files.some((file) => file.sha256 === digest) &&
        sha256(bytes) === digest,
      "UNREFERENCED_OBJECT"
    );
    await putVerified(store, `objects/${digest}`, bytes);
  }
  // Publication marker last: a partial upload can never make a release available.
  await putVerified(store, `releases/${archive.releaseId}`, archive.bytes);
  return {
    releaseId: archive.releaseId,
    artifactDigest: manifest.artifactDigest,
    files: manifest.files.length,
  };
}
