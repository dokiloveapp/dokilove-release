import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, chmod, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import test from "node:test";
import { openEnvelope, sealEnvelope } from "./bridge.mjs";
import { runHostedRelease } from "./run-release.mjs";

const key = Buffer.alloc(32, 0x58);
const sha = "b".repeat(40);
const uuid = "54d9c02c-761e-4415-9974-f0acde3693a3";
const privateValue = "private-build-config-canary";
const privateToken = "private-source-token-canary";

async function fixture(directory) {
  const root = join(directory, "fixture-source");
  const scripts = join(root, "scripts", "ci");
  const fakeBin = join(directory, "fake-bin");
  await mkdir(scripts, { recursive: true, mode: 0o700 });
  await mkdir(fakeBin, { recursive: true, mode: 0o700 });
  const fakeGit = [
    "#!/bin/sh",
    "set -eu",
    'if [ "$1" = "-c" ] && [ "$3" = "fetch" ]; then',
    "  /bin/cp -R " + JSON.stringify(root + "/.") + ' "$PWD"',
    "  exit 0",
    "fi",
    'if [ "$1" = "rev-parse" ]; then printf "%s\\n" "' + sha + '"; exit 0; fi',
    "exit 0",
    "",
  ].join("\n");
  await writeFile(join(fakeBin, "git"), fakeGit, { mode: 0o700 });
  await chmod(join(fakeBin, "git"), 0o700);

  const build = [
    "#!/bin/sh",
    "set -eu",
    'printf "private config=%s\\n" "$PRIVATE_BUILD_VALUE"',
    'printf "PRIVATE_VALUE=%s\\n" "$PRIVATE_BUILD_VALUE" >> "$GITHUB_ENV"',
    'printf "PRIVATE_OUTPUT=%s\\n" "$PRIVATE_BUILD_VALUE" >> "$GITHUB_OUTPUT"',
    'printf "# private summary %s\\n" "$PRIVATE_BUILD_VALUE" >> "$GITHUB_STEP_SUMMARY"',
    'printf "%s\\n" "$PRIVATE_BUILD_VALUE" >> "$GITHUB_PATH"',
    'printf "PRIVATE_STATE=%s\\n" "$PRIVATE_BUILD_VALUE" >> "$GITHUB_STATE"',
    'if [ "$PRIVATE_BUILD_FAIL" = "1" ]; then exit 37; fi',
    "node -e 'require(\"node:fs\").writeFileSync(process.env.HOSTED_RELEASE_RESULT_FILE,JSON.stringify({schema:1,source_sha:process.env.SOURCE_SHA,component:process.env.HOSTED_RELEASE_COMPONENT}))'",
    "",
  ].join("\n");
  await writeFile(join(scripts, "hosted-build.sh"), build, { mode: 0o700 });
  await writeFile(join(scripts, "hosted-deploy.sh"), "#!/bin/sh\nprintf 'private deployment stage\\n'\n", { mode: 0o700 });
  await chmod(join(scripts, "hosted-build.sh"), 0o700);
  await chmod(join(scripts, "hosted-deploy.sh"), 0o700);
  return { root, fakeBin };
}

function makeRequest(overrides = {}) {
  return {
    v: 1,
    id: uuid,
    source_repository: "private-company/application",
    source_sha: sha,
    component: "dokilove-web",
    tag: "",
    mode: "build",
    env: {
      ACCESS_TOKEN: privateToken,
      PRIVATE_BUILD_VALUE: privateValue,
      PRIVATE_BUILD_FAIL: "0",
    },
    ...overrides,
  };
}

async function runFixture({ request, fixturePaths, root }) {
  const oldPath = process.env.PATH;
  const outputFile = join(root, "github-output.txt");
  const oldOutput = process.env.GITHUB_OUTPUT;
  process.env.PATH = fixturePaths.fakeBin + delimiter + oldPath;
  process.env.GITHUB_OUTPUT = outputFile;
  const payload = sealEnvelope(request, key, "request");
  const statuses = [];
  const warnings = [];
  const maskCommands = [];
  const publicLines = [];
  const originalWrite = process.stdout.write;
  process.stdout.write = function (chunk, encoding, callback) {
    const text = Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk);
    if (text.startsWith("::add-mask::")) maskCommands.push(text);
    else publicLines.push(text);
    const done = typeof encoding === "function" ? encoding : callback;
    if (typeof done === "function") done();
    return true;
  };
  try {
    const result = await runHostedRelease({
      payload,
      requestId: request.id,
      bridgeKey: key,
      runnerTemp: root,
      status: (message) => statuses.push(message),
      failure: () => warnings.push("Release failed; encrypted diagnostics are available."),
    });
    return {
      result,
      statuses,
      warnings,
      maskCommands,
      publicText: publicLines.join(""),
      output: await readFile(outputFile, "utf8"),
    };
  } finally {
    process.stdout.write = originalWrite;
    process.env.PATH = oldPath;
    if (oldOutput === undefined) delete process.env.GITHUB_OUTPUT;
    else process.env.GITHUB_OUTPUT = oldOutput;
  }
}

test("a private build returns encrypted diagnostics and a result without printing private values", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "public-runner-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const fixturePaths = await fixture(root);
  const request = makeRequest();
  const result = await runFixture({ request, fixturePaths, root });
  const diagnostics = openEnvelope(
    (await readFile(join(root, "release-output", "diagnostics.enc"), "utf8")).trim(),
    key,
    "diagnostics",
  );

  assert.equal(
    result.result.ok,
    true,
    JSON.stringify({
      statuses: result.statuses,
      warnings: result.warnings,
      artifactReady: result.result.artifactReady,
      diagnosticSummary: diagnostics.logs.slice(-1_500).replaceAll(privateToken, "<token>"),
    }),
  );
  assert.equal(result.result.artifactReady, true);
  assert.deepEqual(result.statuses, [
    "Preparing release.",
    "Building release.",
    "Release complete.",
  ]);
  assert.equal(result.warnings.length, 0);
  assert.match(result.output, /^artifact_ready=true\n$/);
  assert.ok(!result.publicText.includes(request.source_repository));
  assert.ok(!result.publicText.includes(request.source_sha));
  assert.ok(!result.publicText.includes(privateToken));
  assert.ok(!result.publicText.includes(privateValue));
  assert.ok(result.maskCommands.some((line) => line.includes(privateToken)));
  assert.ok(result.maskCommands.some((line) => line.includes(request.source_repository)));

  const encryptedDiagnostics = await readFile(join(root, "release-output", "diagnostics.enc"), "utf8");
  assert.ok(!encryptedDiagnostics.includes(privateValue));
  assert.equal(diagnostics.status, "success");
  assert.ok(diagnostics.logs.includes(privateValue));
  assert.equal(diagnostics.source_repository, request.source_repository);
  assert.equal(
    diagnostics.workflow_command_files.GITHUB_ENV.trim(),
    "PRIVATE_VALUE=" + privateValue,
  );
  assert.equal(
    diagnostics.workflow_command_files.GITHUB_OUTPUT.trim(),
    "PRIVATE_OUTPUT=" + privateValue,
  );
  assert.ok(diagnostics.workflow_command_files.GITHUB_STEP_SUMMARY.includes(privateValue));
  assert.ok(diagnostics.workflow_command_files.GITHUB_PATH.includes(privateValue));
  assert.equal(
    diagnostics.workflow_command_files.GITHUB_STATE.trim(),
    "PRIVATE_STATE=" + privateValue,
  );
  assert.equal(result.output, "artifact_ready=true\n");
  assert.ok(!result.output.includes(privateValue));

  const encryptedResult = (await readFile(join(root, "release-output", "result.enc"), "utf8")).trim();
  assert.ok(!encryptedResult.includes(request.source_sha));
  const resultEnvelope = openEnvelope(encryptedResult, key, "result");
  assert.deepEqual(resultEnvelope.result, {
    schema: 1,
    source_sha: request.source_sha,
    component: request.component,
  });
});

test("a failed private probe keeps its source path and canary encrypted", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "public-runner-probe-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const fixturePaths = await fixture(root);
  const request = makeRequest({
    mode: "probe",
    tag: "",
    env: {
      ACCESS_TOKEN: privateToken,
      RELEASE_LOG_CANARY: "private-probe-canary",
      RELEASE_PROBE_FAIL: "1",
    },
  });
  const result = await runFixture({ request, fixturePaths, root });

  assert.equal(result.result.ok, false);
  assert.equal(result.result.artifactReady, true);
  assert.deepEqual(result.statuses, ["Preparing release."]);
  assert.deepEqual(result.warnings, ["Release failed; encrypted diagnostics are available."]);
  assert.ok(!result.publicText.includes(request.source_repository));
  assert.ok(!result.publicText.includes(request.source_sha));
  assert.ok(!result.publicText.includes(privateToken));
  assert.ok(!result.publicText.includes("private-probe-canary"));
  assert.ok(result.maskCommands.some((line) => line.includes("private-probe-canary")));

  const encryptedDiagnostics = (
    await readFile(join(root, "release-output", "diagnostics.enc"), "utf8")
  ).trim();
  assert.ok(!encryptedDiagnostics.includes("private-probe-canary"));
  const diagnostics = openEnvelope(encryptedDiagnostics, key, "diagnostics");
  assert.equal(diagnostics.status, "failure");
  assert.ok(diagnostics.logs.includes("private-probe-canary"));
  assert.ok(diagnostics.logs.includes("scripts/ci/hosted-build.sh"));
});
