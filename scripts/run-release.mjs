#!/usr/bin/env node
import { spawn } from "node:child_process";
import { createWriteStream } from "node:fs";
import {
  chmod,
  mkdir,
  mkdtemp,
  open,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  decodeKey,
  openEnvelope,
  sealEnvelope,
  validateRequest,
} from "./bridge.mjs";

const MAX_DIAGNOSTICS = 64 * 1024 * 1024;
const SOURCE_CREDENTIALS = [
  "SOURCE_ACCESS_TOKEN",
  "ACCESS_TOKEN",
];

function escapeWorkflowCommandValue(value) {
  return value
    .replaceAll("%", "%25")
    .replaceAll("\r", "%0D")
    .replaceAll("\n", "%0A");
}

function registerMask(value) {
  if (typeof value !== "string" || value.length === 0) return;
  process.stdout.write("::add-mask::" + escapeWorkflowCommandValue(value) + "\n");
}

function maskRequest(request, accessToken) {
  for (const value of [
    request.id,
    request.source_repository,
    request.source_sha,
    request.tag,
    accessToken,
    ...Object.values(request.env),
  ]) {
    registerMask(value);
    for (const part of value.split(/\r?\n/)) {
      if (part.length >= 3) registerMask(part);
    }
  }
}

function fixedStatus(message) {
  process.stdout.write(message + "\n");
}

function fixedFailure(artifactReady) {
  process.stderr.write(
    artifactReady
      ? "Release failed; encrypted diagnostics are available.\n"
      : "Release failed before encrypted diagnostics could be saved.\n",
  );
}

function fixedRequestFailure() {
  process.stderr.write("Release request rejected before private source checkout.\n");
}

async function finishWrite(stream) {
  await new Promise((resolveDone, rejectDone) => {
    stream.end((error) => (error ? rejectDone(error) : resolveDone()));
  });
}

async function appendDiagnostic(stream, source, chunk, budget) {
  if (budget.remaining <= 0) {
    budget.truncated = true;
    return;
  }
  const prefix = Buffer.from(source === "stdout" ? "[stdout] " : "[stderr] ", "utf8");
  const separator = Buffer.from("\n", "utf8");
  const data = Buffer.concat([prefix, chunk, separator]);
  const content = data.subarray(0, budget.remaining);
  budget.remaining -= content.length;
  if (content.length !== data.length) budget.truncated = true;
  if (!stream.write(content)) {
    await new Promise((resolveDrain) => stream.once("drain", resolveDrain));
  }
}

async function runPrivateProcess({
  command,
  args,
  cwd,
  env,
  logStream,
  budget,
}) {
  const child = spawn(command, args, {
    cwd,
    env,
    shell: false,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdoutOutput = "";
  const returnedOutputLimit = 256;
  const pending = [
    (async () => {
      for await (const chunk of child.stdout) {
        if (stdoutOutput.length < returnedOutputLimit) {
          stdoutOutput += chunk
            .toString("utf8")
            .slice(0, returnedOutputLimit - stdoutOutput.length);
        }
        await appendDiagnostic(logStream, "stdout", chunk, budget);
      }
    })(),
    (async () => {
      for await (const chunk of child.stderr) {
        await appendDiagnostic(logStream, "stderr", chunk, budget);
      }
    })(),
  ];
  const result = await new Promise((resolveChild, rejectChild) => {
    child.once("error", rejectChild);
    child.once("close", (code, signal) => resolveChild({ code, signal }));
  });
  await Promise.all(pending);
  return { ...result, stdout: stdoutOutput };
}

async function privateChildEnvironment(request, accessToken, workspace, sourceDirectory) {
  const commandDirectory = join(workspace, "workflow-command-files");
  await mkdir(commandDirectory, { mode: 0o700 });
  const workflowFiles = {};
  const commandPaths = {};
  for (const name of ["GITHUB_ENV", "GITHUB_OUTPUT", "GITHUB_PATH", "GITHUB_STEP_SUMMARY", "GITHUB_STATE"]) {
    const path = join(commandDirectory, name.toLowerCase());
    await writeFile(path, "", { encoding: "utf8", mode: 0o600, flag: "wx" });
    workflowFiles[name] = path;
    commandPaths[name] = path;
  }
  const isolated = {
    docker: join(workspace, "docker-config"),
    gh: join(workspace, "gh-config"),
    xdg: join(workspace, "xdg-config"),
    cache: join(workspace, "cache"),
  };
  await Promise.all(
    Object.values(isolated).map((path) => mkdir(path, { mode: 0o700 })),
  );
  const env = {
    PATH: process.env.PATH ?? "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    ...(typeof process.env.HOME === "string" ? { HOME: process.env.HOME } : {}),
    LANG: "C.UTF-8",
    LC_ALL: "C.UTF-8",
    CI: "true",
    TMPDIR: join(workspace, "tmp"),
    TEMP: join(workspace, "tmp"),
    RUNNER_TEMP: workspace,
    DOCKER_CONFIG: isolated.docker,
    GH_CONFIG_DIR: isolated.gh,
    XDG_CONFIG_HOME: isolated.xdg,
    XDG_CACHE_HOME: isolated.cache,
    COREPACK_HOME: join(isolated.cache, "corepack"),
    GITHUB_WORKSPACE: sourceDirectory,
    GITHUB_REPOSITORY: request.source_repository,
    GITHUB_REPOSITORY_OWNER: request.source_repository.split("/")[0],
    GITHUB_SHA: request.source_sha,
    GITHUB_REF: request.tag ? "refs/tags/" + request.tag : "refs/heads/" + request.source_sha,
    GITHUB_SERVER_URL: "https://github.com",
    GITHUB_WORKFLOW: "Release",
    GITHUB_ACTOR: process.env.GITHUB_ACTOR ?? "",
    GITHUB_RUN_ID: process.env.GITHUB_RUN_ID ?? request.id,
    GITHUB_RUN_ATTEMPT: process.env.GITHUB_RUN_ATTEMPT ?? "1",
    ...commandPaths,
    ...request.env,
  };
  for (const name of SOURCE_CREDENTIALS) delete env[name];
  env.ACCESS_TOKEN = accessToken;
  env.SOURCE_ACCESS_TOKEN = accessToken;
  env.GH_TOKEN = accessToken;
  env.GITHUB_TOKEN = accessToken;
  env.GH_REPO = request.source_repository;
  env.GH_HOST = "github.com";
  env.SOURCE_REPOSITORY = request.source_repository;
  env.SOURCE_SHA = request.source_sha;
  env.HOSTED_RELEASE_SOURCE_SHA = request.source_sha;
  env.HOSTED_RELEASE_COMPONENT = request.component;
  env.HOSTED_RELEASE_TAG = request.tag;
  env.HOSTED_RELEASE_MODE = request.mode;
  env.HOSTED_RELEASE_REQUEST_ID = request.id;
  env.HOSTED_RELEASE_RESULT_FILE = join(workspace, "result.json");
  return { env, workflowFiles };
}

async function privateSourceCheckout(request, accessToken, workspace, logStream, budget) {
  const sourceDirectory = join(workspace, "source");
  await mkdir(sourceDirectory, { recursive: false, mode: 0o700 });
  const askpassFile = join(workspace, "askpass.sh");
  await writeFile(
    askpassFile,
    [
      "#!/bin/sh",
      'case "$1" in',
      '  *Username*) printf "%s\\n" "x-access-token" ;;',
      '  *) printf "%s\\n" "$SOURCE_ACCESS_TOKEN" ;;',
      "esac",
      "",
    ].join("\n"),
    { mode: 0o700, flag: "wx" },
  );
  await chmod(askpassFile, 0o700);

  const checkoutEnvironment = {
    PATH: process.env.PATH ?? "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    GIT_CONFIG_GLOBAL: join(workspace, "gitconfig"),
    GIT_CONFIG_SYSTEM: "/dev/null",
    GIT_ASKPASS: askpassFile,
    GIT_TERMINAL_PROMPT: "0",
    GIT_TRACE: "0",
    GIT_TRACE_CURL: "0",
    SOURCE_ACCESS_TOKEN: accessToken,
  };
  for (const args of [
    ["init", "--quiet"],
    ["remote", "add", "origin", "https://github.com/" + request.source_repository + ".git"],
    [
      "-c",
      "credential.helper=",
      "fetch",
      "--quiet",
      "--no-tags",
      "--depth=1",
      "origin",
      request.source_sha,
    ],
    ["checkout", "--quiet", "--detach", "FETCH_HEAD"],
  ]) {
    const git = await runPrivateProcess({
      command: "git",
      args,
      cwd: sourceDirectory,
      env: checkoutEnvironment,
      logStream,
      budget,
    });
    if (git.code !== 0 || git.signal !== null) {
      throw new Error("The private source checkout failed.");
    }
  }
  const head = await runPrivateProcess({
    command: "git",
    args: ["rev-parse", "--verify", "HEAD"],
    cwd: sourceDirectory,
    env: checkoutEnvironment,
    logStream,
    budget,
  });
  if (head.code !== 0 || head.signal !== null || budget.truncated) {
    throw new Error("The private source checkout could not be verified.");
  }

  return { sourceDirectory, askpassFile };
}

async function requirePrivateHelper(sourceDirectory, relativePath) {
  const helperPath = join(sourceDirectory, relativePath);
  if (!helperPath.startsWith(sourceDirectory + "/")) {
    throw new Error("The private release request is invalid.");
  }
  const helper = await readFile(helperPath, "utf8");
  if (!helper.startsWith("#!")) throw new Error("A private release helper is invalid.");
  return helperPath;
}

async function runPrivateHelpers(request, sourceDirectory, env, logStream, budget, status) {
  if (request.mode === "probe") {
    if (request.env.RELEASE_LOG_CANARY) {
      await appendDiagnostic(
        logStream,
        "probe",
        Buffer.from(request.env.RELEASE_LOG_CANARY, "utf8"),
        budget,
      );
    }
    if (request.env.RELEASE_PROBE_FAIL === "1") {
      throw new Error(
        "Private diagnostic failure " +
          (request.env.RELEASE_LOG_CANARY ?? "") +
          " at " +
          sourceDirectory +
          "/scripts/ci/hosted-build.sh",
      );
    }
    await requirePrivateHelper(sourceDirectory, "scripts/ci/hosted-build.sh");
    await requirePrivateHelper(sourceDirectory, "scripts/ci/hosted-deploy.sh");
    return;
  }

  const buildScript = await requirePrivateHelper(
    sourceDirectory,
    "scripts/ci/hosted-build.sh",
  );
  status("Building release.");
  const build = await runPrivateProcess({
    command: "bash",
    args: [buildScript],
    cwd: sourceDirectory,
    env,
    logStream,
    budget,
  });
  if (build.code !== 0 || build.signal !== null || budget.truncated) {
    throw new Error("The private release build failed.");
  }

  if (request.mode === "build") return;
  const deployScript = await requirePrivateHelper(
    sourceDirectory,
    "scripts/ci/hosted-deploy.sh",
  );
  status("Deploying release.");
  const deploy = await runPrivateProcess({
    command: "bash",
    args: [deployScript],
    cwd: sourceDirectory,
    env,
    logStream,
    budget,
  });
  if (deploy.code !== 0 || deploy.signal !== null || budget.truncated) {
    throw new Error("The private release deployment failed.");
  }
}

async function writeEncrypted(directory, name, value, key, purpose) {
  const output = join(directory, name);
  const content = sealEnvelope(value, key, purpose) + "\n";
  await writeFile(output, content, { encoding: "utf8", mode: 0o600, flag: "wx" });
  await chmod(output, 0o600);
  return output;
}

export async function runHostedRelease({
  payload,
  requestId,
  bridgeKey,
  runnerTemp,
  status = fixedStatus,
  failure = fixedFailure,
}) {
  let request;
  try {
    request = validateRequest(openEnvelope(payload, bridgeKey, "request"), requestId);
  } catch {
    fixedRequestFailure();
    return { ok: false, artifactReady: false };
  }

  const accessToken = request.env.ACCESS_TOKEN;
  if (typeof accessToken !== "string" || accessToken.length === 0) {
    fixedRequestFailure();
    return { ok: false, artifactReady: false };
  }
  maskRequest(request, accessToken);

  const runnerRoot = resolve(runnerTemp ?? process.env.RUNNER_TEMP ?? tmpdir());
  const workspace = await mkdtemp(join(runnerRoot, "private-release-"));
  await chmod(workspace, 0o700);
  await mkdir(join(workspace, "tmp"), { mode: 0o700 });
  await mkdir(join(workspace, "home"), { mode: 0o700 });
  const logFile = join(workspace, "private-diagnostics.ndjson");
  const logStream = createWriteStream(logFile, { flags: "wx", mode: 0o600 });
  const budget = { remaining: MAX_DIAGNOSTICS, truncated: false };
  let sourceDirectory;
  let askpassFile;
  let ok = false;
  let privateError = null;
  let resultPath;
  let validatedBuildResult = null;
  let completionMessage = null;

  try {
    status("Preparing release.");
    const checkout = await privateSourceCheckout(
      request,
      accessToken,
      workspace,
      logStream,
      budget,
    );
    sourceDirectory = checkout.sourceDirectory;
    askpassFile = checkout.askpassFile;

    const sourcePath = await runPrivateProcess({
      command: "git",
      args: ["rev-parse", "--verify", "HEAD"],
      cwd: sourceDirectory,
      env: {
        PATH: process.env.PATH ?? "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        ...(typeof process.env.HOME === "string" ? { HOME: process.env.HOME } : {}),
        GIT_CONFIG_GLOBAL: join(workspace, "gitconfig"),
        GIT_CONFIG_SYSTEM: "/dev/null",
        GIT_TERMINAL_PROMPT: "0",
      },
      logStream,
      budget,
    });
    if (sourcePath.code !== 0 || sourcePath.signal !== null) {
      throw new Error("The private source commit could not be verified.");
    }
    // Check the exact object a second time via Git's local object database; its
    // output stays in the encrypted diagnostic file.
    if (sourcePath.stdout.trim() !== request.source_sha) {
      throw new Error("The private source commit did not match the request.");
    }

    const childEnvironment = await privateChildEnvironment(
      request,
      accessToken,
      workspace,
      sourceDirectory,
    );
    const childEnv = childEnvironment.env;
    request.workflowFiles = childEnvironment.workflowFiles;
    await runPrivateHelpers(
      request,
      sourceDirectory,
      childEnv,
      logStream,
      budget,
      status,
    );
    resultPath = childEnv.HOSTED_RELEASE_RESULT_FILE;
    if (request.mode !== "probe") {
      const result = JSON.parse(await readFile(resultPath, "utf8"));
      if (
        result.schema !== 1 ||
        result.source_sha !== request.source_sha ||
        result.component !== request.component
      ) {
        throw new Error("The private release result did not match the request.");
      }
      validatedBuildResult = result;
    }
    ok = true;
    completionMessage =
      request.mode === "probe" ? "Release request checked." : "Release complete.";
  } catch (error) {
    privateError = error;
  } finally {
    if (privateError) {
      const event = {
        private_error: privateError instanceof Error ? privateError.stack : "Private execution failed.",
      };
      await appendDiagnostic(
        logStream,
        "launcher",
        Buffer.from(JSON.stringify(event)),
        budget,
      );
    }
    if (budget.truncated) {
      await appendDiagnostic(
        logStream,
        "launcher",
        Buffer.from("[diagnostics truncated at configured limit]"),
        { remaining: 512, truncated: false },
      );
    }
    await finishWrite(logStream).catch(() => {});
    if (askpassFile) await rm(askpassFile, { force: true }).catch(() => {});
    if (sourceDirectory) {
      await rm(sourceDirectory, { recursive: true, force: true }).catch(() => {});
    }
  }

  const outputDirectory = join(runnerRoot, "release-output");
  await mkdir(outputDirectory, { recursive: true, mode: 0o700 });
  await chmod(outputDirectory, 0o700);
  let artifactReady = false;
  try {
    const diagnostics = {
      schema: 1,
      request_id: request.id,
      source_repository: request.source_repository,
      source_sha: request.source_sha,
      component: request.component,
      tag: request.tag,
      mode: request.mode,
      status: ok ? "success" : "failure",
      truncated: budget.truncated,
      workflow_command_files: request.workflowFiles
        ? Object.fromEntries(
            await Promise.all(
              Object.entries(request.workflowFiles).map(async ([name, path]) => [
                name,
                await readFile(path, "utf8"),
              ]),
            ),
          )
        : {},
      logs: await readFile(logFile, "utf8"),
    };
    await writeEncrypted(
      outputDirectory,
      "diagnostics.enc",
      diagnostics,
      bridgeKey,
      "diagnostics",
    );
    if (validatedBuildResult !== null) {
      try {
        await writeEncrypted(
          outputDirectory,
          "result.enc",
          {
            schema: 1,
            request_id: request.id,
            source_sha: request.source_sha,
            component: request.component,
            status: ok ? "success" : "failure",
            result: validatedBuildResult,
          },
          bridgeKey,
          "result",
        );
      } catch {
        if (ok) throw new Error("The private build result could not be encrypted.");
      }
    }
    const output = process.env.GITHUB_OUTPUT;
    if (output) {
      const handle = await open(output, "a", 0o600);
      try {
        await handle.writeFile("artifact_ready=true\n");
      } finally {
        await handle.close();
      }
    }
    artifactReady = true;
  } catch {
    artifactReady = false;
  }

  await rm(workspace, { recursive: true, force: true }).catch(() => {});
  if (ok && artifactReady && completionMessage) status(completionMessage);
  if (ok && !artifactReady) ok = false;
  if (!ok) failure(artifactReady);
  return { ok, artifactReady };
}

export async function runCli({
  environment = process.env,
  execute = runHostedRelease,
  failure = (message) => process.stderr.write(message + "\n"),
} = {}) {
  let key;
  try {
    key = decodeKey(environment.RELEASE_BRIDGE_KEY);
  } catch {
    failure("Release setup failed before private source checkout.");
    return 1;
  }

  try {
    const result = await execute({
      payload: environment.RELEASE_PAYLOAD ?? "",
      requestId: environment.RELEASE_REQUEST_ID ?? "",
      bridgeKey: key,
      runnerTemp: environment.RUNNER_TEMP ?? tmpdir(),
    });
    return result.ok && result.artifactReady ? 0 : 1;
  } catch {
    failure("Release failed before encrypted diagnostics could be saved.");
    return 1;
  }
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  process.exitCode = await runCli();
}
