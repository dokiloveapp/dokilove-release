#!/usr/bin/env node
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

export const MAX_ENVELOPE_LENGTH = 65_000;
export const MAX_REQUEST_BYTES = 48_000;
const MAX_DIAGNOSTIC_ENVELOPE_LENGTH = 140 * 1024 * 1024;
const MAX_DIAGNOSTIC_BYTES = 96 * 1024 * 1024;
const MAX_RESULT_ENVELOPE_LENGTH = 24 * 1024 * 1024;
const MAX_RESULT_BYTES = 18 * 1024 * 1024;
const PLAINTEXT_LIMITS = new Map([
  ["request", MAX_REQUEST_BYTES],
  ["diagnostics", MAX_DIAGNOSTIC_BYTES],
  ["result", MAX_RESULT_BYTES],
]);
const ENVELOPE_LIMITS = new Map([
  ["request", MAX_ENVELOPE_LENGTH],
  ["diagnostics", MAX_DIAGNOSTIC_ENVELOPE_LENGTH],
  ["result", MAX_RESULT_ENVELOPE_LENGTH],
]);

const PURPOSES = new Set(["request", "diagnostics", "result"]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const REPOSITORY = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const SHA = /^[0-9a-f]{40}$/;
const ENV_NAME = /^[A-Z][A-Z0-9_]{0,127}$/;
const FORBIDDEN_ENV = /^(?:PATH|HOME|USER|SHELL|CI|NODE_OPTIONS|GITHUB_.+|RUNNER_.+|ACTIONS_.+|LD_.+)$/;

function invalid() {
  throw new Error("Invalid or unauthenticated release envelope.");
}

function aad(purpose) {
  if (!PURPOSES.has(purpose)) invalid();
  return Buffer.from("release-bridge:v1:" + purpose, "utf8");
}

function decodeBase64Url(value, exactLength) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) invalid();
  const bytes = Buffer.from(value, "base64url");
  if (bytes.toString("base64url") !== value) invalid();
  if (exactLength !== undefined && bytes.length !== exactLength) invalid();
  return bytes;
}

function validateKey(key) {
  if (!Buffer.isBuffer(key) || key.length !== 32) invalid();
  return key;
}

export function decodeKey(encoded) {
  if (typeof encoded !== "string" || !/^[A-Za-z0-9+/]{43}=$/.test(encoded)) invalid();
  const key = Buffer.from(encoded, "base64");
  if (key.length !== 32 || key.toString("base64") !== encoded) invalid();
  return key;
}

export function sealEnvelope(value, key, purpose) {
  validateKey(key);
  const associatedData = aad(purpose);
  const plaintextLimit = PLAINTEXT_LIMITS.get(purpose);
  let cleartext;
  try {
    cleartext = Buffer.from(JSON.stringify(value), "utf8");
  } catch {
    invalid();
  }
  if (cleartext.length > plaintextLimit) invalid();

  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(associatedData);
  const data = Buffer.concat([cipher.update(cleartext), cipher.final()]);
  const envelope = {
    v: 1,
    iv: iv.toString("base64url"),
    tag: cipher.getAuthTag().toString("base64url"),
    data: data.toString("base64url"),
  };
  const encoded = Buffer.from(JSON.stringify(envelope), "utf8").toString("base64url");
  if (encoded.length > ENVELOPE_LIMITS.get(purpose)) invalid();
  return encoded;
}

export function openEnvelope(encoded, key, purpose) {
  validateKey(key);
  if (
    typeof encoded !== "string" ||
    encoded.length === 0 ||
    encoded.length > ENVELOPE_LIMITS.get(purpose)
  ) invalid();
  const associatedData = aad(purpose);
  const envelope = JSON.parse(decodeBase64Url(encoded).toString("utf8"));
  if (
    envelope === null ||
    typeof envelope !== "object" ||
    Array.isArray(envelope) ||
    Object.keys(envelope).sort().join(",") !== "data,iv,tag,v" ||
    envelope.v !== 1
  ) invalid();

  const iv = decodeBase64Url(envelope.iv, 12);
  const tag = decodeBase64Url(envelope.tag, 16);
  const data = decodeBase64Url(envelope.data);
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAAD(associatedData);
    decipher.setAuthTag(tag);
    const cleartext = Buffer.concat([decipher.update(data), decipher.final()]);
    if (cleartext.length > PLAINTEXT_LIMITS.get(purpose)) invalid();
    return JSON.parse(cleartext.toString("utf8"));
  } catch {
    invalid();
  }
}

export function validateRequest(request, expectedId) {
  if (
    request === null ||
    typeof request !== "object" ||
    Array.isArray(request) ||
    Object.keys(request).sort().join(",") !==
      "component,env,id,mode,source_repository,source_sha,tag,v" ||
    request.v !== 1 ||
    typeof expectedId !== "string" ||
    !UUID.test(expectedId) ||
    typeof request.id !== "string" ||
    !UUID.test(request.id) ||
    request.id !== expectedId ||
    typeof request.source_repository !== "string" ||
    !REPOSITORY.test(request.source_repository) ||
    request.source_repository.split("/").some((part) => part === "." || part === "..") ||
    typeof request.source_sha !== "string" ||
    !SHA.test(request.source_sha) ||
    typeof request.component !== "string" ||
    !/^[a-z0-9][a-z0-9-]{0,62}$/.test(request.component) ||
    !["probe", "build", "release"].includes(request.mode) ||
    typeof request.tag !== "string" ||
    request.tag.length > 128 ||
    (request.mode === "release"
      ? !new RegExp("^" + request.component + "-v[0-9]+\\.[0-9]+\\.[0-9]+$").test(request.tag)
      : request.tag !== "") ||
    request.env === null ||
    typeof request.env !== "object" ||
    Array.isArray(request.env)
  ) invalid();

  for (const [name, value] of Object.entries(request.env)) {
    if (
      !ENV_NAME.test(name) ||
      FORBIDDEN_ENV.test(name) ||
      typeof value !== "string" ||
      value.includes("\u0000") ||
      Buffer.byteLength(value, "utf8") > 16_384
    ) invalid();
  }
  if (Buffer.byteLength(JSON.stringify(request), "utf8") > MAX_REQUEST_BYTES) invalid();

  if (request.mode === "probe") {
    if (
      request.env.RELEASE_PROBE_FAIL !== undefined &&
      !["0", "1"].includes(request.env.RELEASE_PROBE_FAIL)
    ) invalid();
  } else if (
    request.env.RELEASE_PROBE_FAIL !== undefined ||
    request.env.RELEASE_LOG_CANARY !== undefined
  ) invalid();

  return request;
}
