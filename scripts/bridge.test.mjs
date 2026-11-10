import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import test from "node:test";
import {
  MAX_ENVELOPE_LENGTH,
  decodeKey,
  openEnvelope,
  sealEnvelope,
  validateRequest,
} from "./bridge.mjs";

const key = Buffer.alloc(32, 0x37);
const request = (overrides = {}) => ({
  v: 1,
  id: "a204da55-7280-4d8c-8f79-605a67d48654",
  source_repository: "sample-private/application",
  source_sha: "a".repeat(40),
  component: "web",
  tag: "",
  mode: "probe",
  env: { ACCESS_TOKEN: "example private token" },
  ...overrides,
});

test("envelopes round trip with the documented AES-GCM fields", () => {
  const plain = request();
  const encoded = sealEnvelope(plain, key, "request");
  const envelope = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  assert.equal(envelope.v, 1);
  assert.equal(Buffer.from(envelope.iv, "base64url").length, 12);
  assert.equal(Buffer.from(envelope.tag, "base64url").length, 16);
  assert.deepEqual(openEnvelope(encoded, key, "request"), plain);
  assert.ok(!encoded.includes(plain.source_repository));
  assert.ok(!encoded.includes(plain.env.ACCESS_TOKEN));
});

test("wrong key, purpose, or tampered ciphertext are rejected", () => {
  const encoded = sealEnvelope(request(), key, "request");
  assert.throws(() => openEnvelope(encoded, randomBytes(32), "request"));
  assert.throws(() => openEnvelope(encoded, key, "diagnostics"));
  const envelope = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  const ciphertext = Buffer.from(envelope.data, "base64url");
  ciphertext[0] ^= 1;
  envelope.data = ciphertext.toString("base64url");
  const tampered = Buffer.from(JSON.stringify(envelope)).toString("base64url");
  assert.throws(() => openEnvelope(tampered, key, "request"));
});

test("diagnostic envelopes support captured logs larger than the workflow input limit", () => {
  const diagnostics = {
    request_id: "a204da55-7280-4d8c-8f79-605a67d48654",
    logs: "private diagnostic line\n".repeat(4_500),
  };
  const encoded = sealEnvelope(diagnostics, key, "diagnostics");
  assert.ok(encoded.length > MAX_ENVELOPE_LENGTH);
  assert.deepEqual(openEnvelope(encoded, key, "diagnostics"), diagnostics);
});

test("only a canonical base64 encoded 32 byte key is accepted", () => {
  const encoded = key.toString("base64");
  assert.deepEqual(decodeKey(encoded), key);
  assert.throws(() => decodeKey("not a key"));
  assert.throws(() => decodeKey(Buffer.alloc(33).toString("base64")));
});

test("a release request must match the public opaque id and private source SHA", () => {
  const value = request();
  assert.equal(validateRequest(value, value.id), value);
  assert.throws(() => validateRequest(value, "b204da55-7280-4d8c-8f79-605a67d48654"));
  assert.throws(() => validateRequest({ ...value, source_sha: "a".repeat(39) }, value.id));
  assert.throws(() => validateRequest({ ...value, source_repository: "../outside" }, value.id));
});

test("release tags identify the requested component and build probes have no public tag", () => {
  const release = request({ mode: "release", tag: "web-v2.3.4" });
  assert.equal(validateRequest(release, release.id), release);
  assert.throws(() =>
    validateRequest({ ...release, tag: "other-v2.3.4" }, release.id),
  );
  assert.throws(() =>
    validateRequest({ ...request(), tag: "private-feature-branch" }, request().id),
  );
});

test("child control variables and oversized environment values are rejected", () => {
  for (const name of ["PATH", "HOME", "NODE_OPTIONS", "GITHUB_TOKEN", "RUNNER_TEMP"]) {
    const value = request({ env: { [name]: "attacker-controlled" } });
    assert.throws(() => validateRequest(value, value.id));
  }
  const value = request({ env: { BUILD_SETTING: "x".repeat(16_385) } });
  assert.throws(() => validateRequest(value, value.id));
});

test("environment values cannot contain null bytes or exceed the encrypted request budget", () => {
  const nullByte = request({ env: { PRIVATE_CONFIG: "first\u0000last" } });
  assert.throws(() => validateRequest(nullByte, nullByte.id));
  const oversized = request({ env: { PRIVATE_CONFIG: "x".repeat(45_000) } });
  assert.throws(() => validateRequest(oversized, oversized.id));
});
