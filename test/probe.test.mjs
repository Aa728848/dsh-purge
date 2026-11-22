// The probe is the only check that can prove the model actually received the
// inject, so its lifetime and text must be predictable.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createProbe, createProbeDelivery, readProbe, probeText, probeMessage, PROBE_TTL_MS } from "../lib/probe.js";

test("a probe is single-valued, expires, and disappears from the prompt text", () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "purge-probe-"));
  try {
    assert.equal(readProbe(home), null, "no probe by default");
    assert.equal(probeText(home), "", "no probe section without a probe");

    const created = createProbe(home);
    assert.match(created.nonce, /^purge-[0-9a-f]{8}$/);
    assert.equal(readProbe(home).nonce, created.nonce);
    const text = probeText(home);
    assert(text.includes(created.nonce), "probe nonce is in the injected text");
    assert(text.includes("dsh_probe"));

    // 过期后自动失效
    const file = path.join(home, "dsh-purge", "probe.json");
    fs.writeFileSync(file, JSON.stringify({ nonce: created.nonce, at: Date.now() - PROBE_TTL_MS - 1000 }));
    assert.equal(readProbe(home), null);
    assert.equal(probeText(home), "");

    // 坏文件不抛
    fs.writeFileSync(file, "{oops");
    assert.equal(readProbe(home), null);
    assert(probeMessage("purge-deadbeef").includes("purge-deadbeef"));
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("probe delivery appends one tail notice per session and nonce", () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "purge-probe-delivery-"));
  const file = path.join(home, "dsh-purge", "probe.json");
  try {
    const created = createProbe(home);
    const deliver = createProbeDelivery(() => true, home);
    const session = {};
    const otherSession = {};
    const decision = { kind: "continue", messages: [{ id: "downstream", role: "user", content: [] }] };

    const first = deliver({ agent: { session } }, decision);
    assert.equal(first.messages.length, 2);
    assert.equal(first.messages[0], decision.messages[0], "downstream tail messages keep their order");
    assert(first.messages[1].content[0].text.includes(created.nonce));
    assert.equal(first.messages[1].role, "user");
    assert.strictEqual(deliver({ agent: { session } }, decision), decision, "same nonce is not delivered twice");
    assert.equal(deliver({ agent: { session: otherSession } }, decision).messages.length, 2, "another session gets its own probe");

    const denied = createProbeDelivery(() => false, home);
    assert.strictEqual(denied({ agent: { session: {} } }, decision), decision, "excluded presets stay clean");

    const replacement = createProbe(home);
    assert.notEqual(replacement.nonce, created.nonce);
    assert.equal(deliver({ agent: { session } }, decision).messages.length, 2, "a new nonce is delivered once");

    fs.writeFileSync(file, JSON.stringify({ nonce: replacement.nonce, at: Date.now() - PROBE_TTL_MS - 1000 }));
    assert.strictEqual(deliver({ agent: { session: {} } }, decision), decision, "expiry only stops future delivery");
  } finally {
    fs.rmSync(file, { force: true });
    fs.rmdirSync(path.dirname(file));
    fs.rmdirSync(home);
  }
});
