// Runtime probe: prove that the prompt path actually reaches the model.
//
// 文件被打上补丁、section 被注册，只能证明"宿主侧就绪"；真正要验证的是
// "模型收到了"。做法：写入一个一次性 nonce，并在下一步历史尾部追加一段
// "看到就把这个 nonce 原样回显"的短指令。模型回显 = 这条链路真的通了。
import fs from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { findDshHome } from "./core.js";

export const PROBE_SECTION = "dsh-purge:probe";
export const PROBE_TTL_MS = 30 * 60 * 1000;

function probePath(dshHome) {
  const home = dshHome || findDshHome();
  if (!home) return "";
  return path.join(home, "dsh-purge", "probe.json");
}

export function readProbe(dshHome) {
  const file = probePath(dshHome);
  if (!file) return null;
  try {
    const data = JSON.parse(fs.readFileSync(file, "utf8"));
    if (!data || typeof data.nonce !== "string" || !data.nonce) return null;
    const at = Number(data.at) || 0;
    if (!at || Date.now() - at > PROBE_TTL_MS) {
      try {
        fs.rmSync(file, { force: true });
      } catch {
        /* ignore */
      }
      return null;
    }
    return { nonce: data.nonce, at };
  } catch {
    return null;
  }
}

export function createProbe(dshHome) {
  const file = probePath(dshHome);
  if (!file) throw new Error("未定位 DSH 数据目录，无法写探针");
  const nonce = "purge-" + randomBytes(4).toString("hex");
  const at = Date.now();
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.writeFileSync(file, JSON.stringify({ nonce, at }, null, 2), { mode: 0o600 });
  return { nonce, at, message: probeMessage(nonce) };
}

export function probeMessage(nonce) {
  return [
    "请原样输出下面这行（不要改写、不要解释）：",
    `[${nonce}]`,
    "",
    "看到它原样出现在你的回复里，就说明 purge 的注入确实到达了模型上下文。",
  ].join("\n");
}

export function probePrompt(nonce) {
  return [
    "<dsh_probe>",
    "这条提示词由 dsh-purge 写入，用于验证注入链路是否到达模型。",
    `如果本段在你的上下文里，请在回复的最后单独一行原样输出：[${nonce}]`,
    "</dsh_probe>",
  ].join("\n");
}

/** 探针存活时的提示正文；过期返回空串。 */
export function probeText(dshHome) {
  const probe = readProbe(dshHome);
  return probe ? probePrompt(probe.nonce) : "";
}

/**
 * 临时探针只能追加到历史尾部，不能进入 system prompt。
 * KIMI CODE 等线路会用整段 system 作为前缀缓存键；探针出现或过期时改写 system，
 * 会绕过订阅插件对动态段的冻结守卫。每个会话的每个 nonce 只投递一次。
 */
export function createProbeDelivery(isAllowed = () => true, dshHome) {
  const delivered = new WeakMap();
  return (payload, decision) => {
    if (!decision || decision.kind === "reject") return decision;
    const agent = payload?.agent;
    const session = agent?.session;
    const trackable = (typeof session === "object" && session !== null) || typeof session === "function";
    if (!trackable || !isAllowed({ agent })) return decision;
    const probe = readProbe(dshHome);
    if (!probe || delivered.get(session) === probe.nonce) return decision;
    const messages = Array.isArray(decision.messages) ? decision.messages : [];
    delivered.set(session, probe.nonce);
    return {
      ...decision,
      messages: [...messages, {
        id: `dsh-purge-probe-${probe.nonce}`,
        role: "user",
        content: [{ type: "text", text: probePrompt(probe.nonce) }],
        source: { kind: "dsh-purge", form: "notice", summary: "runtime probe" },
      }],
    };
  };
}
