/**
 * The "agent brain". Deliberately NAIVE: it does whatever the text says,
 * including malicious instructions. That is the point of AgentVault: the agent
 * is untrusted, and the chain is what keeps the funds safe.
 *
 * Works with no API key. An optional LLM provider (llm.ts) can replace it.
 */
export const YOCTO_PER_NEAR = 10n ** 24n;

export interface Proposal {
  to: string;
  amountYocto: bigint;
  amountNear: string;
}

/** Decimal NEAR string -> yoctoNEAR without floating point. */
export function nearToYocto(s: string): bigint {
  if (!/^\d+(\.\d{1,24})?$/.test(s)) throw new Error(`bad amount: ${s}`);
  const [whole, frac = ""] = s.split(".");
  return BigInt(whole) * YOCTO_PER_NEAR + BigInt(frac.padEnd(24, "0"));
}

const ACCOUNT = "[a-z0-9][a-z0-9._-]{1,62}";
const AMOUNT = "(\\d+(?:\\.\\d+)?)";

const PATTERNS: RegExp[] = [
  // "send 0.5 NEAR to alice.testnet", "transfer 1 near to bob.testnet"
  new RegExp(`(?:send|pay|transfer|give)\\s+${AMOUNT}\\s*(?:near|n)?\\s+(?:to\\s+)?(${ACCOUNT})`, "i"),
  // "pay alice.testnet 0.5 NEAR"
  new RegExp(`(?:send|pay|transfer|give)\\s+(${ACCOUNT})\\s+${AMOUNT}\\s*(?:near|n)?`, "i"),
];

export function parseInstruction(text: string): Proposal {
  // Pattern 1: amount first, account second.
  let m = text.match(PATTERNS[0]);
  if (m) return build(m[2], m[1]);
  // Pattern 2: account first, amount second.
  m = text.match(PATTERNS[1]);
  if (m) return build(m[1], m[2]);
  throw new Error(`could not understand instruction: "${text}"`);
}

function build(to: string, amount: string): Proposal {
  return { to: to.toLowerCase(), amountYocto: nearToYocto(amount), amountNear: amount };
}
