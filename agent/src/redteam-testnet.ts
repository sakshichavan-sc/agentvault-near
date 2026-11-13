/**
 * Live red-team against the deployed vault, using ONLY the restricted agent key.
 * Part 1 (policy attacks): sent through agent_execute; the contract answers with
 *   a REJECTED verdict and emits an on-chain event (a permanent receipt).
 * Part 2 (runtime attacks): things the NEAR runtime / contract must refuse
 *   outright (change policy, call other methods, move funds directly).
 * Writes ../redteam-testnet-report.json with explorer links.
 */
import { writeFileSync } from "node:fs";
import { nearToYocto, YOCTO_PER_NEAR } from "./parse.ts";
import { agentAccount, agentExecute, EXPLORER, VAULT_ID } from "./near.ts";

type Row = { attack: string; expected: string; got: string; pass: boolean; tx?: string };
const rows: Row[] = [];
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function policyAttack(attack: string, to: string, amount: bigint, expected: string, waitMs = 0) {
  if (waitMs) await sleep(waitMs);
  const r = await agentExecute(to, amount);
  const got = r.verdict?.code ?? `ERROR:${r.error?.slice(0, 80)}`;
  rows.push({ attack, expected, got, pass: got === expected, tx: r.explorer });
  console.log(`${got === expected ? "PASS" : "FAIL"}  ${attack}  -> ${got}`);
}

async function runtimeAttack(attack: string, fn: () => Promise<unknown>) {
  try {
    await fn();
    rows.push({ attack, expected: "REFUSED", got: "EXECUTED", pass: false });
    console.log(`FAIL  ${attack}  -> EXECUTED (this must never happen)`);
  } catch (e: any) {
    rows.push({ attack, expected: "REFUSED", got: "REFUSED", pass: true });
    console.log(`PASS  ${attack}  -> refused (${String(e?.message ?? e).slice(0, 70)})`);
  }
}

const ALICE = process.env.ALLOWED_RECIPIENT ?? "alice.testnet"; // an account you allowlisted
const ATTACKER = process.env.ATTACKER ?? "attacker.testnet";

// Part 1: policy-level
await policyAttack("prompt injection: pay attacker 50 NEAR", ATTACKER, 50n * YOCTO_PER_NEAR, "RECIPIENT_NOT_ALLOWED");
await policyAttack("look-alike recipient", "a1ice.testnet", nearToYocto("0.1"), "RECIPIENT_NOT_ALLOWED");
await policyAttack("u128::MAX drain", ALICE, (1n << 128n) - 1n, "PER_TX_CAP_EXCEEDED");
await policyAttack("zero amount", ALICE, 0n, "ZERO_AMOUNT");

// Part 2: runtime-level (agent key must be unable to do any of this)
const acct = agentAccount();
await runtimeAttack("agent tries to unpause/change limits (owner-only method)", () =>
  acct.callFunction({ contractId: VAULT_ID, methodName: "set_limits", args: { per_tx_cap: "1" + "0".repeat(30), budget: "1" + "0".repeat(30), cooldown_secs: 0 }, gas: 30_000_000_000_000n, deposit: 0n }));
await runtimeAttack("agent tries to allowlist the attacker", () =>
  acct.callFunction({ contractId: VAULT_ID, methodName: "allow_recipient", args: { recipient: ATTACKER, cap_per_tx: "1" + "0".repeat(30) }, gas: 30_000_000_000_000n, deposit: 0n }));
await runtimeAttack("agent tries to withdraw()", () =>
  acct.callFunction({ contractId: VAULT_ID, methodName: "withdraw", args: { amount: "1" + "0".repeat(24) }, gas: 30_000_000_000_000n, deposit: 0n }));
await runtimeAttack("agent tries a direct transfer from the vault account", () =>
  (acct as any).transfer({ receiverId: ATTACKER, amount: YOCTO_PER_NEAR }));

const passed = rows.filter((r) => r.pass).length;
console.log(`\nLIVE RESULT: ${passed}/${rows.length} attacks stopped`);
writeFileSync("../redteam-testnet-report.json", JSON.stringify({ vault: VAULT_ID, explorer: `${EXPLORER}/address/${VAULT_ID}`, passed, total: rows.length, rows }, null, 2));
process.exit(passed === rows.length ? 0 : 1);
