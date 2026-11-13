/**
 * ALL near-api-js usage lives here so an API change is a one-file fix.
 * Written against near-api-js v6 (Account / JsonRpcProvider / KeyPairSigner).
 * Not yet exercised against a live testnet from the build sandbox.
 *
 * Env:
 *   VAULT_ID         vault account, e.g. vault.yourname.testnet
 *   AGENT_KEY        ed25519:... function-call key for the vault (agent_execute only)
 *   NEAR_RPC_URL     default https://test.rpc.fastnear.com
 *   OWNER_ID/OWNER_KEY (optional, only used by the red-team to prove the agent can't act as owner)
 */
import { Account, JsonRpcProvider, KeyPairSigner } from "near-api-js";

export const RPC = process.env.NEAR_RPC_URL ?? "https://test.rpc.fastnear.com";
export const VAULT_ID = need("VAULT_ID");
export const EXPLORER = "https://testnet.nearblocks.io";

function need(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`missing env var ${name} (see README)`);
  return v;
}

export const provider = new JsonRpcProvider({ url: RPC });

/** Account object that signs AS THE VAULT with the restricted agent key. */
export function agentAccount(): Account {
  const signer = KeyPairSigner.fromSecretKey(need("AGENT_KEY") as any);
  return new Account(VAULT_ID, provider, signer);
}

export interface Verdict { ok: boolean; code: string; message: string }

/** Backend validator: ask the contract itself (no duplicated rules). */
export async function precheck(to: string, amountYocto: bigint): Promise<Verdict> {
  return (await provider.callFunction(VAULT_ID, "check_action", { to, amount: amountYocto.toString() })) as Verdict;
}

export interface Submitted { verdict?: Verdict; txHash?: string; error?: string; explorer?: string }

/** Submit an action on-chain with the agent key. */
export async function agentExecute(to: string, amountYocto: bigint): Promise<Submitted> {
  try {
    const out: any = await agentAccount().callFunction({
      contractId: VAULT_ID,
      methodName: "agent_execute",
      args: { to, amount: amountYocto.toString() },
      gas: 30_000_000_000_000n,
      deposit: 0n,
    });
    const txHash: string | undefined = out?.transaction?.hash ?? out?.transaction_outcome?.id;
    // callFunction returns the contract's JSON return value in v6; tolerate both shapes.
    const verdict: Verdict | undefined = out?.code ? out : undefined;
    return { verdict, txHash, explorer: txHash ? `${EXPLORER}/txns/${txHash}` : undefined };
  } catch (e: any) {
    return { error: String(e?.message ?? e) };
  }
}
