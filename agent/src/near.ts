/** ALL NEAR access lives here. View calls use raw JSON-RPC (library independent); signing uses near-api-js. */
import { Account, JsonRpcProvider, KeyPairSigner } from "near-api-js";

export const RPC = process.env.NEAR_RPC_URL ?? "https://test.rpc.fastnear.com";
export const VAULT_ID = need("VAULT_ID");
export const EXPLORER = "https://testnet.nearblocks.io";

function need(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`missing env var ${name}`);
  return v;
}

export const provider = new JsonRpcProvider({ url: RPC });

export function agentAccount(): Account {
  const signer = KeyPairSigner.fromSecretKey(need("AGENT_KEY") as any);
  return new Account(VAULT_ID, provider, signer);
}

export interface Verdict { ok: boolean; code: string; message: string }

async function viewCall(method: string, args: object): Promise<any> {
  const res = await fetch(RPC, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0", id: "av", method: "query",
      params: {
        request_type: "call_function", finality: "final",
        account_id: VAULT_ID, method_name: method,
        args_base64: Buffer.from(JSON.stringify(args)).toString("base64"),
      },
    }),
  });
  const j: any = await res.json();
  if (j.error || j.result?.error) throw new Error(JSON.stringify(j.error ?? j.result.error));
  return JSON.parse(Buffer.from(j.result.result).toString());
}

/** Backend validator: ask the contract itself (no duplicated rules). */
export async function precheck(to: string, amountYocto: bigint): Promise<Verdict> {
  return (await viewCall("check_action", { to, amount: amountYocto.toString() })) as Verdict;
}

export interface Submitted { verdict?: Verdict; txHash?: string; error?: string; explorer?: string; raw?: unknown }

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
    const verdict: Verdict | undefined = out?.code ? out : undefined;
    return { verdict, txHash, raw: out, explorer: txHash ? `${EXPLORER}/txns/${txHash}` : undefined };
  } catch (e: any) {
    return { error: String(e?.message ?? e) };
  }
}