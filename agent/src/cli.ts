import { parseInstruction } from "./parse.ts";
import { llmParse } from "./llm.ts";
import { agentExecute, precheck } from "./near.ts";

const args = process.argv.slice(2);
const direct = args.includes("--no-precheck"); // send straight to chain to get an on-chain rejection receipt
const text = args.filter((a) => !a.startsWith("--")).join(" ");
if (!text) {
  console.log('usage: npm run agent -- "send 0.5 NEAR to alice.testnet" [--no-precheck]');
  process.exit(1);
}

const proposal = process.env.GEMINI_API_KEY ? await llmParse(text) : parseInstruction(text);
console.log(`agent proposes: send ${proposal.amountNear} NEAR -> ${proposal.to}`);

if (!direct) {
  const v = await precheck(proposal.to, proposal.amountYocto);
  console.log(`validator (reads vault policy): ${v.code}${v.ok ? "" : " - " + v.message}`);
  if (!v.ok) {
    console.log("blocked before submission. Use --no-precheck to push it on-chain and record the rejection.");
    process.exit(0);
  }
}

const r = await agentExecute(proposal.to, proposal.amountYocto);
if (r.error) console.log(`chain refused: ${r.error}`);
else console.log(`on-chain verdict: ${r.verdict?.code ?? "(see tx)"}  ${r.explorer ?? ""}`);
