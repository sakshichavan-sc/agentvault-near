/**
 * OPTIONAL free LLM brain (Google AI Studio free tier). Not required: without a
 * GEMINI_API_KEY the rule-based parser in parse.ts is used. Either way the
 * output is only a *proposal*; the vault contract decides.
 *
 * NOTE: written from the public REST shape of generateContent; verify the model
 * name in AI Studio if the call 404s (set GEMINI_MODEL).
 */
import { nearToYocto, type Proposal } from "./parse.ts";

export async function llmParse(text: string): Promise<Proposal> {
  const key = process.env.GEMINI_API_KEY;
  if (!key) throw new Error("GEMINI_API_KEY not set");
  const model = process.env.GEMINI_MODEL ?? "gemini-2.0-flash";
  const res = await fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${key}`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        contents: [{ role: "user", parts: [{ text }] }],
        tools: [{
          functionDeclarations: [{
            name: "send_near",
            description: "Send NEAR tokens to a NEAR account",
            parameters: {
              type: "OBJECT",
              properties: {
                to: { type: "STRING", description: "recipient NEAR account id" },
                amount_near: { type: "STRING", description: "decimal amount in NEAR, e.g. 0.5" },
              },
              required: ["to", "amount_near"],
            },
          }],
        }],
        toolConfig: { functionCallingConfig: { mode: "ANY", allowedFunctionNames: ["send_near"] } },
      }),
    },
  );
  if (!res.ok) throw new Error(`Gemini ${res.status}: ${await res.text()}`);
  const data: any = await res.json();
  const call = data?.candidates?.[0]?.content?.parts?.find((p: any) => p.functionCall)?.functionCall;
  if (!call) throw new Error("model returned no function call");
  const { to, amount_near } = call.args;
  return { to: String(to).toLowerCase(), amountNear: String(amount_near), amountYocto: nearToYocto(String(amount_near)) };
}
