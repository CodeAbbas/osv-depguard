/**
 * AI enrichment — turns verified OSV data into human-readable summaries
 * and remediation steps. The model only interprets the supplied data; it
 * is given no tools and cannot fabricate vulnerabilities.
 */

import {
  ANTHROPIC_API_URL,
  ANTHROPIC_MAX_TOKENS,
  ANTHROPIC_MODEL,
  ANTHROPIC_VERSION,
} from "./constants.js";
import { safeJsonParse, stripCodeFences } from "./utils.js";

const SYSTEM_PROMPT = `You are a security advisor. You will receive structured vulnerability data sourced directly from the OSV.dev database.
Your only job is to interpret this data and produce output that is easier for developers to act on.
Do NOT invent, assume, or add any information not present in the input.
Respond ONLY with a valid JSON array (no markdown, no backticks, no preamble):
[
  {
    "id": "<OSV id from input>",
    "humanSummary": "2-3 sentences in plain English describing the risk, attack vector, and potential impact",
    "remediationStep": "A single specific command or action the developer should take (e.g. 'Run: npm install packageName@X.Y.Z')"
  }
]`;

/**
 * Reduce normalised vulns to the minimal payload sent to the model.
 *
 * @param {Array<object>} vulns
 * @returns {Array<object>}
 */
export function buildAiPayload(vulns) {
  return vulns.map((v) => ({
    id: v.id,
    package: v.package,
    installedVersion: v.version,
    severity: v.severity,
    summary: v.summary,
    details: (v.details || "").slice(0, 600), // keep prompt size reasonable
    fixedIn: v.fixedIn,
    aliases: v.aliases,
  }));
}

/**
 * Call the Anthropic Messages API to enrich vulnerabilities.
 *
 * @param {Array<object>} vulns
 * @param {object}   deps
 * @param {string}   deps.apiKey        Anthropic API key.
 * @param {Function} [deps.fetchImpl]   Injectable fetch (defaults to global).
 * @returns {Promise<Array<{id: string, humanSummary: string, remediationStep: string}>>}
 */
export async function enrichWithAI(vulns, { apiKey, fetchImpl = globalThis.fetch } = {}) {
  if (!vulns || vulns.length === 0) return [];
  if (!apiKey) throw new Error("ANTHROPIC_API_KEY is required for AI enrichment");

  const payload = buildAiPayload(vulns);

  const res = await fetchImpl(ANTHROPIC_API_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": apiKey,
      "anthropic-version": ANTHROPIC_VERSION,
    },
    body: JSON.stringify({
      model: ANTHROPIC_MODEL,
      max_tokens: ANTHROPIC_MAX_TOKENS,
      system: SYSTEM_PROMPT,
      messages: [
        {
          role: "user",
          content: `Generate human-readable summaries and remediation steps for these verified vulnerabilities:\n\n${JSON.stringify(payload, null, 2)}`,
        },
      ],
    }),
  });

  if (!res.ok) {
    throw new Error(`Anthropic API ${res.status}: ${res.statusText}`);
  }

  const data = await res.json();
  const text =
    data.content
      ?.filter((b) => b.type === "text")
      .map((b) => b.text)
      .join("") || "[]";

  return safeJsonParse(stripCodeFences(text), "AI response");
}

/**
 * Merge AI-generated summaries/remediation into normalised vulns,
 * falling back to OSV data when the model omitted an entry.
 *
 * @param {Array<object>} vulns
 * @param {Array<object>} aiData
 * @returns {Array<object>}
 */
export function mergeAiData(vulns, aiData = []) {
  const aiMap = Object.fromEntries((aiData || []).map((a) => [a.id, a]));

  return vulns.map((v) => ({
    ...v,
    humanSummary: aiMap[v.id]?.humanSummary || v.summary,
    remediationStep:
      aiMap[v.id]?.remediationStep ||
      (v.fixedIn ? `Run: npm install ${v.package}@${v.fixedIn}` : "No fix available"),
  }));
}
