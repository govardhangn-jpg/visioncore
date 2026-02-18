/**
 * netlify/functions/analyze.js
 *
 * Serverless proxy for Anthropic API.
 * - Verifies Netlify Identity JWT (user must be logged in)
 * - Calls Claude vision model with server-side ANTHROPIC_API_KEY
 * - Never exposes the key to the browser
 *
 * Environment variable required (set in Netlify dashboard):
 *   ANTHROPIC_API_KEY = sk-ant-...
 */

export const handler = async (event, context) => {
  // ── CORS preflight
  if (event.httpMethod === "OPTIONS") {
    return {
      statusCode: 204,
      headers: corsHeaders(),
    };
  }

  // ── Only accept POST
  if (event.httpMethod !== "POST") {
    return respond(405, { error: "Method not allowed" });
  }

  // ── Verify Netlify Identity JWT
  const { user } = context.clientContext || {};
  if (!user) {
    return respond(401, { error: "Unauthorized: please log in first." });
  }

  // ── Validate env
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    console.error("ANTHROPIC_API_KEY environment variable is not set.");
    return respond(500, { error: "Server configuration error." });
  }

  // ── Parse request body
  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch {
    return respond(400, { error: "Invalid JSON body." });
  }

  const { imageBase64, mediaType } = body;

  if (!imageBase64 || !mediaType) {
    return respond(400, { error: "Missing imageBase64 or mediaType." });
  }

  // ── Call Anthropic
  const DEFECT_PROMPT = `You are an expert visual quality control inspector. Analyze this image thoroughly for any defects, anomalies, or dissimilarities including:
- Lines (cracks, scratches, fracture lines, surface lines)
- Spots or discolorations
- Chips, dents, holes
- Texture irregularities or surface damage
- Any other visual anomalies

Respond ONLY with a valid JSON object in this exact structure (no markdown, no extra text):
{
  "classification": "FAULTY" or "NON-FAULTY",
  "confidence": number between 0 and 100,
  "defects": [
    {
      "type": "defect type name",
      "severity": "LOW" or "MEDIUM" or "HIGH",
      "location": "description of where in the image",
      "description": "detailed description of the defect"
    }
  ],
  "summary": "one concise paragraph summarizing your findings",
  "recommendation": "actionable recommendation"
}

If the image is NON-FAULTY, return an empty array for defects.`;

  try {
    const anthropicRes = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type":    "application/json",
        "x-api-key":       apiKey,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model:      "claude-sonnet-4-20250514",
        max_tokens: 1000,
        messages: [
          {
            role: "user",
            content: [
              {
                type: "image",
                source: { type: "base64", media_type: mediaType, data: imageBase64 },
              },
              { type: "text", text: DEFECT_PROMPT },
            ],
          },
        ],
      }),
    });

    const data = await anthropicRes.json();

    if (data.error) {
      return respond(502, { error: data.error.message || "Anthropic API error." });
    }

    const text   = (data.content || []).map((c) => c.text || "").join("");
    const clean  = text.replace(/```json|```/g, "").trim();
    const parsed = JSON.parse(clean);

    return respond(200, parsed);

  } catch (err) {
    console.error("Analysis error:", err);
    return respond(502, { error: `Analysis failed: ${err.message}` });
  }
};

/* ── helpers ── */

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin":  "*",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
  };
}

function respond(statusCode, body) {
  return {
    statusCode,
    headers: { "Content-Type": "application/json", ...corsHeaders() },
    body: JSON.stringify(body),
  };
}
