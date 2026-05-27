# Groq

Groq provides ultra-fast inference for open-weight large language models (LLaMA, Mixtral, Gemma, etc.) via an OpenAI-compatible API. IOC Router uses it as an alternative AI backend to Google Gemini for generating SOC incident ticket narratives.

---

## How It Works (Technical)

### Endpoint Used

[`providers/groq.py`](../providers/groq.py) calls the Groq chat completions endpoint (OpenAI-compatible):

```
POST https://api.groq.com/openai/v1/chat/completions
```

### Authentication

API key sent via the standard `Authorization` Bearer header:

```
Authorization: Bearer <GROQ_KEY>
```

### Request Payload

[`providers/groq.py:14`](../providers/groq.py#L14) sends a chat completion payload:

```json
{
  "model": "llama-3.1-8b-instant",
  "messages": [
    { "role": "system", "content": "You are a SOC assistant." },
    { "role": "user",   "content": "<prompt>" }
  ],
  "temperature": 0.2,
  "top_p": 0.9,
  "max_tokens": 4096
}
```

The system prompt primes the model as a SOC assistant for consistent, professional output. Temperature is set low (`0.2`) to favour factual, deterministic ticket content over creative variation.

### Default Model

The default model is `llama-3.1-8b-instant` — chosen for speed. The `model` parameter is exposed as a function argument ([`providers/groq.py:12`](../providers/groq.py#L12)), so the caller can swap to any model Groq supports (e.g. `llama-3.3-70b-versatile`, `mixtral-8x7b-32768`, `gemma2-9b-it`).

### Response Parsing

[`providers/groq.py:36`](../providers/groq.py#L36) extracts the generated text from:

```
response.choices[0].message.content
```

### Prompt Construction

The same prompt builder used for Gemini (in [`ui/components/ai_panel.py`](../ui/components/ai_panel.py)) is reused. The prompt includes:
- IOC value, type, and aggregated verdict
- Threat flags with severity levels and MITRE mappings
- Raw provider data excerpts
- Analyst-supplied context (asset, impact notes)

### Groq vs Gemini

| Aspect | Groq | Gemini |
|--------|------|--------|
| Model family | Open-weight (LLaMA, Mixtral, Gemma) | Google Gemini (proprietary) |
| Max output tokens | 4 096 | 8 192 |
| API compatibility | OpenAI-compatible | Google Generative Language API |
| Speed | Very fast (LPU hardware) | Fast |
| Free tier | Yes (generous) | Yes (rate-limited) |

### Timeout

- Timeout: **20 seconds** per request

---

## Getting an API Key

1. Go to [https://console.groq.com/](https://console.groq.com/) and sign in (Google or GitHub account supported).
2. In the left sidebar, click **API Keys**.
3. Click **Create API Key**, give it a name, and copy the generated key immediately (it is only shown once).
4. Add it to `.env`:
   ```env
   GROQ_KEY=your_api_key_here
   ```

**Free tier:** Groq offers a generous free tier with rate limits per minute per model (e.g. 30 requests/min and 14 400 requests/day for LLaMA 3.1 8B Instant as of 2025). No credit card required for the free tier. Check current limits at [https://console.groq.com/docs/rate-limits](https://console.groq.com/docs/rate-limits).
