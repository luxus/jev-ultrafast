# Jev Ultrafast

Read README.md before editing. Keep the loop small: page -> indexed elements -> operation + target -> execution.

- The input is one natural-language goal. Do not add site-specific plans or hardcoded field values.
- TypeSafe chooses an operation and operation-specific target heads in one request. Consume only the selected operation's target. TypeSafe stays on TYPESAFE_API_KEY + api.typesafe.ai; do not merge TypeSafe auth into the text helper.
- Targets must map to observed elements and supported operations. Never let the model emit selectors or executable code.
- TYPE_TEXT invokes Grok (xAI) at https://api.x.ai/v1. Authenticate with `jev-ultrafast login` (Grok subscription OAuth; token store under ~/.config/jev-ultrafast/). TEXT_MODEL_API_KEY is a CI/dev fallback, not the recommended path. Do not use OpenRouter as the text helper.
- TYPE_TEXT cache a stale retry's value only while its entire helper input is identical.
- Never retry a browser mutation. Log execution before observing its result.
- Screenshots are optional; the model does not consume them. Keep demonstration footage at its original speed.
- Keep credentials server-side and .env ignored. Tests must not call paid APIs.
- Chrome CDP: `BU_CDP_URL=http://127.0.0.1:9242` (HTTP DevTools endpoint for Browser Harness).
- Verify actual final outcomes independently. A DONE choice is not proof of success.
- Keep examples, README claims, raw evidence, and model-call counts consistent.
- Do not commit or push unless the user requests it.

Checks: uv run ruff check ., uv run pytest, node --check jev_ultrafast/static/app.js, uv build.
