## 2026-03-07 - Race Condition in Module-Level State Initialization
**Vulnerability:** A cold start in Cloudflare Workers can trigger parallel initialization of shared module-level state when multiple concurrent requests hit the uninitialized isolate simultaneously.
**Learning:** Checking a module-level boolean (`if (!initialized)`) is insufficient in an asynchronous context (like fetching from KV). Multiple requests will await the fetch in parallel, causing duplicate KV calls, state corruption, or memory leaks.
**Prevention:** Use a module-level `Promise<void>` to lock the initialization block, so all concurrent requests `await` the single initialization promise instead of running parallel initializations.
