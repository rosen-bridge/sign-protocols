---
'tss-api': patch
---

Fix a crash when a failed sign is retried: the first attempt's timeout goroutine now only ever acts on its own operation (identified by its registered channel, not just the message id), and instance cleanup no longer closes the shared error channel, so the stale timeout can no longer panic with "send on closed channel" and kill tss-api
