---
'@rosen-bridge/tss': patch
---

Fix start messages passing the threshold check with duplicate or too few guards: `getApprovedGuards` now counts each distinct guard once, and no signing round is started while the threshold has not been loaded from tss-api yet (it stays at its initial -1 until the first successful fetch, which previously satisfied every `>=` comparison)
