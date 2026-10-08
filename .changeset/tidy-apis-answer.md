---
'tss-api': patch
---

Give the guard HTTP client a 30 second timeout and drain and close every response body, so a guard that stops answering cannot block a call forever and callbacks no longer leak a connection per call
