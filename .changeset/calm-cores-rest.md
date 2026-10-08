---
'tss-api': patch
---

Stop each active TSS operation from keeping a CPU core busy: the sign and keygen `StartAction` loops created the party in a `default` branch of their select, so the select never blocked once the party existed. The party is now created once before the wait loop, and the loops block until the next message, error or result arrives
