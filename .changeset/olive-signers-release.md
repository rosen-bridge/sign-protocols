---
'@rosen-bridge/tss': patch
---

`TssSigner.update` releases the sign mutex when signing a payload fails, and `TssSigner.sign` checks for duplicates under the mutex so two same-tick calls for one message no longer queue two entries
