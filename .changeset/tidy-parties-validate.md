---
'tss-api': patch
---

fix CreateParty deadlocking on party-start failures and validate the party list before creating a party: duplicate parties and party sets at or below the threshold are now rejected instead of panicking or hanging tss-lib
