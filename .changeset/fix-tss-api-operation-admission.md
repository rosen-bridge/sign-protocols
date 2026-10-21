---
'tss-api': patch
---

Serialize key-generation and signing admission, protect operation registries during concurrent access, and preserve operation ownership during cleanup. Return HTTP 409 when key-generation and signing reservations for the same protocol conflict. Validate protocol and derivation-path prerequisites before registration, and cancel and join timeout goroutines when initialization fails or an operation ends. Buffer operation errors to avoid CreateParty self-deadlocks, preserve a queued terminal error without blocking failed initialization, and skip party-status logging when initialization fails before a party is assigned.
