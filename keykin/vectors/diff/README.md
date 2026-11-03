# Differential probes (TypeScript ↔ Kotlin)

161 hostile and edge inputs (event ids, JCS, BIP-340, WebAuthn, lifetimes, the destructive rule,
records, changes and approvals), run through both implementations. From independent review 6.

```bash
node gen.ts > probes.json
JAVA_HOME=$(/usr/libexec/java_home -v 21) ../../kotlin/gradlew -p kprobe run -q
node compare.ts          # prints every disagreement; --all prints every probe
```

Expected: 3 disagreements, all on the raw event-id function for events whose `created_at` isn't a
safe integer, which both implementations refuse at verification.
