# Differential probes (TypeScript ↔ Kotlin)

327 hostile and edge inputs (event ids, JCS, BIP-340, WebAuthn, lifetimes, the destructive rule,
records, changes and approvals), run through both implementations. From independent review 6.

```bash
node gen.ts > probes.json
JAVA_HOME=$(/usr/libexec/java_home -v 21) ../../kotlin/gradlew -p kprobe run -q
node compare.ts          # prints every disagreement; --all prints every probe
```

Expected: 0 disagreements. Since core §9.5 (14.15) both sides read every text with the same profile, so
the event-id probes whose `created_at` isn't a safe integer, the 3 differences left after review 6, are
now refused alike. The §9.5 probes cover the reader (`read: …`), fatal UTF-8 (`utf8`), both base64
spellings (`b64u`, `b64`), event shapes (`event_id`) and §5.8's counting (`destructive`).
