# Electoral Commission of South Africa API

BallotProof v0.16 includes a source-specific streaming adapter for the Electoral Commission of South Africa (IEC) API at `api.elections.org.za`.

## Why the adapter is disabled by default

The official IEC API documentation states that the API exists for third-party websites, political parties, media and other interested parties to retrieve election-related data. The API requires assigned credentials and the published terms currently state a 10,000 requests/hour limit.

The same terms also restrict scraping, database-building, permanent copies and cached copies beyond cache-header permissions unless the content owner or applicable law separately permits that use. BallotProof intentionally preserves raw source responses immutably. That creates a material retention-rights question even though machine access itself is documented.

For that reason `default_policy()` remains `review_required`. The adapter must not be activated merely because credentials exist.

## Activation gates

A reviewed deployment must establish all of the following before creating an approved source policy:

1. current IEC API terms and endpoint documentation have been reviewed;
2. valid IEC credentials have been assigned to the operator;
3. the operator has documented permission compatible with BallotProof's immutable raw-response retention;
4. the policy remains restricted to `api.elections.org.za` and an appropriate request rate at or below the official limit.

`approved_policy()` requires a non-empty retention-permission reference. `build_transport()` independently fails closed unless `BALLOTPROOF_IEC_RETENTION_PERMISSION=confirmed` and `BALLOTPROOF_IEC_AUTHORIZATION` is present. The authorization value is operator-supplied; BallotProof does not guess or hard-code an authentication scheme.

## Network safety

The IEC adapter uses `PinnedHTTPSStreamingTransport`:

- HTTPS and GET only;
- exact approved host only;
- DNS is resolved before connection;
- every resolved address must be globally routable;
- the socket connects directly to one validated IP, preventing a second resolver lookup between validation and connection;
- TLS certificate verification and SNI still use the original approved hostname;
- redirects are rejected;
- environment HTTP proxies are not consulted;
- `Accept-Encoding: identity` avoids transparent decompression expansion;
- declared `Content-Length` is checked before streaming when present;
- the existing capture layer still enforces the true byte count while reading.

The adapter records a stable transport ID, version and configuration hash on the transport object. A later provenance-schema change should bind those values directly into immutable receipts before broad live deployment.

## Non-affiliation

BallotProof is independent. The presence of this adapter does not imply partnership, sponsorship or endorsement by the Electoral Commission of South Africa.
