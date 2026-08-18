# Kubernetes deployment notes

These manifests are reference deployment primitives, not a claim that cluster-level dependencies
have been provisioned.

Before applying `api.yaml`, create outside Git:

- a Kubernetes Secret named `ballotproof-runtime` with key `database-url`;
- a durable shared PVC named `ballotproof-shared-data` that can be mounted by every API replica;
- the `ballotproof:0.27.0` image in your trusted image registry; and
- an ingress/CDN/WAF policy appropriate for the deployment.

Run the PostgreSQL initialization Job before the API rollout. For migrated elections, complete the
quiesced `app-migrate --activate` and `app-equivalence` procedure in `docs/POSTGRES_CUTOVER.md`
before switching traffic to a Postgres-primary API.

`worker.example.yaml` is intentionally `replicas: 0` and contains an invalid transport placeholder.
It must not be scaled up until the placeholder is replaced with an explicitly trusted adapter and
the source-access/retention approval gates are satisfied.
