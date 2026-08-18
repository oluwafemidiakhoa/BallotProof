const checks = [
  ["Candidate total", "285 = 285", "pass"],
  ["Ballots vs accredited", "300 <= 300", "pass"],
  ["Source reconciliation", "Candidate A: -10", "flag"],
] as const;

export default function Home() {
  return (
    <main>
      <nav className="nav shell" aria-label="Primary navigation">
        <a className="brand" href="#top" aria-label="BallotProof home">
          <span className="brandMark" aria-hidden="true">BP</span>
          <span>BallotProof</span>
        </a>
        <div className="navLinks">
          <a href="#method">Method</a>
          <a href="/evidence/DEMO-PU-001">Explorer</a>
          <a href="https://github.com/oluwafemidiakhoa/BallotProof">GitHub</a>
        </div>
      </nav>

      <section className="hero shell" id="top">
        <div className="eyebrow">Open election evidence infrastructure</div>
        <h1>Do not trust the dashboard. <span>Verify the evidence.</span></h1>
        <p className="lede">
          BallotProof preserves source artifacts, exposes machine uncertainty, validates
          result-sheet arithmetic, and keeps human corrections and source disagreements visible.
        </p>
        <div className="actions">
          <a className="button primary" href="/evidence/DEMO-PU-001">Open the evidence explorer</a>
          <a className="button secondary" href="https://github.com/oluwafemidiakhoa/BallotProof">Inspect the source</a>
        </div>
        <p className="disclaimer">Independent infrastructure. Not an election authority. Demo data is synthetic.</p>
      </section>

      <section className="signal shell" aria-label="Core principles">
        <article><strong>Immutable</strong><span>Content-addressed source artifacts</span></article>
        <article><strong>Append-only</strong><span>Machine and human claims remain separate</span></article>
        <article><strong>Signed</strong><span>Ed25519 actor attestations</span></article>
        <article><strong>Source-neutral</strong><span>Discrepancies stay visible</span></article>
      </section>

      <section className="demo shell" id="evidence">
        <div className="sectionCopy">
          <div className="eyebrow">Synthetic demonstration</div>
          <h2>One claim. Every layer exposed.</h2>
          <p>
            A result should never be reduced to a green badge. BallotProof keeps source bytes,
            machine extraction, human review, arithmetic checks, signatures, and disagreements separate.
          </p>
          <div className="actions"><a className="button secondary" href="/evidence/DEMO-PU-001">Inspect DEMO-PU-001</a></div>
        </div>

        <div className="evidenceCard">
          <div className="cardHeader">
            <div><span className="kicker">Polling unit</span><strong>DEMO-PU-001</strong></div>
            <span className="status">Chain verified</span>
          </div>
          <dl className="fingerprint">
            <div><dt>Artifact</dt><dd>EC8A</dd></div>
            <div><dt>SHA-256</dt><dd>7b51...9af2</dd></div>
            <div><dt>Version</dt><dd>2</dd></div>
          </dl>
          <div className="checkList">
            {checks.map(([label, value, status]) => (
              <div className="check" key={label}>
                <span className={`dot ${status}`} aria-hidden="true" />
                <span>{label}</span>
                <code>{value}</code>
              </div>
            ))}
          </div>
          <div className="alert">
            <span className="alertIcon" aria-hidden="true">!</span>
            <div>
              <strong>Machine extraction has a reviewed correction</strong>
              <p>The original model value is preserved beside the reviewer correction; neither silently overwrites the other.</p>
            </div>
          </div>
        </div>
      </section>

      <section className="method shell" id="method">
        <div className="sectionCopy">
          <div className="eyebrow">Trust boundary</div>
          <h2>AI proposes. Rules validate. Humans attest.</h2>
        </div>
        <div className="steps">
          <article><span>01</span><h3>Preserve</h3><p>Fingerprint and retain the original evidence before extraction or transformation.</p></article>
          <article><span>02</span><h3>Extract</h3><p>Store field-level model claims with confidence and model provenance.</p></article>
          <article><span>03</span><h3>Review</h3><p>Record human acceptance, correction, or rejection without destroying the machine claim.</p></article>
          <article><span>04</span><h3>Reconcile</h3><p>Compare evidence sources and expose every unresolved delta.</p></article>
        </div>
      </section>

      <footer className="shell footer">
        <div><strong>BallotProof</strong><p>Evidence, not trust.</p></div>
        <p>Open-source foundation for independently auditable election evidence.</p>
      </footer>
    </main>
  );
}
