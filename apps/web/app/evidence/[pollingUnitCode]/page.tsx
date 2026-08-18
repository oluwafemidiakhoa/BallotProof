import styles from "./page.module.css";

const extractedFields = [
  { field: "Accredited voters", raw: "300", value: "300", confidence: 0.99, review: "Accepted" },
  { field: "Valid votes", raw: "285", value: "285", confidence: 0.98, review: "Accepted" },
  { field: "Candidate A", raw: "160", value: "160", confidence: 0.99, review: "Accepted" },
  { field: "Candidate B", raw: "12S", value: "125", confidence: 0.68, review: "Corrected to 128" },
] as const;

const versions = [
  { version: 1, source: "Observer capture", hash: "31a7…9c2e", time: "14:03:19 WAT" },
  { version: 2, source: "Official publication", hash: "7b51…9af2", time: "14:17:36 WAT" },
] as const;

export function generateStaticParams() {
  return [{ pollingUnitCode: "DEMO-PU-001" }];
}

type PageProps = {
  params: Promise<{ pollingUnitCode: string }>;
};

export default async function PollingUnitEvidencePage({ params }: PageProps) {
  const { pollingUnitCode } = await params;

  return (
    <main className={styles.page}>
      <nav className="nav shell" aria-label="Primary navigation">
        <a className="brand" href="/" aria-label="BallotProof home">
          <span className="brandMark" aria-hidden="true">BP</span>
          <span>BallotProof</span>
        </a>
        <div className="navLinks">
          <a href="/">Home</a>
          <a href="https://github.com/oluwafemidiakhoa/BallotProof">Source</a>
        </div>
      </nav>

      <header className={`shell ${styles.hero}`}>
        <div>
          <div className="eyebrow">Synthetic polling-unit evidence explorer</div>
          <h1 className={styles.title}>{pollingUnitCode}</h1>
          <p className={styles.subtitle}>
            One polling unit, separated into source artifacts, machine claims, deterministic checks,
            human review, and attestations. Nothing below is a real election result.
          </p>
        </div>
        <span className={styles.demoBadge}>Demo evidence</span>
      </header>

      <section className={`shell ${styles.trustGrid}`} aria-label="Evidence state">
        <article><span>Provenance chain</span><strong>Verified</strong><small>2 versions checked</small></article>
        <article><span>Source artifacts</span><strong>2</strong><small>Both retained</small></article>
        <article><span>Attestations</span><strong>2</strong><small>Ed25519 verified</small></article>
        <article><span>Human review</span><strong>1 correction</strong><small>Machine value preserved</small></article>
      </section>

      <section className={`shell ${styles.grid}`}>
        <div className={styles.primaryColumn}>
          <article className={styles.panel}>
            <div className={styles.panelHeading}>
              <div><span className={styles.kicker}>Latest evidence</span><h2>EC8A · version 2</h2></div>
              <span className={styles.goodBadge}>Chain valid</span>
            </div>
            <dl className={styles.metadata}>
              <div><dt>Source</dt><dd>Official publication</dd></div>
              <div><dt>Observed</dt><dd>14:17:36 WAT</dd></div>
              <div><dt>SHA-256</dt><dd><code>7b51a34d…9af2</code></dd></div>
              <div><dt>Record hash</dt><dd><code>4e91c1f0…77b8</code></dd></div>
            </dl>
            <div className={styles.sourcePlaceholder}>
              <div><span>Original source artifact</span><strong>Preserved bytes</strong></div>
              <p>Production deployments render or link the stored artifact here. The explorer never replaces it with an OCR reconstruction.</p>
            </div>
          </article>

          <article className={styles.panel}>
            <div className={styles.panelHeading}>
              <div><span className={styles.kicker}>Machine extraction</span><h2>Field-level uncertainty</h2></div>
              <span className={styles.reviewBadge}>Needs review</span>
            </div>
            <div className={styles.tableWrap}>
              <table className={styles.table}>
                <thead><tr><th>Field</th><th>Raw</th><th>Machine value</th><th>Confidence</th><th>Review</th></tr></thead>
                <tbody>
                  {extractedFields.map((item) => (
                    <tr key={item.field}>
                      <td>{item.field}</td><td><code>{item.raw}</code></td><td>{item.value}</td>
                      <td><span className={item.confidence < 0.8 ? styles.low : styles.high}>{Math.round(item.confidence * 100)}%</span></td>
                      <td>{item.review}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className={styles.reviewNote}>
              <strong>Human correction is additive, not destructive.</strong>
              <p>The model read Candidate B as 125 from raw text “12S”. Reviewer observer:42 recorded 128. Both claims remain visible.</p>
            </div>
          </article>

          <article className={styles.panel}>
            <div className={styles.panelHeading}>
              <div><span className={styles.kicker}>Deterministic validation</span><h2>Checks anyone can reproduce</h2></div>
            </div>
            <div className={styles.checks}>
              <div><span className={styles.passDot} />Candidate totals reconcile with valid votes <code>285 = 285</code></div>
              <div><span className={styles.passDot} />Ballots do not exceed accreditation <code>300 ≤ 300</code></div>
              <div><span className={styles.flagDot} />Comparison source differs for Candidate B <code>+3</code></div>
            </div>
          </article>
        </div>

        <aside className={styles.sidebar}>
          <article className={styles.panel}>
            <span className={styles.kicker}>Version history</span>
            <div className={styles.timeline}>
              {versions.map((item) => (
                <div className={styles.timelineItem} key={item.version}>
                  <span className={styles.timelineDot} />
                  <div><strong>Version {item.version}</strong><p>{item.source}</p><code>{item.hash}</code><small>{item.time}</small></div>
                </div>
              ))}
            </div>
          </article>

          <article className={styles.panel}>
            <span className={styles.kicker}>Attestations</span>
            <div className={styles.attestation}><strong>observer-network:42</strong><span>Reviewed source</span><small>Signature verified</small></div>
            <div className={styles.attestation}><strong>civic-lab:reviewer-7</strong><span>Disputes extraction</span><small>Signature verified</small></div>
          </article>

          <article className={styles.warningPanel}>
            <span className={styles.kicker}>Open discrepancy</span>
            <strong>Source disagreement remains unresolved.</strong>
            <p>BallotProof displays the delta and supporting records. It does not convert disagreement into an accusation or select an authority automatically.</p>
          </article>
        </aside>
      </section>

      <footer className="shell footer">
        <div><strong>BallotProof</strong><p>Evidence, not trust.</p></div>
        <p>Synthetic interface demonstrating the public evidence contract.</p>
      </footer>
    </main>
  );
}
