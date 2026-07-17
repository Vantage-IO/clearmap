// The authenticated patient chart view — no third-party tracking of PHI.

import { identifySession, trackChartOpened } from "./analytics";
import type { Patient } from "./storage";

export function PatientView({ patient }: { patient: Patient }) {
  // PHI is held in transient in-memory props only — never cached, never sent
  // to a third-party SDK. Only a non-PHI interaction signal is tracked.
  identifySession(patient);
  trackChartOpened();

  // Records are referenced by opaque id; no health context in the URL.
  const shareLink = `https://clinic.example/chart?ref=${patient.id}`;

  return (
    <div>
      <h1>{patient.name}</h1>
      <p>Diagnosis: {patient.diagnosis}</p>
      <a href={shareLink}>Share chart</a>
      {/* NEAR-MISS (TRANSIT): an SVG xmlns is a constant XML namespace
          identifier, not a network endpoint — nothing is transmitted to it. */}
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="16">
        <path d="M12 2a10 10 0 100 20 10 10 0 000-20z" />
      </svg>
    </div>
  );
}
