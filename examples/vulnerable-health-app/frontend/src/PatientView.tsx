// The authenticated patient chart view.

import { useEffect } from "react";

import { identifyPatientSession, trackDiagnosisViewed } from "./analytics";
import { cachePatient, stashActivePatient, type Patient } from "./storage";

declare const analytics: { page: (name: string, props: Record<string, unknown>) => void };

export function PatientView({ patient }: { patient: Patient }) {
  useEffect(() => {
    cachePatient(patient);
    stashActivePatient(patient);
    identifyPatientSession(patient);
    trackDiagnosisViewed(patient);

    // TRACKING-01: analytics firing inside an authenticated patient view. A third-party
    // pageview is sent from a screen rendering PHI; the analytics vendor now
    // receives signal tied to a specific patient chart being open.
    analytics.page("PatientChart", { patientId: patient.id });
  }, [patient]);

  // TRACKING-03: URL param reveals health context. Building a share/deep link that puts
  // the patient's condition in a query string leaks the health context into
  // browser history, server logs, and any Referer header sent to third parties.
  const shareLink = `https://clinic.example/chart?mrn=${patient.mrn}&condition=${patient.diagnosis}`;

  return (
    <div>
      <h1>{patient.name}</h1>
      <p>Diagnosis: {patient.diagnosis}</p>
      <a href={shareLink}>Share chart</a>
    </div>
  );
}
