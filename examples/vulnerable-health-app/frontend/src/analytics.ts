// Product analytics wiring (Segment-style third-party SDK).

import type { Patient } from "./storage";

declare const analytics: {
  identify: (id: string, traits: Record<string, unknown>) => void;
  track: (event: string, props: Record<string, unknown>) => void;
};

export function identifyPatientSession(patient: Patient): void {
  // SESSION-04: patient state passed to a third-party SDK. The patient's identity and
  // clinical data are handed to the analytics vendor via `identify`, shipping
  // PHI off to a third party that has no BAA and no clinical purpose.
  analytics.identify(patient.id, {
    name: patient.name,
    mrn: patient.mrn,
    diagnosis: patient.diagnosis,
  });
}

export function trackDiagnosisViewed(patient: Patient): void {
  // TRACKING-02: health-field analytics event. The diagnosis (a health field) is sent
  // as an analytics event property, so the tracking pipeline now carries the
  // patient's condition.
  analytics.track("diagnosis_viewed", {
    patientId: patient.id,
    diagnosis: patient.diagnosis,
  });
}
