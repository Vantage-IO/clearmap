// Client observability + user identification wired to third-party SDKs.

import type { Patient } from "./storage";

declare const datadogRum: { init: (cfg: Record<string, unknown>) => void };
declare const analytics: { setUser: (traits: Record<string, unknown>) => void };

export function initObservability(): void {
  // TRACKING-04: session replay records the full patient screen (fields, notes,
  // identifiers) and ships it to a third-party vendor.
  datadogRum.init({
    applicationId: "00000000-0000-4000-8000-000000000000",
    clientToken: "puba1b2c3d4e5f60718293a4b5c6d7e8f",
    site: "datadoghq.com",
    sessionReplaySampleRate: 100,
    trackUserInteractions: true,
  });
}

export function identifyUser(patient: Patient): void {
  // SESSION-05: PHI (name, MRN, DOB) passed to a third-party setUser call.
  analytics.setUser({ name: patient.name, mrn: patient.mrn, dob: patient.dob });
}
