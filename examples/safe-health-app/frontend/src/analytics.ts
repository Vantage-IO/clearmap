// Product analytics — opaque ids only, no PHI, no health fields.

import type { Patient } from "./storage";

declare const analytics: {
  identify: (id: string, traits: Record<string, unknown>) => void;
  track: (event: string, props: Record<string, unknown>) => void;
};

// NEAR-MISS (SESSION-04): identify() is called, but only with an opaque id and a
// non-PHI plan tier. No name, MRN, or diagnosis is passed to the vendor.
export function identifySession(patient: Patient): void {
  analytics.identify(patient.id, { plan: "clinic-pro" });
}

// NEAR-MISS (TRACKING-02): an analytics event fires, but it carries only a non-PHI
// interaction signal — no diagnosis or other health field.
export function trackChartOpened(): void {
  analytics.track("chart_opened", { surface: "web" });
}
