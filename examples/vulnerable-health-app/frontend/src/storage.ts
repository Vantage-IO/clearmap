// Client-side caching of patient data for a snappier UI.
//
// This module is the Category E cluster: PHI written to browser-persisted
// storage where it survives logout, is readable by any script on the origin,
// and is exfiltrated by anything with DOM access.

export interface Patient {
  id: string;
  name: string;
  mrn: string;
  dob: string;
  diagnosis: string;
}

export function cachePatient(patient: Patient): void {
  // SESSION-01: PHI in localStorage. The full patient object (name, MRN, diagnosis)
  // is persisted to localStorage, where it remains after logout and is
  // accessible to every script and browser extension on the origin.
  localStorage.setItem(`patient:${patient.id}`, JSON.stringify(patient));
}

export function stashActivePatient(patient: Patient): void {
  // SESSION-02: PHI in sessionStorage. The active patient's chart is written to
  // sessionStorage, exposing PHI to any XSS on the page for the session.
  sessionStorage.setItem("activePatient", JSON.stringify(patient));
}

export function rememberRecentMrn(patient: Patient): void {
  // SESSION-03: PHI in a cookie. The MRN is written into a non-HttpOnly cookie,
  // readable by JavaScript and sent on every request to the origin.
  document.cookie = `recentMrn=${patient.mrn}; path=/`;
}

export function cacheAppState(patientChart: Patient): void {
  // SESSION-06: PHI under a BENIGN key. The key ("appState") looks harmless, but
  // the value serializes a PHI-named object, so the chart still lands in storage.
  localStorage.setItem("appState", JSON.stringify(patientChart));
}
