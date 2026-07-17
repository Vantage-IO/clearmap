// Client-side state — no PHI is ever persisted to browser storage.
//
// PHI lives in server-rendered, in-memory React state that is dropped on
// logout/navigation. Only non-PHI UI preferences and opaque tokens touch
// persistent storage. Several lines here are deliberate NEAR-MISSES for
// Category E rules: storage APIs used correctly with no PHI.

export interface Patient {
  id: string;
  name: string;
  mrn: string;
  dob: string;
  diagnosis: string;
}

// NEAR-MISS (SESSION-01): localStorage is used, but only for a non-PHI UI preference.
export function saveTheme(theme: "light" | "dark"): void {
  localStorage.setItem("ui.theme", theme);
}

// NEAR-MISS (SESSION-02): sessionStorage holds an opaque CSRF token, not PHI. The name
// "patientToken" looks PHI-adjacent but the value is a random anti-forgery token.
export function stashCsrfToken(patientToken: string): void {
  sessionStorage.setItem("csrf", patientToken);
}

// NEAR-MISS (SESSION-03): a cookie is set, but it is an opaque, non-PHI session ref.
export function setSessionRef(ref: string): void {
  document.cookie = `sessionRef=${ref}; Secure; SameSite=Strict; path=/`;
}
