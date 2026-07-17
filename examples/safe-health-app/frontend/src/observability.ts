// Client-side observability + i18n config. Everything in this file is public
// by design — these are the real-world false-positive classes ClearMap's
// secret detection must NOT flag.

declare const datadogRum: { init: (cfg: Record<string, unknown>) => void };

// NEAR-MISS (SECRETS): a Datadog RUM client token is publishable — it ships in
// the browser bundle by design (marker: "pub" + hex). Not a secret.
export function initObservability(): void {
  datadogRum.init({
    applicationId: "00000000-0000-4000-8000-000000000000",
    clientToken: "puba1b2c3d4e5f60718293a4b5c6d7e8f",
    site: "datadoghq.com",
  });
}

// NEAR-MISS (SECRETS): a support-widget embed URL carries a public key= UUID;
// it is served to every visitor and is not a credential.
export const SUPPORT_WIDGET_SRC =
  "https://static.widget-cdn.example/snippet.js?key=11111111-2222-4333-8444-555555555555";

// NEAR-MISS (SECRETS): i18n label keys look like `somethingKey: "...":` pairs;
// the values are translation-catalog paths, not secret material.
export const SURVEY_OPTIONS = [
  { value: "option_a", labelKey: "q1_option_a" },
  { value: "option_b", labelKey: "survey.q1.option_b" },
];
