// PHI canary fixture — every literal here is FAKE and exists only to assert
// that redaction strips it from all ClearMap output. Values are unique and
// greppable; tests/test_phi_leak_e2e.py fails if any appears downstream.

function persistRecord() {
  localStorage.setItem("patient_ssn_record", JSON.stringify({ ssn: "987-65-4329", contact: "jane.canary@example.org", phone: "(555)014-9876", note: "MRN: 4455667" }));
}

function lookupRecord() {
  return fetch("http://api.canary-external-host.com/records?mrn=4455667");
}
