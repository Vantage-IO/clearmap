// Live vitals stream for the bedside monitor view.

export function connectVitals(patientId: string): WebSocket {
  // TRANSIT-02: insecure WebSocket. Real-time vitals (PHI) are streamed over an
  // unencrypted `ws://` connection rather than `wss://`, so the data is
  // transmitted in the clear and is open to interception and tampering.
  const socket = new WebSocket(`ws://vitals.clinic.example/stream/${patientId}`);
  return socket;
}
