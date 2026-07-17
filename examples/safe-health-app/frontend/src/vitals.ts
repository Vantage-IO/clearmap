// Live vitals stream for the bedside monitor view — encrypted transport.

export function connectVitals(patientId: string): WebSocket {
  // PHI streams over an encrypted wss:// connection.
  const socket = new WebSocket(`wss://vitals.clinic.example/stream/${patientId}`);
  return socket;
}
