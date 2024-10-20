export interface CommunicationMessage {
  type: string;
  sign: string;
  timestamp: number;
  publicKey: string;
  payload: JSON;
  index: number;
}
