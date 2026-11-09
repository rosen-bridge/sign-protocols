export interface CommunicationMessage {
  type: string;
  sign: string;
  timestamp: number;
  publicKey: string;
  payload: JSON;
  index: number;
  version: string | undefined;
}

/**
 * a decoded `<version>:<raw signature>` signature
 */
export interface VersionedSignature {
  /**
   * protocol version the signature was produced with
   */
  version: string;
  /**
   * raw signature produced by the encryption handler
   */
  rawSignature: string;
}
