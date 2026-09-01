import { randomBytes } from 'crypto';

export abstract class EncryptionHandler {
  /**
   * sign a message with its own private key
   */
  abstract sign: (message: string) => Promise<string>;

  /**
   * verify a message with sender public key
   */
  abstract verify: (
    message: string,
    signature: string,
    signerPublicKey: string,
  ) => Promise<boolean>;

  /**
   * get used crypto algorithm
   */
  abstract getCrypto: () => string;

  /**
   * get my public key
   */
  abstract getPk: () => Promise<string>;

  /**
   * generate a random secret key
   */
  static randomKey = async (): Promise<string> => {
    return randomBytes(32).toString('hex');
  };
}
