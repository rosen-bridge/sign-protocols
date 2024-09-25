import { EncryptionHandler } from '../abstract';
import * as ed from '@noble/ed25519';
import { blake2b } from '@noble/hashes/blake2b';

ed.etc.sha512Sync = (...m) => blake2b(ed.etc.concatBytes(...m));

class EdDSA extends EncryptionHandler {
  private readonly key: Uint8Array;

  constructor(key: string) {
    super();
    this.key = Uint8Array.from(Buffer.from(key, 'hex'));
  }

  /**
   * get public key
   */
  getPk = async () => {
    return Buffer.from(await ed.getPublicKey(this.key)).toString('hex');
  };

  /**
   * sign message
   * @param message
   */
  sign = async (message: string): Promise<string> => {
    return Buffer.from(ed.sign(Buffer.from(message), this.key)).toString('hex');
  };

  /**
   * verify message signature
   * @param message
   * @param signature
   * @param signerPublicKey
   */
  verify = async (
    message: string,
    signature: string,
    signerPublicKey: string,
  ): Promise<boolean> => {
    const msg = Buffer.from(message);
    const sign = Buffer.from(signature, 'hex');
    const publicKey = Buffer.from(signerPublicKey, 'hex');
    return ed.verify(sign, msg, publicKey);
  };

  /**
   * get current algorithm
   */
  getCrypto = () => 'eddsa';
}

export { EdDSA };
