import { AbstractLogger } from '@rosen-bridge/abstract-logger';
import { EncryptionHandler } from '@rosen-bridge/encryption';

import { guardMessageValidTimeoutDefault } from './const/const';
import { CommunicationMessage } from './interfaces/types';
import { getVersionSections } from './utils';

export abstract class Communicator {
  protected logger: AbstractLogger;
  protected messageEnc: EncryptionHandler;
  private readonly submitMessage: (
    msg: string,
    peers: Array<string>,
  ) => unknown;
  protected guardPks: Array<string>;
  protected index = -1;
  protected messageValidDuration: number;

  /**
   * semantic version (e.g. `2.0.2`) of this protocol's message envelope and
   * signing scheme, defined by each class extending Communicator. Bump the
   * major component only when this protocol's wire format or message
   * semantics change in a way that's incompatible with older guards; minor
   * and patch changes are assumed compatible. Messages from a peer whose
   * major version differs are rejected in handleMessage. Classes typically
   * set this to their own package.json version, e.g.
   * `import packageJson from '../package.json' with { type: 'json' };`.
   */
  protected abstract readonly protocolVersion: string;

  /**
   * get current timestamp in seconds
   */
  protected getDate = () => Math.floor(Date.now() / 1000);

  protected constructor(
    logger: AbstractLogger,
    messageEnc: EncryptionHandler,
    submitMessage: (msg: string, peers: Array<string>) => unknown,
    guardPks: Array<string>,
    messageValidDurationSeconds?: number,
  ) {
    this.logger = logger;
    this.messageEnc = messageEnc;
    this.guardPks = guardPks;
    this.submitMessage = submitMessage;
    this.messageValidDuration = messageValidDurationSeconds
      ? messageValidDurationSeconds
      : guardMessageValidTimeoutDefault;
  }

  /**
   * get my index
   */
  protected getIndex = async () => {
    if (this.index === -1) {
      const pk = await this.messageEnc.getPk();
      this.index = this.guardPks.indexOf(pk);
      if (this.index == -1)
        throw Error(`Public key ${pk} not found among the listed guardPks`);
    }
    return this.index;
  };

  /**
   * convert payload to signing data for communication
   * @param payload
   * @param timestamp
   * @param publicKey
   * @param version protocol version of the class that produced/received this payload
   */
  static generatePayloadToSign = (
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    payload: any,
    timestamp: number,
    publicKey: string,
    version: string,
  ) => {
    return `${JSON.stringify(payload)}${timestamp}${publicKey}${version}`;
  };

  /**
   * sign a payload before submit
   * @param payload
   * @param timestamp
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  signPayload = async (payload: any, timestamp: number) => {
    const publicKey = await this.messageEnc.getPk();
    return await this.messageEnc.sign(
      Communicator.generatePayloadToSign(
        payload,
        timestamp,
        publicKey,
        this.protocolVersion,
      ),
    );
  };

  /**
   * send a message to other instances.
   * first sign payload and timestamp and send it
   * @param messageType
   * @param payload
   * @param peers
   * @param timestamp
   */
  protected sendMessage = async (
    messageType: string,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    payload: any,
    peers: Array<string>,
    timestamp?: number,
  ) => {
    this.logger.debug(
      `sending new message of type ${messageType} with payload ${JSON.stringify(
        payload,
      )} to ${JSON.stringify(peers)}`,
    );
    timestamp = timestamp ? timestamp : this.getDate();
    const publicKey = await this.messageEnc.getPk();
    const payloadSign = await this.signPayload(payload, timestamp);
    const message: CommunicationMessage = {
      type: messageType,
      payload: payload,
      publicKey,
      timestamp,
      sign: payloadSign,
      index: await this.getIndex(),
      version: this.protocolVersion,
    };
    this.submitMessage(JSON.stringify(message), peers);
  };

  /**
   * child classes must implement this function to handle new incoming messages
   */
  abstract processMessage: (
    type: string,
    payload: unknown,
    signature: string,
    senderIndex: number,
    peerId: string,
    timestamp: number,
  ) => unknown;

  /**
   * handle new message.
   * verify sender index, message sign and valid interval for message
   * @param message
   * @param peerId
   */
  handleMessage = async (message: string, peerId: string) => {
    this.logger.info('new message arrived');
    const msg: CommunicationMessage = JSON.parse(
      message,
    ) as CommunicationMessage;
    const guardPk = this.guardPks[msg.index];
    const messageVersions = getVersionSections(msg.version);
    const currentVersions = getVersionSections(this.protocolVersion);
    if (messageVersions.major !== currentVersions.major) {
      this.logger.warn(
        `Invalid message. Protocol version mismatch (received [${msg.version}], expected [${this.protocolVersion}])`,
      );
      this.logger.debug(message);
      return;
    } else if (messageVersions.minor !== currentVersions.minor) {
      this.logger.debug(
        `Minor protocol version mismatch detected (received [${msg.version}], expected [${this.protocolVersion}])`,
      );
    }
    if (this.getDate() - this.messageValidDuration > msg.timestamp) {
      this.logger.warn('Invalid message. message timed out');
      this.logger.debug(message);
      return;
    }
    if (guardPk !== msg.publicKey) {
      this.logger.warn(
        'Invalid message. Sender index mismatch with sender public key',
      );
      this.logger.debug(message);
      return;
    }
    if (
      !(await this.messageEnc.verify(
        Communicator.generatePayloadToSign(
          msg.payload,
          msg.timestamp,
          msg.publicKey,
          msg.version,
        ),
        msg.sign,
        guardPk,
      ))
    ) {
      this.logger.warn('Invalid message. Message signature is invalid');
      this.logger.debug(message);
      return;
    }
    this.logger.debug('new message arrived');
    await this.processMessage(
      msg.type,
      msg.payload,
      msg.sign,
      msg.index,
      peerId,
      msg.timestamp,
    );
  };

  /**
   * Update guards pk to new set
   * @param newPks
   */
  async changePks(newPks: Array<string>) {
    this.guardPks = [...newPks];
  }
}
