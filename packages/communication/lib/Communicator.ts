import { AbstractLogger } from '@rosen-bridge/abstract-logger';
import { EncryptionHandler } from '@rosen-bridge/encryption';
import { CommunicationMessage } from './interfaces/types';
import { guardMessageValidTimeoutDefault } from './const/const';

export abstract class Communicator {
  protected logger: AbstractLogger;
  protected signer: EncryptionHandler;
  private readonly submitMessage: (
    msg: string,
    peers: Array<string>,
  ) => unknown;
  protected guardPks: Array<string>;
  protected index = -1;
  protected messageValidDuration: number;

  /**
   * get current timestamp in seconds
   */
  protected getDate = () => Math.floor(Date.now() / 1000);

  protected constructor(
    logger: AbstractLogger,
    signer: EncryptionHandler,
    submitMessage: (msg: string, peers: Array<string>) => unknown,
    guardPks: Array<string>,
    messageValidDurationSeconds?: number,
  ) {
    this.logger = logger;
    this.signer = signer;
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
      const pk = await this.signer.getPk();
      this.index = this.guardPks.indexOf(pk);
    }
    return this.index;
  };

  /**
   * convert payload to signing data for communication
   * @param payload
   * @param timestamp
   * @param publicKey
   */
  static generatePayloadToSign = (
    payload: any,
    timestamp: number,
    publicKey: string,
  ) => {
    return `${JSON.stringify(payload)}${timestamp}${publicKey}`;
  };

  /**
   * sign a payload before submit
   * @param payload
   * @param timestamp
   */
  signPayload = async (payload: any, timestamp: number) => {
    const publicKey = await this.signer.getPk();
    return await this.signer.sign(
      Communicator.generatePayloadToSign(payload, timestamp, publicKey),
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
    const publicKey = await this.signer.getPk();
    const payloadSign = await this.signPayload(payload, timestamp);
    const message: CommunicationMessage = {
      type: messageType,
      payload: payload,
      publicKey,
      timestamp,
      sign: payloadSign,
      index: await this.getIndex(),
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
      !(await this.signer.verify(
        Communicator.generatePayloadToSign(
          msg.payload,
          msg.timestamp,
          msg.publicKey,
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
