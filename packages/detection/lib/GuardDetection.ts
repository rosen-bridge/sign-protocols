import { Communicator } from '@rosen-bridge/communication';
import { DummyLogger } from '@rosen-bridge/abstract-logger';
import {
  ActiveGuard,
  DetectionApprovePayload,
  GuardDetectionConfig,
  GuardInfo,
  DetectionHeartbeatPayload,
  DetectionMessageType,
  Nonce,
  DetectionRegisterPayload,
} from './interfaces/types';
import {
  guardHeartbeatTimeoutDefault,
  guardActiveTimeoutDefault,
} from './const/const';
import {
  approveMessage,
  heartbeatMessage,
  registerMessage,
} from './const/detection';

export class GuardDetection extends Communicator {
  protected guardsInfo: Array<GuardInfo> = [];
  protected readonly activeTimeout: number;
  protected needGuardThreshold: number;
  protected readonly heartbeatTimeout: number;
  protected readonly getPeerId: () => Promise<string>;

  /**
   * set needed guards count.
   * this value can change during execution
   * @param needGuardThreshold
   */
  setNeedGuardThreshold = (needGuardThreshold: number) => {
    this.needGuardThreshold = needGuardThreshold;
  };

  constructor(config: GuardDetectionConfig) {
    super(
      config.logger ? config.logger : new DummyLogger(),
      config.messageEnc,
      config.submit,
      config.guardsPublicKey,
      config.messageValidDurationSeconds,
    );
    this.needGuardThreshold = 0;
    this.activeTimeout =
      config.activeTimeoutSeconds || guardActiveTimeoutDefault;
    this.heartbeatTimeout =
      config.heartbeatTimeoutSeconds || guardHeartbeatTimeoutDefault;
    this.guardsInfo = config.guardsPublicKey.map((item, index) => ({
      peerId: '',
      nonce: [],
      lastUpdate: 0,
      publicKey: item,
      callback: [],
      index: index,
    }));
    this.getPeerId = config.getPeerId;
  }

  /**
   * add new random nonce to guards info and return it
   * @param index if undefined add one nonce to all guards otherwise add to selected guard
   */
  protected addNonce = (index?: number) => {
    this.clearNonce();
    const nonce = new Nonce();
    if (index) {
      const info = this.guardsInfo[index];
      info.nonce.push(nonce);
    } else {
      this.guardsInfo.forEach((info) => info.nonce.push(nonce));
    }
    return nonce.bytes;
  };

  /**
   * clear all timed out nonce
   */
  protected clearNonce = () => {
    const cleanupTime = this.getDate() - this.messageValidDuration;
    this.guardsInfo.forEach((info) => {
      const index = info.nonce.findIndex(
        (nonce) => nonce.timestamp > cleanupTime,
      );
      info.nonce.splice(0, index === -1 ? info.nonce.length : index);
    });
  };

  /**
   * Initialize the guard detection
   * @returns
   */
  init = async (): Promise<void> => {
    if (
      this.guardsInfo.filter(
        (item) =>
          (item.peerId === '' ||
            item.lastUpdate < this.getDate() - this.activeTimeout) &&
          item.nonce.length === 0,
      ).length > 0
    ) {
      const nonce = this.addNonce();
      await this.sendMessage(registerMessage, { nonce }, []);
      this.clearNonce();
    }
  };

  /**
   * send heartbeat to all guards if required.
   * if more than half of guards are inactive send register message
   */
  update = async (): Promise<void> => {
    this.clearNonce();
    if ((await this.activeGuards()).length < this.needGuardThreshold) {
      await this.init();
    } else {
      // TODO: improve the performance of TSS functions
      //  local:ergo/rosen-bridge/sign-protocols#18
      const timedOutIndexes = this.guardsInfo
        .map((item, index) =>
          item.peerId !== '' &&
          item.lastUpdate < this.getDate() - this.heartbeatTimeout &&
          item.nonce.length == 0
            ? index
            : -1,
        )
        .filter((item) => item !== -1);
      for (const index of timedOutIndexes) {
        const nonce = this.addNonce(index);
        await this.sendMessage(
          heartbeatMessage,
          {
            nonce: nonce,
          },
          [this.guardsInfo[index].peerId],
        );
      }
    }
  };

  /**
   * handle receive message according to message type
   * @public
   * @param messageType
   * @param payload
   * @param sign
   * @param senderIndex
   * @param peerId
   * @param timestamp
   */
  processMessage = async (
    messageType: string,
    payload: unknown,
    sign: string,
    senderIndex: number,
    peerId: string,
    timestamp: number,
  ): Promise<void> => {
    switch (messageType as DetectionMessageType) {
      case approveMessage:
        await this.handleApproveMessage(
          payload as DetectionApprovePayload,
          peerId,
          senderIndex,
        );
        return;
      case heartbeatMessage:
        await this.handleHeartbeatMessage(
          payload as DetectionHeartbeatPayload,
          peerId,
          senderIndex,
        );
        return;
      case registerMessage:
        await this.handleRegisterMessage(
          payload as DetectionRegisterPayload,
          peerId,
          senderIndex,
        );
        return;
    }
  };

  /**
   * handle Register message from other node in the network and send approval
   * message with new nonce
   * @param registerPayload - RegisterPayload
   * @param sender - public key of sender
   * @param guardIndex
   * @protected
   */
  protected handleRegisterMessage = async (
    registerPayload: DetectionRegisterPayload,
    sender: string,
    guardIndex: number,
  ): Promise<void> => {
    try {
      const receivedNonce = registerPayload.nonce;
      const nonce = this.addNonce(guardIndex);
      await this.sendMessage(
        approveMessage,
        {
          nonce: nonce,
          receivedNonce: receivedNonce,
        },
        [sender],
      );
      this.logger.debug(
        `Sent approval to register request of guard [${guardIndex}]`,
      );
    } catch (e) {
      this.logger.warn(
        `An Error occurred while handling register message: ${e}`,
      );
      if (e instanceof Error && e.stack) {
        this.logger.warn(e.stack);
      }
    }
  };

  /**
   * handle approval message from other node in the network
   * @param approvePayload - ApprovePayload
   * @param sender - public key of sender
   * @param guardIndex
   * @protected
   */
  protected handleApproveMessage = async (
    approvePayload: DetectionApprovePayload,
    sender: string,
    guardIndex: number,
  ): Promise<void> => {
    try {
      const receivedNonce = approvePayload.receivedNonce;
      const nonce = approvePayload.nonce;
      const guard = this.guardsInfo[guardIndex];
      this.clearNonce();
      if (
        guard.nonce.filter((nonce) => nonce.bytes === receivedNonce).length > 0
      ) {
        guard.peerId = sender;
        guard.lastUpdate = this.getDate();
        guard.callback.forEach((resolve) => resolve(true));
        guard.callback = [];
        guard.nonce.splice(0, guard.nonce.length);
        if (nonce) {
          const payload: DetectionApprovePayload = {
            receivedNonce: nonce,
          };
          await this.sendMessage(approveMessage, payload, [sender]);
          this.logger.debug(
            `Sent approval to register message guard with index [${guardIndex}]`,
          );
        }
      } else {
        this.logger.warn(
          `Received nonce from guard with index [${guardIndex}] is not valid`,
        );
      }
    } catch (e) {
      this.logger.warn(
        `An Error occurred while handling approval message: ${e}`,
      );
      if (e instanceof Error && e.stack) {
        this.logger.warn(e.stack);
      }
    }
  };

  /**
   * handle Heartbeat message from other node in the network and send approval message
   * to sender of heartbeat message
   * @param heartbeatPayload - HeartbeatPayload
   * @param sender - public key of sender
   * @param guardIndex
   * @protected
   */
  protected handleHeartbeatMessage = async (
    heartbeatPayload: DetectionHeartbeatPayload,
    sender: string,
    guardIndex: number,
  ): Promise<void> => {
    try {
      const nonce = heartbeatPayload.nonce;
      const payload: DetectionApprovePayload = {
        receivedNonce: nonce,
      };
      await this.sendMessage(approveMessage, payload, [sender]);
      this.logger.debug(
        `Sent approval message to heartbeat message guard with index [${guardIndex}]`,
      );
    } catch (e) {
      this.logger.warn(
        `An Error occurred while handling heartbeat message: ${e}`,
      );
      if (e instanceof Error && e.stack) {
        this.logger.warn(e.stack);
      }
    }
  };

  /**
   * Checks if guard is active or not by checking the last update time is
   * less than `guardsRegisterTimeout`
   * @param guardIndex
   * @protected
   */
  protected isGuardActive = (guardIndex: number) => {
    const currentTime = this.getDate();
    return (
      this.guardsInfo[guardIndex].peerId !== '' &&
      currentTime - this.guardsInfo[guardIndex].lastUpdate < this.activeTimeout
    );
  };

  /**
   * get active guards publicKey and peerId
   * @public
   * @returns array of guards publicKey and peerIds
   */
  activeGuards = async (): Promise<Array<ActiveGuard>> => {
    const myActiveGuard: ActiveGuard = {
      publicKey: await this.messageEnc.getPk(),
      peerId: await this.getPeerId(),
      index: this.index,
    };
    return [
      ...this.guardsInfo
        .filter((item, index) => this.isGuardActive(index))
        .map((item) => ({
          peerId: item.peerId,
          publicKey: item.publicKey,
          index: item.index,
        })),
      myActiveGuard,
    ].sort((item1, item2) => item1.publicKey.localeCompare(item2.publicKey));
  };

  /**
   * Register new guard to the class
   * @param peerId
   * @param publicKey
   * @param callback
   */
  register = async (
    peerId: string,
    publicKey: string,
    callback: (status: boolean, message?: string) => unknown,
  ) => {
    const guardIndex = this.guardPks.indexOf(publicKey);
    if (guardIndex === -1) {
      callback(false, 'Guard not found');
      return;
    }
    const guard = this.guardsInfo[guardIndex];
    if (guard.peerId === '' || !this.isGuardActive(guardIndex)) {
      try {
        guard.callback.push(callback);
        const nonce = new Nonce();
        guard.nonce.push(nonce);
        await this.sendMessage(registerMessage, { nonce: nonce.bytes }, [
          peerId,
        ]);
        this.clearNonce();
      } catch (e) {
        this.logger.warn(`An Error occurred while registering guard: ${e}`);
        if (e instanceof Error && e.stack) {
          this.logger.warn(e.stack);
        }
        callback(false, 'Error while registering guard');
      }
    } else {
      if (this.guardsInfo[guardIndex].peerId !== peerId) {
        callback(false, 'PeerId is not the same');
      } else {
        callback(true);
      }
    }
  };

  /**
   * Register new guard to the class returning promise
   * @param peerId
   * @param publicKey
   */
  registerPromised = async (
    peerId: string,
    publicKey: string,
  ): Promise<boolean> => {
    return new Promise<boolean>((resolve, reject) => {
      this.register(peerId, publicKey, (status: boolean, reason?: string) => {
        if (status) resolve(true);
        reject(new Error(reason));
      }).then(() => null);
    });
  };

  /**
   * Update guards pk to new set
   * @param newPks
   */
  changePks = async (newPks: Array<string>) => {
    await super.changePks(newPks);
    this.guardsInfo = newPks.map((item, index) => ({
      peerId: '',
      nonce: [],
      lastUpdate: 0,
      publicKey: item,
      callback: [],
      index: index,
    }));
    await this.update();
  };
}
