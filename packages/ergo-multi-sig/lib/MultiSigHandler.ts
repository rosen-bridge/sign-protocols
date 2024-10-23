import * as wasm from 'ergo-lib-wasm-nodejs';
import {
  CommitmentPayload,
  CommunicationMessage,
  ErgoMultiSigConfig,
  GenerateCommitmentPayload,
  InitiateSignPayload,
  SignedTxPayload,
  Signer,
  SignPayload,
  TxQueued,
  MessageType,
} from './types';
import { turnTime } from './const';
import { Semaphore } from 'await-semaphore';
import { ECDSA } from '@rosen-bridge/encryption';
import { MultiSigUtils } from './MultiSigUtils';
import { AbstractLogger, DummyLogger } from '@rosen-bridge/abstract-logger';
import { ActiveGuard, GuardDetection } from '@rosen-bridge/detection';

export class MultiSigHandler {
  protected logger: AbstractLogger;
  private readonly submitMessage: (
    msg: string,
    peers: Array<string>,
  ) => unknown;
  private readonly getPeerId: () => Promise<string>;
  private readonly getPeerPks: () => string[];
  private readonly multiSigUtilsInstance: MultiSigUtils;
  private readonly transactions: Map<string, TxQueued>;
  private readonly secret: Uint8Array;
  private readonly txSignTimeout: number;
  private prover?: wasm.Wallet;
  private index?: number;
  private semaphore = new Semaphore(1);
  private guardDetection: GuardDetection;
  private publicKey?: string;
  private encryption: ECDSA;

  constructor(config: ErgoMultiSigConfig) {
    this.logger = config.logger ? config.logger : new DummyLogger();
    this.transactions = new Map<string, TxQueued>();
    this.secret = Buffer.from(config.secretHex, 'hex');
    this.txSignTimeout = config.txSignTimeout;
    this.multiSigUtilsInstance = config.multiSigUtilsInstance;
    this.submitMessage = config.submit;
    this.getPeerId = config.getPeerId;
    this.getPeerPks = config.getPeerPks;
    this.guardDetection = config.guardDetection;
    this.encryption = new ECDSA(config.secretHex);
  }

  /**
   * getting all peers without initializing IDs
   */
  peers = (): Signer[] => {
    return this.getPeerPks().map((pub) => ({ pub }));
  };

  /**
   * getting all peers with their IDs (if they are active, otherwise undefined)
   */
  peersWithIds = async (): Promise<Signer[]> => {
    const activeGuards = await this.guardDetection.activeGuards();
    return this.getPeerPks().map((pub) => {
      const guard = activeGuards.find((guard) => guard.publicKey === pub);
      return { pub, id: guard?.peerId };
    });
  };

  /**
   * getting the current turn index
   */
  public getCurrentTurnInd = (): number => {
    // every turnTime the turn changes to the next guard
    return Math.floor(new Date().getTime() / turnTime) % this.peers().length;
  };

  /**
   * getting id for the guard with the current turn, undefined if not active
   */
  public getCurrentTurnId = async (): Promise<string | undefined> => {
    try {
      const activeGuards = await this.guardDetection.activeGuards();
      const currentTurnPk = this.peers()[this.getCurrentTurnInd()].pub;
      return activeGuards.filter(
        (guard: ActiveGuard) => guard.publicKey === currentTurnPk,
      )[0].peerId;
    } catch (e) {
      return undefined;
    }
  };

  /**
   * checks if it's this peer's turn to sign
   */
  public isMyTurn = (): boolean => {
    return this.getIndex() === this.getCurrentTurnInd();
  };

  /**
   * checks if peers initiated using guards public keys, throws error if not
   */
  peersMustBeInitialized = (): void => {
    if (this.peers().length === 0)
      throw Error(
        `Cannot proceed MultiSig action, public keys are not provided yet`,
      );
  };

  /**
   * getting the index of the guard
   */
  getIndex = (): number => {
    if (this.index === undefined) {
      const pub = this.getPk();
      this.index = this.peers()
        .map((peer) => peer.pub)
        .indexOf(pub);
    }
    if (this.index !== undefined) return this.index;
    throw Error('Secret key does not match with any guard public keys');
  };

  /**
   * getting this guard's public key
   */
  getPk = (): string => {
    if (!this.publicKey) {
      const secret = wasm.SecretKey.dlog_from_bytes(this.secret);
      this.publicKey = Buffer.from(
        secret.get_address().content_bytes(),
      ).toString('hex');
    }
    return this.publicKey;
  };

  /**
   * get a transaction object from queued transactions.
   * @param txId transaction id to get
   */
  getQueuedTransaction = (
    txId: string,
  ): Promise<{ transaction: TxQueued; release: () => void }> => {
    return this.semaphore.acquire().then((release) => {
      try {
        const transaction = this.transactions.get(txId);
        if (transaction) return { transaction, release };
        const newTransaction: TxQueued = {
          boxes: [],
          dataBoxes: [],
          signs: {},
          commitments: {},
          commitmentSigns: {},
          createTime: new Date().getTime(),
          requiredSigner: 0,
          coordinator: -1,
        };
        this.transactions.set(txId, newTransaction);
        return { transaction: newTransaction, release };
      } catch (e) {
        release();
        throw e;
      }
    });
  };

  /**
   * begin sign a multi-sig transaction.
   * @param tx reduced transaction for multi-sig transaction
   * @param requiredSign number of required signs
   * @param boxes input boxes for transaction
   * @param dataBoxes data input boxes for transaction
   */
  public sign = (
    tx: wasm.ReducedTransaction,
    requiredSign: number,
    boxes: Array<wasm.ErgoBox>,
    dataBoxes?: Array<wasm.ErgoBox>,
  ): Promise<wasm.Transaction> => {
    this.peersMustBeInitialized();
    return new Promise<wasm.Transaction>((resolve, reject) => {
      this.getQueuedTransaction(tx.unsigned_tx().id().to_str())
        .then(({ transaction, release }) => {
          transaction.tx = tx;
          transaction.boxes = boxes;
          transaction.dataBoxes = dataBoxes ? dataBoxes : [];
          transaction.resolve = resolve;
          transaction.reject = reject;
          transaction.requiredSigner = requiredSign;
          this.generateCommitment(tx.unsigned_tx().id().to_str());
          release();
        })
        .catch((e) => {
          this.logger.error(`Error in signing MultiSig transaction: ${e}`);
          this.logger.error(e.stack);
          reject(e);
        });
    });
  };

  /**
   * send a message to other guards. it can be sent to all guards or specific guard
   * @param message message
   * @param receivers if set we sent to this list of guards only. otherwise, broadcast it.
   */
  sendMessage = async (
    message: CommunicationMessage,
    receivers?: Array<string>,
  ): Promise<void> => {
    const payload = message.payload;
    payload.index = this.getIndex();
    payload.id = await this.getPeerId();
    const payloadStr = JSON.stringify(message.payload);
    message.sign = Buffer.from(
      await this.encryption.sign(payloadStr),
      'hex',
    ).toString('base64');
    if (receivers && receivers.length) {
      await this.submitMessage(JSON.stringify(message), receivers);
    } else {
      this.submitMessage(JSON.stringify(message), []);
    }
  };

  /**
   * getting prover that makes with guard secrets
   */
  getProver = (): wasm.Wallet => {
    if (!this.prover) {
      const secret = wasm.SecretKey.dlog_from_bytes(this.secret);
      const secretKeys = new wasm.SecretKeys();
      secretKeys.add(secret);
      this.prover = wasm.Wallet.from_secrets(secretKeys);
    }
    if (this.prover) return this.prover;
    throw Error('Cannot create prover in MultiSig');
  };

  /**
   * generating commitment for transaction in the queue by id and send it to the peer with the correct turn
   * @param txId transaction id to generate commitment for
   */
  generateCommitment = async (txId: string): Promise<void> => {
    const currentTurn = this.getCurrentTurnInd();
    const currentTurnId = await this.getCurrentTurnId();
    if (currentTurnId === undefined) {
      this.logger.debug(
        `Cannot generate and send commitment for tx [${txId}] because the peer with the correct turn is not initialized yet.`,
      );
      return;
    }

    const transaction = this.transactions.get(txId);
    if (transaction && transaction.tx) {
      transaction.coordinator = currentTurn;

      transaction.secret =
        this.getProver().generate_commitments_for_reduced_transaction(
          transaction.tx,
        );

      // publishable commitment
      const myPub = this.getPk();
      transaction.commitments[myPub] =
        MultiSigUtils.toReducedPublishedCommitments(transaction.secret, myPub);

      const publishCommitments = MultiSigUtils.toReducedPublishedCommitments(
        transaction.secret,
        myPub,
      );
      this.logger.debug(
        `Commitment generated for tx [${txId}]. Broadcasting to the peer with the correct turn...`,
      );
      // don't send if it's my turn
      if (!this.isMyTurn())
        await this.sendMessage(
          {
            type: MessageType.Commitment,
            payload: {
              txId: txId,
              commitment: publishCommitments,
            },
          },
          [currentTurnId],
        );
    }
  };

  /**
   * handle verified commitment message from other guards
   * if enough commitments, it will initiate signing
   * @param sender sender for this commitment
   * @param payload user commitment
   * @param signature signature for this commitment message
   */
  handleCommitment = async (
    sender: string,
    payload: CommitmentPayload,
    signature: string,
  ): Promise<void> => {
    if (!this.isMyTurn()) {
      this.logger.debug(
        `Received commitment from [${sender}] but it's not my turn.`,
      );
      return;
    }

    if (payload.index !== undefined && payload.txId) {
      const index = payload.index;
      const pub = this.peers()[index].pub;
      const { transaction, release } = await this.getQueuedTransaction(
        payload.txId,
      );

      if (transaction.tx === undefined || transaction.secret === undefined) {
        this.logger.debug(
          `Received commitment for tx [${payload.txId}] but the transaction is not properly in the queue yet.`,
        );
        release();
        return;
      }

      // if enough commitments, we do not need to process new commitments
      const commits = Object.values(transaction.commitments);
      if (commits.length < transaction.requiredSigner) {
        try {
          transaction.commitments[pub] = payload.commitment;
          transaction.commitmentSigns[pub] = signature;

          const myPub = this.getPk();

          if (
            Object.keys(transaction.commitments).length >=
            transaction.requiredSigner
          ) {
            this.logger.debug(`Tx [${payload.txId}] has enough commitments.`);

            const willSignPubs = Object.keys(transaction.commitments);
            const willSignInds = willSignPubs.map((pub) =>
              this.peers()
                .map((peer) => peer.pub)
                .indexOf(pub),
            );
            const simulated = this.peers()
              .filter((peer) => !willSignPubs.includes(peer.pub))
              .map((peer) => peer.pub);

            const hints = MultiSigUtils.publishedCommitmentsToHintBag(
              Object.values(transaction.commitments),
              willSignPubs,
              transaction.tx,
            );
            const hintsCopy = wasm.TransactionHintsBag.from_json(
              JSON.stringify(hints.to_json()),
            );
            const signedTxSim =
              MultiSigUtils.getEmptyProver().sign_reduced_transaction_multi(
                transaction.tx,
                hintsCopy,
              );

            const simHints = await this.multiSigUtilsInstance.extract_hints(
              signedTxSim,
              transaction.boxes,
              transaction.dataBoxes,
              [],
              simulated,
            );
            MultiSigUtils.add_hints(hints, simHints, transaction.tx);

            transaction.simulatedBag = simHints;
            const simHintsPublish =
              MultiSigUtils.toReducedPublishedCommitmentsArray(
                simHints,
                simulated,
              );
            const simPublishedProofs =
              MultiSigUtils.toReducedPublishedProofsArray(simHints, simulated);

            MultiSigUtils.add_hints(hints, transaction.secret, transaction.tx);
            const signedTx = this.getProver().sign_reduced_transaction_multi(
              transaction.tx,
              hints,
            );

            const myHint = await this.multiSigUtilsInstance.extract_hints(
              signedTx,
              transaction.boxes,
              transaction.dataBoxes,
              [myPub],
              [],
            );
            transaction.signs[myPub] = MultiSigUtils.hintBagToPublishedProof(
              myHint,
              myPub,
            );

            const signPayload = {
              txId: payload.txId,
              committedInds: willSignInds,
              cmts: Object.values(transaction.commitments),
              simulated: simHintsPublish,
              simulatedProofs: simPublishedProofs,
            };

            const toSendPeers: string[] = (await this.peersWithIds())
              .filter((peer) => {
                return Object.keys(transaction.commitments).includes(peer.pub);
              })
              .map((peer) => peer.id)
              .filter((id): id is string => id !== undefined);

            this.logger.debug(
              `All commitments received for tx [${payload.txId}]. Initiating sign...`,
            );

            release();
            await this.sendMessage(
              {
                type: MessageType.InitiateSign,
                payload: signPayload,
                sign: '',
              },
              toSendPeers,
            );
          }
        } catch (e) {
          this.logger.warn(
            `An unknown exception occurred while handling commitment from other peer: ${e}`,
          );
          if (e instanceof Error && e.stack) this.logger.warn(e.stack);
        }
      } else {
        this.logger.debug(
          'A new commitment has been received for a transaction that has sufficient commitment.',
        );
      }
      release();
    }
  };

  /**
   * all peers partially sing the transaction and send the proof to the peer with the correct turn
   * @param sender the peer who initiated the sign
   * @param payload initiate sign payload
   */
  initiateSign = async (
    sender: string,
    payload: InitiateSignPayload,
  ): Promise<void> => {
    const currentTurn = this.getCurrentTurnInd();
    if (currentTurn !== payload.index) {
      this.logger.debug(
        `Received initiate sign from [${sender}] but it's not that guard's turn.`,
      );
      return;
    }
    this.logger.debug(`Initiating sign for tx [${payload.txId}]...`);
    try {
      const { transaction, release } = await this.getQueuedTransaction(
        payload.txId,
      );
      if (transaction.tx === undefined || transaction.secret === undefined) {
        this.logger.debug(
          `Received initiate sign for tx [${payload.txId}] but the transaction is not properly in the queue yet.`,
        );
        release();
        return;
      }
      const myPub = this.getPk();
      const signed = payload.committedInds.map((ind) => this.peers()[ind].pub);
      const simulated = this.peers()
        .filter((peer) => !signed.includes(peer.pub))
        .map((peer) => peer.pub);

      const hints = wasm.TransactionHintsBag.empty();
      const cmtHints = MultiSigUtils.publishedCommitmentsToHintBag(
        payload.cmts,
        signed,
        transaction.tx,
      );
      MultiSigUtils.add_hints(hints, cmtHints, transaction.tx);

      const simHints = MultiSigUtils.publishedCommitmentsToHintBag(
        payload.simulated,
        simulated,
        transaction.tx,
        'cmtSimulated',
      );
      MultiSigUtils.add_hints(hints, simHints, transaction.tx);

      const simProofs = MultiSigUtils.publishedProofsToHintBag(
        payload.simulatedProofs,
        simulated,
        transaction.tx,
        'proofSimulated',
      );
      MultiSigUtils.add_hints(hints, simProofs, transaction.tx);

      MultiSigUtils.add_hints(hints, transaction.secret, transaction.tx);

      const partial = this.getProver().sign_reduced_transaction_multi(
        transaction.tx,
        hints,
      );
      const signer = [myPub];
      const myHints = await this.multiSigUtilsInstance.extract_hints(
        partial,
        transaction.boxes,
        transaction.dataBoxes,
        signer,
        [],
      );
      const proof = MultiSigUtils.hintBagToPublishedProof(myHints, myPub);

      const signPayload = {
        proof: proof,
        txId: payload.txId,
      };

      release();
      await this.sendMessage(
        { type: MessageType.Sign, payload: signPayload, sign: '' },
        [sender],
      );
    } catch (e) {
      this.logger.warn(
        `An unknown exception occurred while handling initiate sign from other peer: ${e}`,
      );
    }
  };

  /**
   * the peer with the correct turn collects partial proofs and signs the transaction when all proofs are collected
   * will send the signed transaction to all peers
   * @param sender sender of the proof
   * @param payload proof payload
   */
  handleSign = async (sender: string, payload: SignPayload): Promise<void> => {
    try {
      const { transaction, release } = await this.getQueuedTransaction(
        payload.txId,
      );
      if (
        transaction.tx === undefined ||
        transaction.simulatedBag === undefined ||
        payload.index === undefined
      ) {
        this.logger.debug(
          `Received proof from [${sender}] for tx [${payload.txId}] but the transaction is not properly in the queue yet.`,
        );
        release();
        return;
      }
      this.logger.debug(
        `Received proof from [${sender}] for tx [${payload.txId}]...`,
      );
      const index = payload.index;
      const pub = this.peers()[index].pub;
      transaction.signs[pub] = payload.proof;

      if (Object.keys(transaction.signs).length >= transaction.requiredSigner) {
        this.logger.debug(
          `All proofs received for tx [${payload.txId}]. Signing...`,
        );

        const allHints = wasm.TransactionHintsBag.empty();
        const signedOrder = Object.keys(transaction.signs);
        const signedProofs = signedOrder.map((key) => transaction.signs[key]);
        const hintBag = MultiSigUtils.publishedProofsToHintBag(
          signedProofs,
          signedOrder,
          transaction.tx,
        );
        MultiSigUtils.add_hints(allHints, hintBag, transaction.tx);

        MultiSigUtils.add_hints(
          allHints,
          transaction.simulatedBag,
          transaction.tx,
        );

        const cmtHints = MultiSigUtils.publishedCommitmentsToHintBag(
          Object.values(transaction.commitments),
          Object.keys(transaction.commitments),
          transaction.tx,
        );
        MultiSigUtils.add_hints(allHints, cmtHints, transaction.tx);

        const signed =
          MultiSigUtils.getEmptyProver().sign_reduced_transaction_multi(
            transaction.tx,
            allHints,
          );
        const txBytes = Buffer.from(signed.sigma_serialize_bytes()).toString(
          'base64',
        );
        release();
        await this.handleSignedTx(txBytes);

        const txPayload = {
          txBytes: txBytes,
        };
        const myPub = this.getPk();
        const toSend: string[] = (await this.peersWithIds())
          .filter((peer) => peer.pub !== myPub)
          .map((peer) => peer.id)
          .filter((id): id is string => id !== undefined);

        await this.sendMessage(
          { type: MessageType.SignedTx, payload: txPayload, sign: '' },
          toSend,
        );
      }

      release();
    } catch (e) {
      this.logger.warn(
        `An unknown exception occurred while handling initiate sign from other peer: ${e}`,
      );
    }
  };

  /**
   * handles fully signed transaction
   * checks if the transaction is valid and resolve the promise
   * @param txBytes base64 encoded signed transaction
   */
  handleSignedTx = async (txBytes: string): Promise<void> => {
    try {
      const tx = wasm.Transaction.sigma_parse_bytes(
        Buffer.from(txBytes, 'base64'),
      );
      const { transaction, release } = await this.getQueuedTransaction(
        tx.id().to_str(),
      );
      const isTxValid = await this.multiSigUtilsInstance.verifyInput(
        tx,
        transaction.boxes,
      );
      this.logger.info(
        `Received signed tx [${tx.id().to_str()}] and it is ${isTxValid ? 'valid' : 'invalid'}`,
      );

      if (isTxValid && transaction.resolve) transaction.resolve(tx);
      if (!isTxValid && transaction.reject)
        transaction.reject(`Signed transaction ${tx.id().to_str()} is invalid`);

      release();
      this.transactions.delete(tx.id().to_str());
    } catch (e) {
      this.logger.warn(
        `An unknown exception occurred while handling signed transaction: ${e}`,
      );
    }
  };

  /**
   * if it's this peer's turn, generate commitment for the transaction
   * asks other peers to generate commitment
   * @param txId
   */
  handleMyTurnForTx = async (txId: string) => {
    const transaction = this.transactions.get(txId);
    if (!transaction) return;
    transaction.simulatedBag = wasm.TransactionHintsBag.empty();
    transaction.commitments = {};
    transaction.commitmentSigns = {};
    transaction.signs = {};
    const myInd = this.getIndex();

    if (this.isMyTurn() && transaction.coordinator !== myInd) {
      this.logger.debug(
        `Initiating sign for tx [${txId}] because it's my turn...`,
      );
      transaction.coordinator = myInd;
      await this.generateCommitment(txId);
      //   ask peers to generate commitment
      await this.sendMessage({
        type: MessageType.GenerateCommitment,
        payload: {
          txId: txId,
        },
      });
    }
  };

  /**
   * if it's this peer's turn, handle all transactions in the queue for potential signing
   */
  handleMyTurn = async () => {
    if (!this.isMyTurn()) return;
    this.logger.debug('Handling my turn for all transactions in the queue...');
    for (const [txId, transaction] of Array.from(this.transactions)) {
      await this.handleMyTurnForTx(txId);
    }
  };

  /**
   * cleaning unsigned transaction after txSignTimeout if the transaction still exist in queue
   */
  public cleanup = (): void => {
    this.logger.info('Cleaning MultiSig queue');
    let cleanedTransactionCount = 0;
    this.semaphore.acquire().then((release) => {
      try {
        for (const [key, transaction] of Array.from(this.transactions)) {
          if (
            transaction.createTime <
            new Date().getTime() - this.txSignTimeout * 1000
          ) {
            // milliseconds
            if (transaction.tx) {
              this.logger.debug(
                `Tx [${transaction.tx.unsigned_tx().id()}] got timeout in MultiSig signing process`,
              );
            }
            if (transaction.reject) {
              transaction.reject('Timed out');
            }
            this.transactions.delete(key);
            cleanedTransactionCount++;
          }
        }
        release();
      } catch (e) {
        release();
        this.logger.error(
          `An error occurred while removing unsigned transactions from MultiSig queue: ${e}`,
        );
        if (e instanceof Error && e.stack) this.logger.error(e.stack);
        throw e;
      }
      this.logger.info(`MultiSig queue cleaned up`, {
        count: cleanedTransactionCount,
      });
    });
  };

  /**
   * handle new message from other guards. first verify message sign
   * then if sign is valid pass to handler message according to message.
   * @param messageStr message sent to this peer
   * @param channel channel over which the message is sent
   * @param sender the sender id
   */
  public handleMessage = async (
    messageStr: string,
    channel: string,
    sender: string,
  ): Promise<void> => {
    this.peersMustBeInitialized();
    const message = JSON.parse(messageStr) as CommunicationMessage;
    if (
      message.payload.index !== undefined &&
      message.payload.index >= 0 &&
      message.payload.index < this.peers().length &&
      message.payload.id &&
      message.sign
    ) {
      if (sender !== message.payload.id) {
        this.logger.warn(
          `Received message from [${sender}] which using id [${message.payload.id}]`,
        );
        return;
      }

      const index = message.payload.index;
      if (
        await MultiSigUtils.verifySignature(
          message.sign,
          this.peers()[index].pub,
          JSON.stringify(message.payload),
          this.encryption,
        )
      ) {
        switch (message.type) {
          case MessageType.GenerateCommitment: {
            const payload = message.payload as GenerateCommitmentPayload;
            await this.generateCommitment(payload.txId);
            break;
          }
          case MessageType.Commitment:
            await this.handleCommitment(
              sender,
              message.payload as CommitmentPayload,
              message.sign,
            );
            break;
          case MessageType.InitiateSign:
            await this.initiateSign(
              sender,
              message.payload as InitiateSignPayload,
            );
            break;
          case MessageType.Sign:
            await this.handleSign(sender, message.payload as SignPayload);
            break;
          case MessageType.SignedTx: {
            const payload = message.payload as SignedTxPayload;
            await this.handleSignedTx(payload.txBytes);
            break;
          }
        }
      } else {
        this.logger.warn(
          "Ignoring received message in MultiSig. Signature didn't verify",
        );
      }
    }
  };
}
