import * as wasm from 'ergo-lib-wasm-nodejs';
import {
  ApprovePayload,
  CommitmentPayload,
  CommunicationMessage,
  ErgoMultiSigConfig,
  InitiateSignPayload,
  RegisterPayload,
  signedTxPayload,
  Signer,
  SignPayload,
  TxQueued,
} from './types';
import { multiSigFirstSignDelay, turnTime } from './const';
import * as crypto from 'crypto';
import { Semaphore } from 'await-semaphore';
import Encryption from './utils/Encryption';
import { MultiSigUtils } from './MultiSigUtils';
import { AbstractLogger, DummyLogger } from '@rosen-bridge/abstract-logger';
import { release } from 'node:os';

export class MultiSigHandler {
  protected logger: AbstractLogger;
  private readonly submitMessage: (
    msg: string,
    peers: Array<string>,
  ) => unknown;
  private readonly getPeerId: () => Promise<string>;
  private readonly multiSigUtilsInstance: MultiSigUtils;
  private readonly transactions: Map<string, TxQueued>;
  private peers: Array<Signer>;
  private readonly secret: Uint8Array;
  private nonce?: string;
  private readonly txSignTimeout: number;
  private readonly multiSigFirstSignDelay: number;
  private prover?: wasm.Wallet;
  private index?: number;
  private semaphore = new Semaphore(1);

  constructor(config: ErgoMultiSigConfig) {
    this.logger = config.logger ? config.logger : new DummyLogger();
    this.transactions = new Map<string, TxQueued>();
    this.peers = config.publicKeys.map((item) => ({
      pub: item,
      unapproved: [],
    }));
    this.secret = Buffer.from(config.secretHex, 'hex');
    this.txSignTimeout = config.txSignTimeout;
    this.multiSigFirstSignDelay =
      config.multiSigFirstSignDelay ?? multiSigFirstSignDelay;
    this.multiSigUtilsInstance = config.multiSigUtilsInstance;
    this.submitMessage = config.submit;
    this.getPeerId = config.getPeerId;
  }

  /**
   * getting the current turn index
   */
  public getCurrentTurnInd = (): number => {
    // every turnTime the turn changes to the next guard
    return Math.floor(new Date().getTime() / turnTime) % this.peers.length;
  };

  /**
   * checks if it's this peer's turn to sign
   */
  public isMyTurn = (): boolean => {
    return this.getIndex() === this.getCurrentTurnInd();
  };

  /**
   * sending register message to the network
   */
  public sendRegister = async (): Promise<void> => {
    this.nonce = crypto.randomBytes(32).toString('base64');
    this.sendMessage({
      type: 'register',
      payload: {
        nonce: this.nonce,
        myId: await this.getPeerId(),
      },
    });
  };

  /**
   * checks if peers initiated using guards public keys, throws error if not
   */
  peersMustBeInitialized = (): void => {
    if (this.peers.length === 0)
      throw Error(
        `Cannot proceed MultiSig action, public keys are not provided yet`,
      );
  };

  /**
   * getting the index of the guard
   */
  getIndex = (): number => {
    if (this.index === undefined) {
      const secret = wasm.SecretKey.dlog_from_bytes(this.secret);
      const pub = Buffer.from(secret.get_address().content_bytes()).toString(
        'hex',
      );
      this.index = this.peers.map((peer) => peer.pub).indexOf(pub);
    }
    if (this.index !== undefined) return this.index;
    throw Error('Secret key does not match with any guard public keys');
  };

  /**
   * handle verified register message from other guards
   * @param sender
   * @param payload
   */
  handleRegister = (sender: string, payload: RegisterPayload): void => {
    if (payload.index !== undefined && this.verifyIndex(payload.index)) {
      const peer = this.peers[payload.index];
      const nonce = crypto.randomBytes(32).toString('base64');
      peer.unapproved.push({ id: sender, challenge: nonce });
      this.logger.debug(
        `Peer [${sender}] claimed to be guard of index [${payload.index}]`,
      );
      this.getPeerId().then((peerId) => {
        this.sendMessage(
          {
            type: 'approve',
            sign: '',
            payload: {
              nonce: payload.nonce,
              nonceToSign: nonce,
              myId: peerId,
            },
          },
          [sender],
        );
      });
    }
  };

  /**
   * handle verified approve message from other guards
   * @param sender
   * @param payload
   */
  handleApprove = (sender: string, payload: ApprovePayload): void => {
    if (
      payload.index !== undefined &&
      this.verifyIndex(payload.index) &&
      sender === payload.myId
    ) {
      const nonce = payload.nonce;
      const peer = this.peers[payload.index];
      const unapproved = peer.unapproved.filter(
        (item) => item.id === sender && item.challenge === nonce,
      );
      if (unapproved.length > 0) {
        this.logger.debug(`Peer [${sender}] got approved`);
        peer.id = sender;
        peer.unapproved = peer.unapproved.filter(
          (item) => unapproved.indexOf(item) === -1,
        );
      } else if (this.nonce == payload.nonce) {
        this.logger.debug(
          `Found peer [${sender}] as guard of index [${payload.index}]`,
        );
        peer.id = sender;
      }
      this.logger.debug(`Sending approval message to peer [${sender}] ...`);
      this.getPeerId().then((peerId) => {
        if (payload.nonceToSign) {
          this.sendMessage(
            {
              type: 'approve',
              sign: '',
              payload: {
                nonce: payload.nonceToSign,
                myId: peerId,
                nonceToSign: '',
              },
            },
            [sender],
          );
        }
      });
    }
  };

  /**
   * get a transaction object from queued transactions.
   * @param txId
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
   * add a transaction to the queue without initiating sign
   * @param tx reduced transaction for multi-sig transaction
   * @param boxes input boxes for transaction
   * @param dataBoxes data input boxes for transaction
   */
  public addTx = (
    tx: wasm.ReducedTransaction,
    boxes: Array<wasm.ErgoBox>,
    dataBoxes: Array<wasm.ErgoBox>,
  ) => {
    this.getQueuedTransaction(tx.unsigned_tx().id().to_str())
      .then(({ transaction, release }) => {
        transaction.tx = tx;
        transaction.boxes = boxes;
        transaction.dataBoxes = dataBoxes;
        this.generateCommitment(tx.unsigned_tx().id().to_str());
        release();
      })
      .catch((e) => {
        this.logger.error(
          `Error in adding transaction to MultiSig queue: ${e}`,
        );
        release();
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
      Encryption.sign(payloadStr, Buffer.from(this.secret)),
    ).toString('base64');
    if (receivers && receivers.length) {
      Promise.all(
        receivers.map(async (receiver) =>
          this.submitMessage(JSON.stringify(message), [receiver]),
        ),
      );
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
   * checks index of the tx is valid
   * @param index
   */
  verifyIndex = (index: number): boolean => {
    return index >= 0 && index < this.peers.length;
  };

  /**
   * generating commitment for transaction in the queue by id
   * @param id
   */
  generateCommitment = (id: string): void => {
    const currentTurn = this.getCurrentTurnInd();

    const transaction = this.transactions.get(id);
    if (transaction && !transaction.secret && transaction.tx) {
      transaction.secret =
        this.getProver().generate_commitments_for_reduced_transaction(
          transaction.tx,
        );

      // publishable commitment
      transaction.commitments[this.peers[this.getIndex()].pub] =
        MultiSigUtils.toReducedPublishedCommitments(
          transaction.secret,
          this.peers[this.getIndex()].pub,
        );

      const myPub = this.peers[this.getIndex()].pub;
      const publishCommitments = MultiSigUtils.toReducedPublishedCommitments(
        transaction.secret,
        myPub,
      );
      this.logger.debug(
        `Commitment generated for tx [${id}]. Broadcasting to the peer with the correct turn...`,
      );
      // don't send if it's my turn
      if (!this.isMyTurn())
        this.sendMessage(
          {
            type: 'commitment',
            payload: {
              txId: id,
              commitment: publishCommitments,
            },
          },
          this.peers[currentTurn].id ? [this.peers[currentTurn].id] : [],
        );
    }
  };

  /**
   * handle verified commitment message from other guards
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
      const pub = this.peers[index].pub;
      const { transaction, release } = await this.getQueuedTransaction(
        payload.txId,
      );

      // if enough commitments, we do not need to process new commitments
      const commits = Object.values(transaction.commitments);
      if (commits.length < transaction.requiredSigner) {
        try {
          transaction.commitments[pub] = payload.commitment;
          transaction.commitmentSigns[pub] = signature;

          const myPub = this.peers[this.getIndex()].pub;

          if (
            Object.keys(transaction.commitments).length >=
            transaction.requiredSigner
          ) {
            this.logger.debug(
              `Tx [${payload.txId}] has enough commitments. Signing Delayed for [${this.multiSigFirstSignDelay}] seconds...`,
            );

            const willSignPubs = Object.keys(transaction.commitments);
            const willSignInds = willSignPubs.map((pub) =>
              this.peers.map((peer) => peer.pub).indexOf(pub),
            );
            const simulated = this.peers
              .filter((peer) => !willSignPubs.includes(peer.pub))
              .map((peer) => peer.pub);

            const hints = MultiSigUtils.publishedCommitmentsToHintBag(
              Object.values(transaction.commitments),
              willSignPubs,
              transaction.tx!,
            );
            const hintsCopy = wasm.TransactionHintsBag.from_json(
              JSON.stringify(hints.to_json()),
            );
            const signedTxSim =
              MultiSigUtils.getEmptyProver().sign_reduced_transaction_multi(
                transaction.tx!,
                hintsCopy,
              );

            const simHints = await this.multiSigUtilsInstance.extract_hints(
              signedTxSim,
              transaction.boxes,
              transaction.dataBoxes,
              [],
              simulated,
            );
            MultiSigUtils.add_hints(hints, simHints, transaction.tx!);

            transaction.simulatedBag = simHints;
            const simHintsPublish =
              MultiSigUtils.toReducedPublishedCommitmentsArray(
                simHints,
                simulated,
              );
            const simPublishedProofs =
              MultiSigUtils.toReducedPublishedProofsArray(simHints, simulated);

            MultiSigUtils.add_hints(
              hints,
              transaction.secret!,
              transaction.tx!,
            );
            const signedTx = this.getProver().sign_reduced_transaction_multi(
              transaction.tx!,
              hints,
            );

            const myHint = await this.multiSigUtilsInstance.extract_hints(
              signedTx,
              transaction.boxes,
              transaction.dataBoxes,
              [this.peers[this.getIndex()].pub],
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

            const toSendPeers = this.peers
              .filter((peer) => {
                return Object.keys(transaction.commitments).includes(peer.pub);
              })
              .map((peer) => peer.id!);
            this.sendMessage(
              { type: 'initiateSign', payload: signPayload, sign: '' },
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
    try {
      const { transaction, release } = await this.getQueuedTransaction(
        payload.txId,
      );
      const myPub = this.peers[this.getIndex()].pub;
      const signed = payload.committedInds.map((ind) => this.peers[ind].pub);
      const simulated = this.peers
        .filter((peer) => !signed.includes(peer.pub))
        .map((peer) => peer.pub);

      const hints = wasm.TransactionHintsBag.empty();
      const cmtHints = MultiSigUtils.publishedCommitmentsToHintBag(
        payload.cmts,
        signed,
        transaction.tx!,
      );
      MultiSigUtils.add_hints(hints, cmtHints, transaction.tx!);

      const simHints = MultiSigUtils.publishedCommitmentsToHintBag(
        payload.simulated,
        simulated,
        transaction.tx!,
        'cmtSimulated',
      );
      MultiSigUtils.add_hints(hints, simHints, transaction.tx!);

      const simProofs = MultiSigUtils.publishedProofsToHintBag(
        payload.simulatedProofs,
        simulated,
        transaction.tx!,
        'proofSimulated',
      );
      MultiSigUtils.add_hints(hints, simProofs, transaction.tx!);

      MultiSigUtils.add_hints(hints, transaction.secret!, transaction.tx!);

      const partial = this.getProver().sign_reduced_transaction_multi(
        transaction.tx!,
        hints,
      );
      const signer = [this.peers[this.getIndex()].pub];
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

      this.sendMessage({ type: 'sign', payload: signPayload, sign: '' }, [
        sender,
      ]);

      release();
    } catch (e) {
      this.logger.warn(
        `An unknown exception occurred while handling initiate sign from other peer: ${e}`,
      );
      release();
    }
  };

  /**
   * the peer with the correct turn collects partial proofs and signs the transaction
   * @param sender sender of the proof
   * @param payload proof payload
   */
  handleSign = async (sender: string, payload: SignPayload): Promise<void> => {
    try {
      const { transaction, release } = await this.getQueuedTransaction(
        payload.txId,
      );
      transaction.signs[sender] = payload.proof;

      if (Object.keys(transaction.signs).length >= transaction.requiredSigner) {
        const allHints = wasm.TransactionHintsBag.empty();
        const signedOrder = Object.keys(transaction.signs);
        const signedProofs = signedOrder.map((key) => transaction.signs[key]);
        const hintBag = MultiSigUtils.publishedProofsToHintBag(
          signedProofs,
          signedOrder,
          transaction.tx!,
        );
        MultiSigUtils.add_hints(allHints, hintBag, transaction.tx!);

        MultiSigUtils.add_hints(
          allHints,
          transaction.simulatedBag!,
          transaction.tx!,
        );

        const cmtHints = MultiSigUtils.publishedCommitmentsToHintBag(
          Object.values(transaction.commitments),
          Object.keys(transaction.commitments),
          transaction.tx!,
        );
        MultiSigUtils.add_hints(allHints, cmtHints, transaction.tx!);

        const signed =
          MultiSigUtils.getEmptyProver().sign_reduced_transaction_multi(
            transaction.tx!,
            allHints,
          );
        const txBytes = Buffer.from(signed.sigma_serialize_bytes()).toString(
          'base64',
        );
        release();
        await this.handleSignedTx(txBytes);

        const payload = {
          txBytes: txBytes,
        };
        const myPub = this.peers[this.getIndex()].pub;
        const toSend = this.peers
          .filter((peer) => peer.pub !== myPub)
          .map((peer) => peer.id!);
        this.sendMessage(
          { type: 'signedTx', payload: payload, sign: '' },
          toSend,
        );
      }

      release();
    } catch (e) {
      this.logger.warn(
        `An unknown exception occurred while handling initiate sign from other peer: ${e}`,
      );
      release();
    }
  };

  /**
   * handles fully signed transaction
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
      if (isTxValid && transaction.resolve) transaction.resolve!(tx);
      if (!isTxValid && transaction.reject)
        transaction.reject!(
          `Signed transaction ${tx.id().to_str()} is invalid`,
        );

      this.transactions.delete(tx.id().to_str());
    } catch (e) {
      this.logger.warn(
        `An unknown exception occurred while handling signed transaction: ${e}`,
      );
    }
  };

  /**
   * handle new message from other guards. first verify message sign
   * then if sign is valid pass to handler message according to message.
   * @param messageStr message sent to this peer
   * @param channel channel over which the message is sent
   * @param sender the sender id
   */
  public handleMessage = (
    messageStr: string,
    channel: string,
    sender: string,
  ): void => {
    this.peersMustBeInitialized();
    const message = JSON.parse(messageStr) as CommunicationMessage;
    if (
      message.payload.index !== undefined &&
      message.payload.index >= 0 &&
      message.payload.index < this.peers.length &&
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
        MultiSigUtils.verifySignature(
          message.sign,
          this.peers[index].pub,
          JSON.stringify(message.payload),
        )
      ) {
        switch (message.type) {
          case 'register':
            this.handleRegister(sender, message.payload as RegisterPayload);
            break;
          case 'approve':
            this.handleApprove(sender, message.payload as ApprovePayload);
            break;
          case 'commitment':
            this.handleCommitment(
              sender,
              message.payload as CommitmentPayload,
              message.sign,
            );
            break;
          case 'initiateSign':
            this.initiateSign(sender, message.payload as InitiateSignPayload);
            break;

          case 'sign':
            this.handleSign(sender, message.payload as SignPayload);
            break;

          case 'signedTx': {
            const payload = message.payload as signedTxPayload;
            this.handleSignedTx(payload.txBytes);
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

  /**
   * Apply required changes after changes in public keys
   * @param publicKeys new public keys
   */
  handlePublicKeysChange = (publicKeys: string[]) => {
    this.peers = publicKeys.map((publicKey) => ({
      pub: publicKey,
      unapproved: [],
    }));
    this.sendRegister();
  };

  /**
   * cleaning unsigned transaction after txSignTimeout if the transaction still exist in queue
   */
  public cleanup = (): void => {
    this.logger.info('Cleaning MultiSig queue');
    let cleanedTransactionCount = 0;
    this.semaphore.acquire().then((release) => {
      try {
        for (const [key, transaction] of this.transactions.entries()) {
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
}
