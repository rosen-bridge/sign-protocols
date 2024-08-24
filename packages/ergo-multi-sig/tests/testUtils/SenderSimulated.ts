import { MultiSigHandler } from '../../lib';
import { testPubs } from '../testData';

export class SenderSimulated {
  idToHandler: { [id: string]: MultiSigHandler } = {};

  /**
   * sets the handlers
   * @param handlers MultiSigHandlers
   * @param pubs public keys of the handlers
   */
  changeHandlers = (handlers: Array<MultiSigHandler>, pubs: Array<string>) => {
    handlers.forEach((handler) => {
      const id = pubs[handler.getIndex()];
      this.idToHandler[id] = handler;
    });
  };

  /**
   * sends message to the peers
   * @param msg message to send
   * @param peers peers to send the message
   */
  simulatedSender = async (msg: string, peers: Array<string>) => {
    let toSend = testPubs;
    if (peers.length > 0) {
      toSend = peers;
    }
    const msgJson = JSON.parse(msg);
    await Promise.all(
      toSend.map((id) => {
        const handler = this.idToHandler[id];
        if (handler) {
          const id = msgJson.payload.id;
          return handler.handleMessage(msg, '', id);
        }
      }),
    );
  };
}
