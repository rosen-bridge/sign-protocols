import { MultiSigHandler } from '../../lib';
import { testPubs } from '../testData';

export class SenderSimulated {
  idToHandler: { [id: string]: MultiSigHandler } = {};

  /**
   * sets the handlers
   * @param handlers MultiSigHandlers
   */
  changeHandlers = async (handlers: Array<MultiSigHandler>) => {
    handlers.forEach((handler) => {
      const pk = handler.getPk();
      const ind = testPubs.indexOf(pk);
      const id = testPubs[testPubs.length - 1 - ind];
      this.idToHandler[id] = handler;
    });
  };

  /**
   * sends message to the peers
   * @param msg message to send
   * @param peers peers to send the message
   */
  simulatedSender = async (msg: string, peers: Array<string>) => {
    const commPks = [...testPubs].reverse();
    let toSend = commPks;
    if (peers.length > 0) {
      toSend = peers;
    }
    await Promise.all(
      toSend.map((id) => {
        const handler = this.idToHandler[id];
        const msgJson = JSON.parse(msg);
        if (handler) {
          return handler.handleMessage(msg, commPks[msgJson.index]);
        }
      }),
    );
  };
}
