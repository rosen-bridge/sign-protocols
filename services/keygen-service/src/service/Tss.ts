import axios from 'axios';
import * as crypto from 'crypto';
import CommunicationConfig from '../communication/CommunicationConfig';
import Dialer from '../communication/Dialer';
import Configs from '../configs/Configs';
import { spawn } from 'child_process';
import WinstonLogger from '@rosen-bridge/winston-logger';

const logger = WinstonLogger.getInstance().getLogger(import.meta.url);

class Tss {
  private static instance: Tss;
  protected static dialer: Dialer;
  protected static trustKey: string;

  protected constructor() {
    // do nothing.
  }

  /**
   * generates a Tss object if it doesn't exist
   * @returns Tss instance
   */
  public static getInstance = () => {
    if (!Tss.instance) throw new Error('Tss is not instantiated yet');
    return Tss.instance;
  };

  /**
   * @returns the trust key
   */
  static getTrustKey = (): string => Tss.trustKey;

  /**
   * runs tss binary file
   */
  protected static runBinary = (): void => {
    Tss.trustKey = crypto.randomUUID();
    const args = [
      '-configFile',
      Configs.tssConfigPath,
      '-guardUrl',
      `http://${Configs.apiHost}:${Configs.apiPort}`,
      '-host',
      `${Configs.tssUrl}:${Configs.tssPort}`,
      '-trustKey',
      Tss.trustKey,
    ];
    spawn(Configs.tssExecutionPath, args, {
      detached: false,
      stdio: 'ignore',
    })
      .addListener('close', (code) => {
        const timeout = Configs.tssInstanceRestartGap;
        logger.error(
          `TSS binary failed unexpectedly, TSS will be started in [${timeout}] seconds`,
        );
        logger.debug(`Tss failure error code: ${code}`);
        // wait some seconds to start again
        setTimeout(Tss.runBinary, timeout * 1000);
      })
      .addListener('spawn', () => {
        logger.info('TSS binary started');
      })
      .addListener('error', (err: Error) => {
        logger.error(`an error occured when trying to spawn: ${err}`);
      })
      .addListener('disconnect', () => {
        logger.warn(`received 'disconnect' signal from tss spawner`);
      })
      .addListener('exit', (code: number, signal: string) => {
        logger.warn(
          `received 'exit' signal from tss spawner, exit code: ${code}, signal: ${signal}`,
        );
      });
  };

  /**
   * start keygen process for guards
   * @param guardsCount
   * @param threshold
   */
  static keygen = async (guardsCount: number, threshold: number) => {
    Tss.runBinary();

    // initialize dialer
    Tss.dialer = await Dialer.getInstance();

    Tss.tryCallApi(guardsCount, threshold);
  };

  /**
   * wait until all peers are connected then call tss keygen api
   * @param guardsCount
   * @param threshold
   */
  private static tryCallApi = (guardsCount: number, threshold: number) => {
    const peerIds = Tss.dialer
      .getPeerIds()
      .filter((peerId) => !CommunicationConfig.relays.peerIDs.includes(peerId));
    if (peerIds.length < guardsCount - 1 || !Tss.dialer.getDialerId()) {
      setTimeout(() => Tss.tryCallApi(guardsCount, threshold), 1000);
    } else {
      setTimeout(() => {
        axios
          .post(`${Configs.tssUrl}:${Configs.tssPort}/keygen`, {
            p2pIDs: [Tss.dialer.getDialerId(), ...peerIds],
            callBackUrl: Configs.tssKeygenCallBackUrl,
            crypto: Configs.keygen.algorithm(),
            threshold: threshold,
            peersCount: guardsCount,
            operationTimeout: 10 * 60, // 10 minutes
          })
          .then((res) => {
            logger.info(JSON.stringify(res.data));
          })
          .catch((err) => {
            logger.error(`an error occurred during call keygen ${err}`);
            logger.debug(err.stack);
          });
      }, 10000);
    }
  };
}

export default Tss;
