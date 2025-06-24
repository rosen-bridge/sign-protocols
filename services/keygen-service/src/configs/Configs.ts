import config from 'config';
import { ConfigError } from '../utils/errors';
import { TssAlgorithms } from '../utils/constants';
import { TransportOptions } from '@rosen-bridge/winston-logger';
import { cloneDeep } from 'lodash-es';

/**
 * reads a numerical config, set default value if it does not exits
 * @param key
 * @param defaultValue
 */
const getConfigIntKeyOrDefault = (key: string, defaultValue: number) => {
  const val: string = config.get(key);
  if (val !== undefined) {
    const valNum = parseInt(val);
    if (isNaN(valNum)) {
      throw Error(`Invalid value ${val} for ${key}`);
    }
    return valNum;
  }
  return defaultValue;
};

/**
 * reads an optional config, returns default value if it does not exits
 * @param key
 * @param defaultValue
 */
const getOptionalConfig = <T>(key: string, defaultValue: T) => {
  if (config.has(key)) {
    return config.get<T>(key);
  }
  return defaultValue;
};

const SupportedAlgorithms: string[] = [
  TssAlgorithms.curve,
  TssAlgorithms.edward,
];
class KeygenConfig {
  static guardsCount = getConfigIntKeyOrDefault('keygen.guards', 0);
  static threshold = getConfigIntKeyOrDefault('keygen.threshold', 0);
  static algorithm = () => {
    const algorithm = config.get<string>('keygen.algorithm');
    if (SupportedAlgorithms.indexOf(algorithm) !== -1) {
      return algorithm;
    }
    throw Error(`Invalid keygen algorithm ${algorithm}`);
  };
}

class Configs {
  // express config
  static apiPort = getConfigIntKeyOrDefault('api.port', 8080);
  static apiHost = getOptionalConfig<string>('api.host', 'localhost');

  static apiBodyLimit =
    getConfigIntKeyOrDefault('api.jsonBodyLimit', 50) * 1024 * 1024; // value in MB
  static apiMaxRequestsPerMinute = getConfigIntKeyOrDefault(
    'api.maxRequestsPerMinute',
    100_000,
  );

  // config of API's route
  static MAX_LENGTH_CHANNEL_SIZE = 200;

  // tss configs
  static tssExecutionPath = config.get<string>('tss.path');
  static tssConfigPath = config.get<string>('tss.configPath');
  static tssUrl = config.get<string>('tss.url');
  static tssPort = config.get<string>('tss.port');
  static tssKeygenCallBackUrl = `http://${this.apiHost}:${this.apiPort}/tss/keygen`;

  // jobs configs
  static tssInstanceRestartGap = 5; // seconds

  // logs configs
  static logs;
  static {
    const logs = config.get<TransportOptions[]>('logs');
    const clonedLogs = cloneDeep(logs);
    const wrongLogTypeIndex = clonedLogs.findIndex((log) => {
      const logTypeValidation = ['console', 'file', 'loki'].includes(log.type);
      let loggerChecks = true;
      if (log.type === 'loki') {
        const overrideLokiBasicAuth = getOptionalConfig(
          'overrideLokiBasicAuth',
          '',
        );
        if (overrideLokiBasicAuth !== '') log.basicAuth = overrideLokiBasicAuth;
        loggerChecks =
          log.host != undefined &&
          typeof log.host === 'string' &&
          log.level != undefined &&
          typeof log.level === 'string' &&
          (log.serviceName ? typeof log.serviceName === 'string' : true) &&
          (log.basicAuth ? typeof log.basicAuth === 'string' : true);
      } else if (log.type === 'file') {
        loggerChecks =
          log.path != undefined &&
          typeof log.path === 'string' &&
          log.level != undefined &&
          typeof log.level === 'string' &&
          log.maxSize != undefined &&
          typeof log.maxSize === 'string' &&
          log.maxFiles != undefined &&
          typeof log.maxFiles === 'string';
      }
      return !(loggerChecks && logTypeValidation);
    });
    if (wrongLogTypeIndex >= 0) {
      throw new ConfigError(
        `logs[${wrongLogTypeIndex}]`,
        logs[wrongLogTypeIndex],
      );
    }
    this.logs = clonedLogs;
  }

  static keygen = KeygenConfig;
}

export default Configs;
export { getConfigIntKeyOrDefault };
