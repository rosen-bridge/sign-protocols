import { DefaultLogger } from '@rosen-bridge/abstract-logger';
import WinstonLogger from '@rosen-bridge/winston-logger';

import Configs from './configs/configs';

const winston = WinstonLogger.createLogger(Configs.logs);
DefaultLogger.init(winston);
