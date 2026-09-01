import './bootstrap';

import Configs from './configs/configs';
import { initApiServer } from './jobs/apiServer';
import Tss from './service/tss';

const initKeygen = async () => {
  // initialize express Apis
  await initApiServer();

  await Tss.keygen(Configs.keygen.guardsCount, Configs.keygen.threshold);
};

initKeygen().then(() => null);
