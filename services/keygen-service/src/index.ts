import './bootstrap';
import { initApiServer } from './jobs/apiServer';
import Configs from './configs/Configs';
import Tss from './service/Tss';

const initKeygen = async () => {
  // initialize express Apis
  await initApiServer();

  await Tss.keygen(Configs.keygen.guardsCount, Configs.keygen.threshold);
};

initKeygen().then(() => null);
