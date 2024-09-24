import { EdDSA } from '@rosen-bridge/encryption';

const generateSigners = async () => {
  const guardSigners: Array<EdDSA> = [];
  const guardPks: Array<string> = [];
  for (let index = 0; index < 10; index++) {
    const sk = new EdDSA(await EdDSA.randomKey());
    guardSigners.push(sk);
    guardPks.push(await sk.getPk());
  }
  return {
    guardSigners,
    guardPks,
  };
};

export { generateSigners };
