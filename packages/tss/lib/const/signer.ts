import {
  BoundResultTransportCapability,
  SignMessageType,
} from '../types/signer';

const approveMessage: SignMessageType = 'approve';
const requestMessage: SignMessageType = 'request';
const cachedMessage: SignMessageType = 'cached';
const startMessage: SignMessageType = 'start';
const boundResultMessage: SignMessageType = 'bound-result-v1';
const boundResultTransportV1: BoundResultTransportCapability = Object.freeze({
  capability: 'bound-result-transport',
  version: 1,
});
const signUrl = 'sign';
const getPkUrl = 'getPK';
const thresholdUrl = 'threshold';

export {
  approveMessage,
  requestMessage,
  cachedMessage,
  startMessage,
  boundResultMessage,
  boundResultTransportV1,
  signUrl,
  getPkUrl,
  thresholdUrl,
};
