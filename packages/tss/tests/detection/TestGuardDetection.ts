import {
  DetectionApprovePayload,
  DetectionHeartbeatPayload,
  DetectionRegisterPayload,
  GuardDetection,
} from '../../lib';

/**
 * GuardDetection class for testing
 */
class TestGuardDetection extends GuardDetection {
  getInfo = () => this.guardsInfo;

  mockedHandleApprove = (
    payload: DetectionApprovePayload,
    sender: string,
    guardIndex: number,
  ) => this.handleApproveMessage(payload, sender, guardIndex);
  mockedHandleRegister = (
    payload: DetectionRegisterPayload,
    sender: string,
    guardIndex: number,
  ) => this.handleRegisterMessage(payload, sender, guardIndex);
  mockedHandleHeartbeat = (
    payload: DetectionHeartbeatPayload,
    sender: string,
    guardIndex: number,
  ) => this.handleHeartbeatMessage(payload, sender, guardIndex);

  mockAddNonce = (index?: number) => this.addNonce(index);
  mockClearNonce = () => this.clearNonce();

  getMessageValidDuration = () => this.messageValidDuration;
}

export { TestGuardDetection };
