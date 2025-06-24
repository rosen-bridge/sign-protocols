package sign

import (
	"fmt"
	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"go.uber.org/zap"
	"golang.org/x/crypto/blake2b"
	"math/big"
	_interface "rosen-bridge/tss-api/app/interface"
	"rosen-bridge/tss-api/models"
	"rosen-bridge/tss-api/utils"
)

type Handler interface {
	LoadData(_interface.RosenTss) (*tss.PartyID, error)
	GetData() ([]*big.Int, *big.Int)
	StartParty(
		localTssData *models.TssData,
		threshold int,
		signMsg models.SignMessage,
		outCh chan tss.Message,
		endCh chan *common.SignatureData,
	) error
}

type StructSign struct {
	_interface.SignOperationHandler
	LocalTssData models.TssData
	SignMessage  models.SignMessage
	Logger       *zap.SugaredLogger
	Handler
}

//	- finds the index of peer in the key list.
//	- creates a gossip message from payload.
//	- sends the gossip message to Publish function.
func (s *StructSign) NewMessage(rosenTss _interface.RosenTss, payload models.Payload, receiver string) error {
	s.Logger.Infof("creating new gossip message")
	keyList, sharedId := s.GetData()

	index := utils.IndexOf(keyList, sharedId)
	if index == -1 {
		return fmt.Errorf("party index not found")
	}

	gossipMessage := models.GossipMessage{
		Message:    payload.Message,
		MessageId:  payload.MessageId,
		SenderId:   payload.SenderId,
		ReceiverId: receiver,
	}
	err := rosenTss.GetConnection().Publish(gossipMessage)
	if err != nil {
		return err
	}
	return nil
}

//	- handles party messages on out channel
//	- creates payload from party message
//	- send it to NewMessage function
func (s *StructSign) HandleOutMessage(rosenTss _interface.RosenTss, partyMsg tss.Message) error {
	msgHex, err := s.SignOperationHandler.PartyMessageHandler(partyMsg)
	if err != nil {
		s.Logger.Errorf("there was an error in parsing party message to the struct: %+v", err)
		return err
	}

	msgBytes, _ := utils.HexDecoder(s.SignMessage.Message)
	messageBytes := blake2b.Sum256(msgBytes)
	messageId := fmt.Sprintf("%s%s", s.SignMessage.Crypto, utils.HexEncoder(messageBytes[:]))
	payload := models.Payload{
		Message:   msgHex,
		MessageId: messageId,
		SenderId:  s.LocalTssData.PartyID.Id,
	}

	if partyMsg.IsBroadcast() || partyMsg.GetTo() == nil {
		err = s.NewMessage(rosenTss, payload, "")
		if err != nil {
			return err
		}
	} else {
		for _, peer := range partyMsg.GetTo() {
			err = s.NewMessage(rosenTss, payload, peer.Id)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

//	- handles save data (signature) on end channel of party
//	- logs the data and send it to CallBack
func (s *StructSign) HandleEndMessage(rosenTss _interface.RosenTss, signatureData *common.SignatureData) error {

	signData := models.SignData{
		Signature:         utils.HexEncoder(signatureData.Signature),
		Message:           utils.HexEncoder(signatureData.M),
		SignatureRecovery: utils.HexEncoder(signatureData.SignatureRecovery),
		TrustKey:          rosenTss.GetTrustKey(),
		Status:            "success",
	}

	s.Logger.Infof("signing process for Message: {%s} and Crypto: {%s} finished.", s.SignMessage.Message, s.SignMessage.Crypto)
	s.Logger.Debugf("signature: {%v}, Message: {%v}, SignatureRecovery: {%v}", signData.Signature, signData.Message, signData.SignatureRecovery)

	err := rosenTss.GetConnection().CallBack(s.SignMessage.CallBackUrl, signData)
	if err != nil {
		return err
	}
	return nil
}

//	- handles all party messages on outCh and endCh
//	- listens to channels and send the message to the right function
func (s *StructSign) GossipMessageHandler(
	rosenTss _interface.RosenTss, outCh chan tss.Message, endCh chan *common.SignatureData,
) (bool, error) {
	for {
		select {
		case partyMsg := <-outCh:
			err := s.HandleOutMessage(rosenTss, partyMsg)
			if err != nil {
				return false, err
			}
		case save := <-endCh:
			err := s.HandleEndMessage(rosenTss, save)
			if err != nil {
				return false, err
			}
			return true, nil
		}
	}
}

//	- Updates party on received message destination.
func (s *StructSign) PartyUpdate(partyMsg models.PartyMessage) error {
	dest := partyMsg.GetTo
	if dest == nil { // broadcast!
		if s.LocalTssData.Party.PartyID().Index == partyMsg.GetFrom.Index {
			return nil
		}
		s.Logger.Infof("updating party state with bradcast message")
	} else { // point-to-point!
		if dest[0].Index == partyMsg.GetFrom.Index {
			err := fmt.Errorf("party %d tried to send a message to itself (%d)", dest[0].Index, partyMsg.GetFrom.Index)
			return err
		}
		s.Logger.Infof("updating party state with p2p message")
	}

	err := s.SignOperationHandler.SharedPartyUpdater(s.LocalTssData.Party, partyMsg)
	if err != nil {
		return err
	}
	return nil
}
