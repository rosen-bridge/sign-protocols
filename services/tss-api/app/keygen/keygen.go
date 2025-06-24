package keygen

import (
	"fmt"
	"go.uber.org/zap"
	_interface "rosen-bridge/tss-api/app/interface"
	"rosen-bridge/tss-api/models"
)

const (
	KeygenFileName = "keygen_data.json"
)

type StructKeygen struct {
	_interface.KeygenOperationHandler
	LocalTssData  models.TssData
	KeygenMessage models.KeygenMessage
	Logger        *zap.SugaredLogger
}

//	- creates a gossip message from payload.
//	- sends the gossip message to Publish function.
func (s *StructKeygen) NewMessage(rosenTss _interface.RosenTss, payload models.Payload, receiver string) error {
	s.Logger.Infof("creating new gossip message")

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

//	- Updates party on received message destination.
func (s *StructKeygen) PartyUpdate(partyMsg models.PartyMessage) error {
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

	err := s.KeygenOperationHandler.SharedPartyUpdater(s.LocalTssData.Party, partyMsg)
	if err != nil {
		return err
	}
	return nil
}
