package _interface

import (
	"encoding/hex"
	"encoding/json"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"rosen-bridge/tss-api/models"
)

type KeygenOperationHandler struct {
	KeygenOperation
}

type SignOperationHandler struct {
	SignOperation
}

//	handles gossip message from party to party(s)
func (o *KeygenOperationHandler) PartyMessageHandler(partyMsg tss.Message) (string, error) {
	msgBytes, _, err := partyMsg.WireBytes()
	if err != nil {
		return "", err
	}
	partyMessage := models.PartyMessage{
		Message:                 msgBytes,
		IsBroadcast:             partyMsg.IsBroadcast(),
		GetFrom:                 partyMsg.GetFrom(),
		GetTo:                   partyMsg.GetTo(),
		IsToOldCommittee:        partyMsg.IsToOldCommittee(),
		IsToOldAndNewCommittees: partyMsg.IsToOldAndNewCommittees(),
	}

	partyMessageBytes, err := json.Marshal(partyMessage)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(partyMessageBytes), nil
}

//	this is used to update party
func (o *KeygenOperationHandler) SharedPartyUpdater(party tss.Party, msg models.PartyMessage) error {
	// do not send a message from this party back to itself
	if party.PartyID() == msg.GetFrom {
		return nil
	}
	if _, err := party.UpdateFromBytes(msg.Message, msg.GetFrom, msg.IsBroadcast); err != nil {
		return err
	}
	return nil
}

//	handles gossip message from party to party(s)
func (o *SignOperationHandler) PartyMessageHandler(partyMsg tss.Message) (string, error) {
	msgBytes, _, err := partyMsg.WireBytes()
	if err != nil {
		return "", err
	}
	partyMessage := models.PartyMessage{
		Message:                 msgBytes,
		IsBroadcast:             partyMsg.IsBroadcast(),
		GetFrom:                 partyMsg.GetFrom(),
		GetTo:                   partyMsg.GetTo(),
		IsToOldCommittee:        partyMsg.IsToOldCommittee(),
		IsToOldAndNewCommittees: partyMsg.IsToOldAndNewCommittees(),
	}

	partyMessageBytes, err := json.Marshal(partyMessage)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(partyMessageBytes), nil
}

//	this is used to update party
func (o *SignOperationHandler) SharedPartyUpdater(party tss.Party, msg models.PartyMessage) error {
	// do not send a message from this party back to itself
	if party.PartyID() == msg.GetFrom {
		return nil
	}
	if _, err := party.UpdateFromBytes(msg.Message, msg.GetFrom, msg.IsBroadcast); err != nil {
		return err
	}
	return nil
}
