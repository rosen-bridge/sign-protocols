package ecdsa

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	ecdsaKeygen "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"go.uber.org/zap"
	"math/big"
	"rosen-bridge/tss-api/app/interface"
	"rosen-bridge/tss-api/app/keygen"
	"rosen-bridge/tss-api/logger"
	"rosen-bridge/tss-api/models"
	"rosen-bridge/tss-api/utils"
	"time"
)

var logging *zap.SugaredLogger

var ecdsaHandler handler

// - Initializes the ecdsa keygen partyId metaData and peers
func (s *operationECDSAKeygen) Init(rosenTss _interface.RosenTss, peers []string) error {

	s.Logger.Info("initiation keygen process")

	meta := models.MetaData{
		PeersCount: s.KeygenMessage.PeersCount,
		Threshold:  s.KeygenMessage.Threshold,
	}

	err := rosenTss.SetMetaData(meta, models.ECDSA)
	if err != nil {
		return err
	}

	selfP2PID := rosenTss.GetP2pId()
	var unsortedPeers []*tss.PartyID
	if s.LocalTssData.PartyID == nil {
		for _, peer := range peers {
			moniker := fmt.Sprintf("tssPeer/%s", peer)
			shareID := new(big.Int).SetBytes(utils.Base58Decoder(peer))
			newPartyID := tss.NewPartyID(peer, moniker, shareID)
			unsortedPeers = append(unsortedPeers, newPartyID)
			if peer == selfP2PID {
				s.LocalTssData.PartyID = newPartyID
			}
		}
	}

	keygenPIDs := tss.SortPartyIDs(unsortedPeers)
	s.LocalTssData.PartyIds = keygenPIDs

	s.Logger.Infof("local PartyId: %+v", s.LocalTssData.PartyID)

	return nil
}

// - creates end and out channel for party,
// - calls StartParty function of protocol
// - handles end channel and out channel in a go routine
func (s *operationECDSAKeygen) CreateParty(rosenTss _interface.RosenTss, statusCh chan bool, errorCh chan error) {
	s.Logger.Info("creating and starting party")

	outCh := make(chan tss.Message, len(s.LocalTssData.PartyIds))
	endCh := make(chan *ecdsaKeygen.LocalPartySaveData, len(s.LocalTssData.PartyIds))

	ecdsaMetaData, err := rosenTss.GetMetaData(models.ECDSA)
	if err != nil {
		s.Logger.Errorf("there was an error in getting metadata: %+v", err)
		errorCh <- err
		return
	}

	err = s.StartParty(&s.LocalTssData, ecdsaMetaData.Threshold, outCh, endCh)
	if err != nil {
		s.Logger.Errorf("there was an error in starting party: %+v", err)
		errorCh <- err
		return
	}

	s.Logger.Debugf("party info: %v ", s.LocalTssData.Party)
	go func() {
		result, err := s.GossipMessageHandler(rosenTss, outCh, endCh)
		if err != nil {
			s.Logger.Error(err)
			errorCh <- err
			return
		}
		if !result {
			err = fmt.Errorf("close channel")
			s.Logger.Error(err)
			errorCh <- err
			return
		} else {
			s.Logger.Infof("end party successfully")
			statusCh <- true
			return
		}
	}()
}

// - reads new gossip messages from channel and handle it by calling related function in a go routine.
func (s *operationECDSAKeygen) StartAction(rosenTss _interface.RosenTss, messageCh chan models.GossipMessage, errorCh chan error) error {

	partyStarted := false
	statusCh := make(chan bool)

	for {
		select {
		case err := <-errorCh:
			if err.Error() == "close channel" {
				close(messageCh)
				return nil
			}
			return err
		case msg, ok := <-messageCh:
			if !ok {
				if s.LocalTssData.Party != nil {
					s.Logger.Infof("party was waiting for: %+v", s.LocalTssData.Party.WaitingFor())
				}
				return fmt.Errorf("communication channel is closed")
			}
			s.Logger.Infof("received new message from {%s} on communication channel", msg.SenderId)
			msgBytes, err := utils.HexDecoder(msg.Message)
			if err != nil {
				return err
			}
			partyMsg := models.PartyMessage{}
			err = json.Unmarshal(msgBytes, &partyMsg)
			if err != nil {
				return err
			}
			go func() {
				for {
					if s.LocalTssData.Party == nil {
						time.Sleep(time.Duration(rosenTss.GetConfig().WaitInPartyMessageHandling) * time.Millisecond)
					} else {
						break
					}
				}
				s.Logger.Debugf("party info: %+v", s.LocalTssData.Party)
				err = s.PartyUpdate(partyMsg)
				if err != nil {
					s.Logger.Errorf("there was an error in handling party message: %+v", err)
					errorCh <- err
				}
				s.Logger.Infof("party is waiting for: %+v", s.LocalTssData.Party.WaitingFor())
				return
			}()
		case end := <-statusCh:
			if end {
				return nil
			}
		default:
			if s.LocalTssData.Party == nil && !partyStarted {
				partyStarted = true
				s.CreateParty(rosenTss, statusCh, errorCh)
				s.Logger.Infof("party is waiting for: %+v", s.LocalTssData.Party.WaitingFor())
			}
		}
	}
}

// - create ecdsa keygen operation
func NewKeygenECDSAOperation(keygenMessage models.KeygenMessage) _interface.KeygenOperation {
	logging = logger.NewSugar("ecdsa-keygen")
	return &operationECDSAKeygen{
		StructKeygen: keygen.StructKeygen{
			KeygenMessage: keygenMessage,
			Logger:        logging,
		},
		ECDSAHandler: &ecdsaHandler,
	}
}

// - returns the class name
func (s *operationECDSAKeygen) GetClassName() string {
	return "ecdsaKeygen"
}

// - handles party messages on out channel
// - creates payload from party message
// - send it to NewMessage function
func (s *operationECDSAKeygen) HandleOutMessage(rosenTss _interface.RosenTss, partyMsg tss.Message) error {
	msgHex, err := s.KeygenOperationHandler.PartyMessageHandler(partyMsg)
	if err != nil {
		s.Logger.Errorf("there was an error in parsing party message to the struct: %+v", err)
		return err
	}

	messageId := s.GetClassName()
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

// - handles save data (keygen data) on end channel of party
// - logs the data and send it to CallBack
func (s *operationECDSAKeygen) HandleEndMessage(rosenTss _interface.RosenTss, keygenData *ecdsaKeygen.LocalPartySaveData) error {

	pkX, pkY := keygenData.ECDSAPub.X(), keygenData.ECDSAPub.Y()

	public := utils.GetPKFromECDSAPub(pkX, pkY)
	encodedPK := hex.EncodeToString(public)
	shareIDStr := keygenData.ShareID.String()

	keygenResponse := models.KeygenData{
		ShareID: shareIDStr,
		PubKey:  encodedPK,
		Status:  "success",
	}
	ecdsaMetaData, err := rosenTss.GetMetaData(models.ECDSA)
	if err != nil {
		return err
	}
	tssConfigECDSA := models.TssConfigECDSA{
		MetaData:   ecdsaMetaData,
		KeygenData: *keygenData,
	}

	s.Logger.Infof("hex pubKey: %v", encodedPK)
	s.Logger.Infof("keygen process for ShareID: {%s} and Crypto: {%s} finished.", shareIDStr, s.KeygenMessage.Crypto)

	err = rosenTss.GetStorage().WriteData(tssConfigECDSA, rosenTss.GetPeerHome(), keygen.KeygenFileName, models.ECDSA)
	if err != nil {
		return err
	}

	err = rosenTss.GetConnection().CallBack(s.KeygenMessage.CallBackUrl, keygenResponse)
	if err != nil {
		return err
	}

	return nil
}

// - handles all party messages on outCh and endCh
// - listens to channels and send the message to the right function
func (s *operationECDSAKeygen) GossipMessageHandler(
	rosenTss _interface.RosenTss, outCh chan tss.Message, endCh chan *ecdsaKeygen.LocalPartySaveData,
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

// - creates tss parameters and party
func (h *handler) StartParty(
	localTssData *models.TssData,
	threshold int,
	outCh chan tss.Message,
	endCh chan *ecdsaKeygen.LocalPartySaveData,
) error {
	if localTssData.Party == nil {
		ctx := tss.NewPeerContext(localTssData.PartyIds)
		logging.Info("creating party parameters")

		var localPartyId *tss.PartyID
		for _, peer := range localTssData.PartyIds {
			if peer.Id == localTssData.PartyID.Id {
				localPartyId = peer
			}
		}
		localTssData.Params = tss.NewParameters(tss.S256(), ctx, localPartyId, len(localTssData.PartyIds), threshold)
		localTssData.Party = ecdsaKeygen.NewLocalParty(localTssData.Params, outCh, endCh)

		if err := localTssData.Party.Start(); err != nil {
			return err
		}
		logging.Info("party started")
	}
	return nil
}
