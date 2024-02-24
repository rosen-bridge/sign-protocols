package ecdsa

import (
	"encoding/json"
	"fmt"
	"github.com/bnb-chain/tss-lib/v2/common"
	ecdsaKeygen "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	ecdsaSigning "github.com/bnb-chain/tss-lib/v2/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"go.uber.org/zap"
	"math/big"
	"rosen-bridge/tss-api/app/interface"
	"rosen-bridge/tss-api/app/sign"
	"rosen-bridge/tss-api/logger"
	"rosen-bridge/tss-api/models"
	"rosen-bridge/tss-api/utils"
	"time"
)

type operationECDSASign struct {
	sign.StructSign
}

type handler struct {
	savedData ecdsaKeygen.LocalPartySaveData
}

var logging *zap.SugaredLogger
var ecdsaHandler handler

//	- Initializes the ecdsa sign partyId and peers
func (s *operationECDSASign) Init(rosenTss _interface.RosenTss, peers []models.Peer) error {

	s.Logger.Info("initiation signing process")

	pID, err := s.LoadData(rosenTss)
	if err != nil {
		s.Logger.Error(err)
		return err
	}

	var unsortedPeers []*tss.PartyID
	for _, peer := range peers {
		moniker := fmt.Sprintf("tssPeer/%s", peer.P2PID)
		shareID, _ := new(big.Int).SetString(peer.ShareID, 10)
		unsortedPeers = append(unsortedPeers, tss.NewPartyID(peer.P2PID, moniker, shareID))
	}

	signPIDs := tss.SortPartyIDs(unsortedPeers)

	s.LocalTssData.PartyID = pID
	s.LocalTssData.PartyIds = signPIDs

	s.Logger.Infof("local PartyId: %+v", pID)

	return nil
}

//	- creates end and out channel for party,
//	- calls StartParty function of protocol
//	- handles end channel and out channel in a go routine
func (s *operationECDSASign) CreateParty(rosenTss _interface.RosenTss, statusCh chan bool, errorCh chan error) {
	s.Logger.Info("creating and starting party")
	msgBytes, _ := utils.HexDecoder(s.SignMessage.Message)

	outCh := make(chan tss.Message, len(s.LocalTssData.PartyIds))
	endCh := make(chan *common.SignatureData, len(s.LocalTssData.PartyIds))

	ecdsaMetaData, err := rosenTss.GetMetaData(models.ECDSA)
	if err != nil {
		s.Logger.Errorf("there was an error in getting metadata: %+v", err)
		errorCh <- err
		return
	}

	err = s.StartParty(&s.LocalTssData, ecdsaMetaData.Threshold, msgBytes, outCh, endCh)
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

//	- reads new gossip messages from channel and handle it by calling related function in a go routine.
func (s *operationECDSASign) StartAction(rosenTss _interface.RosenTss, messageCh chan models.GossipMessage, errorCh chan error) error {

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

//	- create ecdsa sign operation
func NewSignECDSAOperation(signMessage models.SignMessage) _interface.SignOperation {
	logging = logger.NewSugar("ecdsa-sign")
	return &operationECDSASign{
		StructSign: sign.StructSign{
			SignMessage: signMessage,
			Signatures:  make(map[int][]byte),
			Logger:      logging,
			Handler:     &ecdsaHandler,
		},
	}
}

//	- returns the class name
func (s *operationECDSASign) GetClassName() string {
	return "ecdsaSign"
}

//	- creates tss parameters and party
func (h *handler) StartParty(
	localTssData *models.TssData,
	threshold int,
	signData []byte,
	outCh chan tss.Message,
	endCh chan *common.SignatureData,
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
		signDataBigInt := new(big.Int).SetBytes(signData)
		localTssData.Params = tss.NewParameters(tss.Edwards(), ctx, localPartyId, len(localTssData.PartyIds), threshold)
		localTssData.Party = ecdsaSigning.NewLocalParty(signDataBigInt, localTssData.Params, h.savedData, outCh, endCh, len(signData))

		if err := localTssData.Party.Start(); err != nil {
			return err
		}
		logging.Info("party started")
	}
	return nil
}

//	- loads keygen data from file for signing
//	- creates tss party ID with p2pID
func (h *handler) LoadData(rosenTss _interface.RosenTss) (*tss.PartyID, error) {
	data, pID, err := rosenTss.GetStorage().LoadECDSAKeygen(rosenTss.GetPeerHome())
	if err != nil {
		logging.Error(err)
		return nil, err
	}
	if pID == nil {
		logging.Error("pID is nil")
		return nil, fmt.Errorf("pID is nil")
	}
	h.savedData = data.KeygenData
	pID.Moniker = fmt.Sprintf("tssPeer/%s", rosenTss.GetP2pId())
	pID.Id = rosenTss.GetP2pId()
	err = rosenTss.SetMetaData(data.MetaData, models.ECDSA)
	if err != nil {
		return nil, err
	}
	return pID, nil
}

//	- returns key_list and shared_ID of peer stored in the struct
func (h *handler) GetData() ([]*big.Int, *big.Int) {
	return h.savedData.Ks, h.savedData.ShareID
}
