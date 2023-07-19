package app

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	keygen "rosen-bridge/tss-api/app/keygen/eddsa"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/blake2b"
	"rosen-bridge/tss-api/app/interface"
	eddsaSign "rosen-bridge/tss-api/app/sign/eddsa"
	"rosen-bridge/tss-api/logger"
	"rosen-bridge/tss-api/models"
	"rosen-bridge/tss-api/network"
	"rosen-bridge/tss-api/storage"
	"rosen-bridge/tss-api/utils"
)

type rosenTss struct {
	ChannelMap         map[string]chan models.GossipMessage
	KeygenOperationMap map[string]_interface.KeygenOperation
	SignOperationMap   map[string]_interface.SignOperation
	metaData           models.MetaData
	storage            storage.Storage
	connection         network.Connection
	Config             models.Config
	peerHome           string
	P2pId              string
}

var logging *zap.SugaredLogger

//	Constructor of an app
func NewRosenTss(connection network.Connection, storage storage.Storage, config models.Config) _interface.RosenTss {
	logging = logger.NewSugar("app")
	return &rosenTss{
		ChannelMap:         make(map[string]chan models.GossipMessage),
		KeygenOperationMap: make(map[string]_interface.KeygenOperation),
		SignOperationMap:   make(map[string]_interface.SignOperation),
		metaData:           models.MetaData{},
		storage:            storage,
		connection:         connection,
		Config:             config,
	}
}

func (r *rosenTss) errorCallBackCall(data interface{}, callBackUrl string) {
	callbackErr := r.GetConnection().CallBack(callBackUrl, data)
	if callbackErr != nil {
		logging.Error(callbackErr)
	}
}

func (r *rosenTss) timeOutGoRoutine(operationName string, messageId string, errorCh chan error) {
	go func() {
		timeout := time.After(time.Second * time.Duration(r.Config.OperationTimeout))
		for {
			select {
			case <-timeout:
				if _, ok := r.ChannelMap[messageId]; ok {
					err := fmt.Errorf("%s operation timeout", operationName)
					errorCh <- err
					time.After(time.Second * 4)
					close(r.ChannelMap[messageId])
				}
				return
			}
		}
	}()
}

// StartNewKeygen starts keygen scenario for app based on given protocol.
func (r *rosenTss) StartNewKeygen(keygenMessage models.KeygenMessage) error {
	logging.Info("Starting New keygen process")

	path := fmt.Sprintf("%s/%s/%s", r.GetPeerHome(), keygenMessage.Crypto, "keygen_data.json")
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf(models.KeygenFileExistError)
	}

	messageId := fmt.Sprintf("%s%s", keygenMessage.Crypto, "Keygen")
	_, ok := r.ChannelMap[messageId]
	if !ok {
		messageCh := make(chan models.GossipMessage, 100)
		r.ChannelMap[messageId] = messageCh
		logging.Infof("creating new channel in StartNewKeygen: %v", messageId)
	} else {
		return fmt.Errorf(models.DuplicatedMessageIdError)
	}

	var operation _interface.KeygenOperation
	switch keygenMessage.Crypto {
	case "eddsa":
		operation = keygen.NewKeygenEDDSAOperation(keygenMessage)
	default:
		return fmt.Errorf(models.WrongCryptoProtocolError)
	}
	channelId := operation.GetClassName()
	r.KeygenOperationMap[channelId] = operation

	errorCh := make(chan error)
	r.timeOutGoRoutine(operation.GetClassName(), messageId, errorCh)

	err := operation.Init(r, keygenMessage.P2PIDs)
	if err != nil {
		return err
	}
	go func() {
		logging.Infof("calling start action for %s keygen", keygenMessage.Crypto)
		err = operation.StartAction(r, r.ChannelMap[messageId], errorCh)
		if err != nil {
			logging.Errorf("an error occurred in %s keygen action, err: %+v", keygenMessage.Crypto, err)
			data := models.FailKeygenData{
				Error:  err.Error(),
				Status: "fail",
			}
			r.errorCallBackCall(data, keygenMessage.CallBackUrl)
		}
		r.deleteInstance("keygen", messageId, channelId, errorCh)
		logging.Infof("end of %s keygen action", keygenMessage.Crypto)
		return
	}()

	return nil
}

//	starts sign scenario for app based on given protocol.
func (r *rosenTss) StartNewSign(signMessage models.SignMessage) error {
	logging.Info("Starting New Sign process")
	msgBytes, _ := utils.HexDecoder(signMessage.Message)
	signData := new(big.Int).SetBytes(msgBytes)
	signDataBytes := blake2b.Sum256(signData.Bytes())
	signDataHash := utils.HexEncoder(signDataBytes[:])
	logging.Infof("encoded sign data: %v", signDataHash)

	messageId := fmt.Sprintf("%s%s", signMessage.Crypto, signDataHash)
	_, ok := r.ChannelMap[messageId]
	if !ok {
		messageCh := make(chan models.GossipMessage, 100)
		r.ChannelMap[messageId] = messageCh
		logging.Infof("new communication channel for signning process: %v", messageId)
	} else {
		return fmt.Errorf(models.DuplicatedMessageIdError)
	}

	var operation _interface.SignOperation
	println(signMessage.Crypto)
	switch signMessage.Crypto {
	case "eddsa":
		operation = eddsaSign.NewSignEDDSAOperation(signMessage)
	default:
		return fmt.Errorf(models.WrongCryptoProtocolError)
	}
	channelId := fmt.Sprintf("%s%s", operation.GetClassName(), messageId)
	r.SignOperationMap[channelId] = operation

	errorCh := make(chan error)
	r.timeOutGoRoutine(operation.GetClassName(), messageId, errorCh)

	err := operation.Init(r, signMessage.Peers)
	if err != nil {
		return err
	}
	go func() {
		logging.Infof("calling start action for %s sign", signMessage.Crypto)
		err = operation.StartAction(r, r.ChannelMap[messageId], errorCh)
		if err != nil {
			logging.Errorf("an error occurred in %s sign action, err: %+v", signMessage.Crypto, err)
			data := models.SignData{
				Message: signMessage.Message,
				Error:   err.Error(),
				Status:  "fail",
			}
			r.errorCallBackCall(data, signMessage.CallBackUrl)
		}
		r.deleteInstance("sign", messageId, channelId, errorCh)
		logging.Infof("end of %s sign action", signMessage.Crypto)
		return
	}()

	return nil
}

//	handles the receiving message from message route
func (r *rosenTss) MessageHandler(message models.Message) error {

	msgBytes := []byte(message.Message)
	gossipMsg := models.GossipMessage{}
	err := json.Unmarshal(msgBytes, &gossipMsg)
	if err != nil {
		return err
	}

	logging.Infof("callback route called. recevied a message with messageId %+v from: %+v", gossipMsg.MessageId, gossipMsg.SenderId)
	logging.Debugf("message info is: %+v", gossipMsg)

	// handling recover in case the channel is closed but not removed from the list yet, and there is a message to send on that
	send := func(c chan models.GossipMessage, t models.GossipMessage) {
		defer func() {
			if x := recover(); x != nil {
				logging.Warnf("unable to send: %v", x)
			}
		}()
		c <- t
	}

	var state bool
	for i, start := 0, time.Now(); ; i++ {
		if time.Since(start) > time.Second*time.Duration(r.Config.MessageTimeout) {
			state = false
			break
		}
		if _, ok := r.ChannelMap[gossipMsg.MessageId]; ok {
			send(r.ChannelMap[gossipMsg.MessageId], gossipMsg)
			state = true
			break
		}
		time.Sleep(time.Millisecond * time.Duration(r.Config.WriteMsgRetryTime))
	}
	if !state {
		logging.Warnf("message timeout, channel not found: %+v", gossipMsg.MessageId)
		return nil
	} else {
		return nil
	}
}

//	returns the storage
func (r *rosenTss) GetStorage() storage.Storage {
	return r.storage
}

//	returns the connection
func (r *rosenTss) GetConnection() network.Connection {
	return r.connection
}

//	setups peer home address and creates that
func (r *rosenTss) SetPeerHome(homeAddress string) error {
	logging.Info("setting up home directory")

	absAddress, err := utils.SetupDir(homeAddress)
	if err != nil {
		return err
	}
	r.peerHome = absAddress
	return nil
}

//	returns the peer's home
func (r *rosenTss) GetPeerHome() string {
	return r.peerHome
}

//	setting ups metadata from given file in the home directory
func (r *rosenTss) SetMetaData(meta models.MetaData) error {
	r.metaData = meta
	return nil
}

//	returns peer's meta data
func (r *rosenTss) GetMetaData() models.MetaData {
	return r.metaData
}

//	returns list of operations
func (r *rosenTss) GetKeygenOperations() map[string]_interface.KeygenOperation {
	return r.KeygenOperationMap
}

//	returns list of operations
func (r *rosenTss) GetSignOperations() map[string]_interface.SignOperation {
	return r.SignOperationMap
}

//	removes operation and related channel from list
func (r *rosenTss) deleteInstance(operationType string, messageId string, channelId string, errorCh chan error) {
	switch operationType {
	case "keygen":
		r.deleteKeygenInstance(messageId, channelId, errorCh)
	case "sign":
		r.deleteSignInstance(messageId, channelId, errorCh)
	}
}

//	removes operation and related channel for Keygen operation
func (r *rosenTss) deleteKeygenInstance(messageId string, channelId string, errorCh chan error) {
	operationName := r.KeygenOperationMap[channelId].GetClassName()
	logging.Debugf("deleting %s for channelId %s and messageId %s for keygen operation", operationName, channelId, messageId)
	delete(r.SignOperationMap, channelId)
	delete(r.ChannelMap, messageId)
	close(errorCh)
	logging.Infof("operation %s removed for channelId %s and messageId %s for keygen operation", operationName, channelId, messageId)
}

//	removes operation and related channel for sign Operation
func (r *rosenTss) deleteSignInstance(messageId string, channelId string, errorCh chan error) {
	operationName := r.SignOperationMap[channelId].GetClassName()
	logging.Debugf("deleting %s for channelId %s and messageId %s for sign operation", operationName, channelId, messageId)
	delete(r.SignOperationMap, channelId)
	delete(r.ChannelMap, messageId)
	close(errorCh)
	logging.Infof("operation %s removed for channelId %s and messageId %s for sign operation", operationName, channelId, messageId)
}

//	set p2p to the variable
func (r *rosenTss) SetP2pId() error {
	p2pId, err := r.GetConnection().GetPeerId()
	if err != nil {
		return err
	}
	r.P2pId = p2pId
	return nil
}

//	get p2pId
func (r *rosenTss) GetP2pId() string {
	return r.P2pId
}

//	get Config
func (r *rosenTss) GetConfig() models.Config {
	return r.Config
}
