package app

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"os"
	ecdsaKeygen "rosen-bridge/tss-api/app/keygen/ecdsa"
	eddsaKeygen "rosen-bridge/tss-api/app/keygen/eddsa"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/blake2b"
	"rosen-bridge/tss-api/app/interface"
	ecdsaSign "rosen-bridge/tss-api/app/sign/ecdsa"
	eddsaSign "rosen-bridge/tss-api/app/sign/eddsa"
	"rosen-bridge/tss-api/logger"
	"rosen-bridge/tss-api/models"
	"rosen-bridge/tss-api/network"
	"rosen-bridge/tss-api/storage"
	"rosen-bridge/tss-api/utils"
)

type rosenTss struct {
	registryMu         sync.RWMutex
	ChannelMap         map[string]chan models.GossipMessage
	KeygenOperationMap map[string]_interface.KeygenOperation
	SignOperationMap   map[string]_interface.SignOperation
	eddsaMetaData      models.MetaData
	ecdsaMetaData      models.MetaData
	storage            storage.Storage
	connection         network.Connection
	Config             models.Config
	peerHome           string
	P2pId              string
}

var logging *zap.SugaredLogger

// Constructor of an app
func NewRosenTss(connection network.Connection, storage storage.Storage, config models.Config) _interface.RosenTss {
	logging = logger.NewSugar("app")
	return &rosenTss{
		ChannelMap:         make(map[string]chan models.GossipMessage),
		KeygenOperationMap: make(map[string]_interface.KeygenOperation),
		SignOperationMap:   make(map[string]_interface.SignOperation),
		eddsaMetaData:      models.MetaData{},
		ecdsaMetaData:      models.MetaData{},
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

func (r *rosenTss) timeOutGoRoutine(operationName string, operationTimeout int, errorCh chan error) func() {
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		timer := time.NewTimer(time.Second * time.Duration(operationTimeout))
		defer timer.Stop()
		select {
		case <-ctx.Done():
		case <-timer.C:
			select {
			case errorCh <- fmt.Errorf("%s operation timeout", operationName):
			case <-ctx.Done():
			}
		}
	}()
	return func() {
		cancel()
		<-finished
	}
}

// StartNewKeygen starts keygen scenario for app based on given protocol.
func (r *rosenTss) StartNewKeygen(keygenMessage models.KeygenMessage) error {
	logging.Info("Starting New keygen process")
	if keygenMessage.Crypto != models.ECDSA && keygenMessage.Crypto != models.EDDSA {
		return fmt.Errorf(models.WrongCryptoProtocolError)
	}

	path := fmt.Sprintf("%s/%s/%s", r.GetPeerHome(), keygenMessage.Crypto, "keygen_data.json")
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf(models.KeygenFileExistError)
	}

	messageId := fmt.Sprintf("%s%s", keygenMessage.Crypto, "Keygen")
	r.registryMu.RLock()
	_, exists := r.ChannelMap[messageId]
	r.registryMu.RUnlock()
	if exists {
		return fmt.Errorf(models.DuplicatedMessageIdError)
	}
	messageCh := make(chan models.GossipMessage, 100)

	var operation _interface.KeygenOperation
	switch keygenMessage.Crypto {
	case models.EDDSA:
		operation = eddsaKeygen.NewKeygenEDDSAOperation(keygenMessage)
	case models.ECDSA:
		operation = ecdsaKeygen.NewKeygenECDSAOperation(keygenMessage)
	default:
		return fmt.Errorf(models.WrongCryptoProtocolError)
	}
	channelId := operation.GetClassName()
	if err := r.reserveKeygenInstance(messageId, channelId, messageCh, operation); err != nil {
		return err
	}
	logging.Infof("creating new channel in StartNewKeygen: %v", messageId)

	errorCh := make(chan error, 1)
	cancelTimeout := r.timeOutGoRoutine(operation.GetClassName(), keygenMessage.OperationTimeout, errorCh)

	err := operation.Init(r, keygenMessage.P2PIDs)
	if err != nil {
		cancelTimeout()
		r.deleteKeygenInstance(messageId, channelId, messageCh, operation)
		return err
	}
	go func() {
		defer func() {
			cancelTimeout()
			r.deleteKeygenInstance(messageId, channelId, messageCh, operation)
		}()
		logging.Infof("calling start action for %s keygen", keygenMessage.Crypto)
		err = operation.StartAction(r, messageCh, errorCh)
		cancelTimeout()
		if err != nil {
			logging.Errorf("an error occurred in %s keygen action, err: %+v", keygenMessage.Crypto, err)
			data := models.FailKeygenData{
				Error:  err.Error(),
				Status: "fail",
			}
			r.errorCallBackCall(data, keygenMessage.CallBackUrl)
		}
		logging.Infof("end of %s keygen action", keygenMessage.Crypto)
		return
	}()

	return nil
}

// starts sign scenario for app based on given protocol.
func (r *rosenTss) StartNewSign(signMessage models.SignMessage) error {
	logging.Info("Starting New Sign process")
	if signMessage.Crypto != models.ECDSA && signMessage.Crypto != models.EDDSA {
		return fmt.Errorf(models.WrongCryptoProtocolError)
	}
	if signMessage.Crypto == models.ECDSA && len(signMessage.DerivationPath) == 0 {
		return fmt.Errorf(models.WrongDerivationPathError)
	}
	msgBytes, _ := utils.HexDecoder(signMessage.Message)
	signDataBytes := blake2b.Sum256(msgBytes)
	signDataHash := utils.HexEncoder(signDataBytes[:])
	logging.Infof("encoded sign data: %v", signDataHash)

	messageId := fmt.Sprintf("%s%s", signMessage.Crypto, signDataHash)
	r.registryMu.RLock()
	_, exists := r.ChannelMap[messageId]
	r.registryMu.RUnlock()
	if exists {
		return fmt.Errorf(models.DuplicatedMessageIdError)
	}
	messageCh := make(chan models.GossipMessage, 100)

	var operation _interface.SignOperation
	switch signMessage.Crypto {
	case models.EDDSA:
		operation = eddsaSign.NewSignEDDSAOperation(signMessage)
	case models.ECDSA:
		operation = ecdsaSign.NewSignECDSAOperation(signMessage)
	default:
		return fmt.Errorf(models.WrongCryptoProtocolError)
	}

	channelId := fmt.Sprintf("%s%s%s", operation.GetClassName(), signMessage.ChainCode, messageId)
	if err := r.reserveSignInstance(messageId, channelId, messageCh, operation); err != nil {
		return err
	}
	logging.Infof("new communication channel for signning process: %v", messageId)

	errorCh := make(chan error, 1)
	cancelTimeout := r.timeOutGoRoutine(operation.GetClassName(), signMessage.OperationTimeout, errorCh)

	err := operation.Init(r, signMessage.Peers)
	if err != nil {
		cancelTimeout()
		r.deleteSignInstance(messageId, channelId, messageCh, operation)
		return err
	}
	go func() {
		defer func() {
			cancelTimeout()
			r.deleteSignInstance(messageId, channelId, messageCh, operation)
		}()
		logging.Infof("calling start action for %s sign", signMessage.Crypto)
		err = operation.StartAction(r, messageCh, errorCh)
		cancelTimeout()
		if err != nil {
			logging.Errorf("an error occurred in %s sign action, err: %+v", signMessage.Crypto, err)
			data := models.SignData{
				Message: signMessage.Message,
				Error:   err.Error(),
				Status:  "fail",
			}
			r.errorCallBackCall(data, signMessage.CallBackUrl)
		}
		logging.Infof("end of %s sign action", signMessage.Crypto)
		return
	}()

	return nil
}

// GetPublicKey get the compressed public key of crypto
func (r *rosenTss) GetPublicKey(pkData models.GetPublicKey) (string, error) {
	switch pkData.Crypto {
	case models.EDDSA:
		eddsaKeygenData, err := r.GetStorage().LoadEDDSAKeygen(r.GetPeerHome(), r.GetP2pId())
		if err != nil {
			logging.Error(err)
			return "", err
		}
		pub := eddsaKeygenData.TssConfig.KeygenData.EDDSAPub
		compressedPublicKey := utils.GetPKFromEDDSAPub(pub.X(), pub.Y())
		encodedPK := hex.EncodeToString(compressedPublicKey)
		return encodedPK, nil
	case models.ECDSA:
		if len(pkData.DerivationPath) == 0 {
			return "", fmt.Errorf(models.WrongDerivationPathError)
		}
		ecdsaKeygenData, err := r.GetStorage().LoadECDSAKeygen(r.GetPeerHome(), r.GetP2pId())
		if err != nil {
			logging.Error(err)
			return "", err
		}
		_, extendedChildPk, err := ecdsaSign.DerivingPubkeyFromPath(ecdsaKeygenData.TssConfig.KeygenData.ECDSAPub, []byte(pkData.ChainCode), pkData.DerivationPath, tss.S256())
		if err != nil {
			return "", err
		}
		compressedPublicKey := utils.GetPKFromECDSAPub(extendedChildPk.X, extendedChildPk.Y)
		encodedPK := hex.EncodeToString(compressedPublicKey)

		return encodedPK, nil
	default:
		return "", fmt.Errorf(models.WrongCryptoProtocolError)
	}
}

// handles the receiving message from message route
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

	// wait for not found channels
	go func() {
		for i, start := 0, time.Now(); ; i++ {
			if time.Since(start) > time.Second*time.Duration(r.Config.MessageTimeout) {
				logging.Warnf("message timeout, channel not found: %+v", gossipMsg.MessageId)
				break
			}
			r.registryMu.RLock()
			messageCh, ok := r.ChannelMap[gossipMsg.MessageId]
			r.registryMu.RUnlock()
			if ok {
				send(messageCh, gossipMsg)
				break
			}
			time.Sleep(time.Millisecond * time.Duration(r.Config.WriteMsgRetryTime))
		}
	}()
	return nil
}

// returns the storage
func (r *rosenTss) GetStorage() storage.Storage {
	return r.storage
}

// returns the connection
func (r *rosenTss) GetConnection() network.Connection {
	return r.connection
}

// setups peer home address and creates that
func (r *rosenTss) SetPeerHome(homeAddress string) error {
	logging.Info("setting up home directory")

	absAddress, err := utils.SetupDir(homeAddress)
	if err != nil {
		return err
	}
	r.peerHome = absAddress
	return nil
}

// returns the peer's home
func (r *rosenTss) GetPeerHome() string {
	return r.peerHome
}

// setting ups metadata from given file in the home directory
func (r *rosenTss) SetMetaData(meta models.MetaData, crypto string) error {
	switch crypto {
	case models.EDDSA:
		r.eddsaMetaData = meta
		return nil
	case models.ECDSA:
		r.ecdsaMetaData = meta
		return nil
	default:
		return fmt.Errorf(models.WrongCryptoProtocolError)
	}
}

// returns peer's meta data
func (r *rosenTss) GetMetaData(crypto string) (models.MetaData, error) {
	switch crypto {
	case models.EDDSA:
		if (r.eddsaMetaData != models.MetaData{}) {
			return r.eddsaMetaData, nil
		} else {
			return r.eddsaMetaData, fmt.Errorf(models.EDDSANoMetaDataFoundError)
		}
	case models.ECDSA:
		if (r.ecdsaMetaData != models.MetaData{}) {
			return r.ecdsaMetaData, nil
		} else {
			return r.ecdsaMetaData, fmt.Errorf(models.ECDSANoMetaDataFoundError)
		}
	default:
		return models.MetaData{}, fmt.Errorf(models.WrongCryptoProtocolError)
	}
}

// returns list of operations
func (r *rosenTss) GetKeygenOperations() map[string]_interface.KeygenOperation {
	r.registryMu.RLock()
	defer r.registryMu.RUnlock()
	operations := make(map[string]_interface.KeygenOperation, len(r.KeygenOperationMap))
	for id, operation := range r.KeygenOperationMap {
		operations[id] = operation
	}
	return operations
}

// returns list of operations
func (r *rosenTss) GetSignOperations() map[string]_interface.SignOperation {
	r.registryMu.RLock()
	defer r.registryMu.RUnlock()
	operations := make(map[string]_interface.SignOperation, len(r.SignOperationMap))
	for id, operation := range r.SignOperationMap {
		operations[id] = operation
	}
	return operations
}

// reserveKeygenInstance atomically checks conflicts and registers the keygen operation and its channel.
func (r *rosenTss) reserveKeygenInstance(messageId string, channelId string, messageCh chan models.GossipMessage, operation _interface.KeygenOperation) error {
	var signClass string
	switch operation.GetClassName() {
	case models.ECDSA + "Keygen":
		signClass = models.ECDSA + "Sign"
	case models.EDDSA + "Keygen":
		signClass = models.EDDSA + "Sign"
	}
	r.registryMu.Lock()
	defer r.registryMu.Unlock()
	if _, ok := r.ChannelMap[messageId]; ok {
		return fmt.Errorf(models.DuplicatedMessageIdError)
	}
	if signClass != "" {
		for _, activeOperation := range r.SignOperationMap {
			if activeOperation.GetClassName() == signClass {
				return fmt.Errorf("%s "+models.OperationIsRunningError, signClass)
			}
		}
	}
	r.ChannelMap[messageId] = messageCh
	r.KeygenOperationMap[channelId] = operation
	return nil
}

// reserveSignInstance atomically checks conflicts and registers the signing operation and its channel.
func (r *rosenTss) reserveSignInstance(messageId string, channelId string, messageCh chan models.GossipMessage, operation _interface.SignOperation) error {
	className := operation.GetClassName()
	var keygenClass string
	switch className {
	case models.ECDSA + "Sign":
		keygenClass = models.ECDSA + "Keygen"
	case models.EDDSA + "Sign":
		keygenClass = models.EDDSA + "Keygen"
	}
	r.registryMu.Lock()
	defer r.registryMu.Unlock()
	if _, ok := r.ChannelMap[messageId]; ok {
		return fmt.Errorf(models.DuplicatedMessageIdError)
	}
	if keygenClass != "" {
		if _, ok := r.KeygenOperationMap[keygenClass]; ok {
			return fmt.Errorf("%s "+models.OperationIsRunningError, keygenClass)
		}
	}
	r.ChannelMap[messageId] = messageCh
	r.SignOperationMap[channelId] = operation
	return nil
}

// removes operation and related channel for Keygen operation
func (r *rosenTss) deleteKeygenInstance(messageId string, channelId string, messageCh chan models.GossipMessage, operation _interface.KeygenOperation) {
	operationName := operation.GetClassName()
	r.registryMu.Lock()
	if r.ChannelMap[messageId] != messageCh || r.KeygenOperationMap[channelId] != operation {
		r.registryMu.Unlock()
		return
	}
	delete(r.KeygenOperationMap, channelId)
	delete(r.ChannelMap, messageId)
	r.registryMu.Unlock()
	logging.Infof("operation %s removed for channelId %s and messageId %s for keygen operation", operationName, channelId, messageId)
}

// removes operation and related channel for sign Operation
func (r *rosenTss) deleteSignInstance(messageId string, channelId string, messageCh chan models.GossipMessage, operation _interface.SignOperation) {
	operationName := operation.GetClassName()
	r.registryMu.Lock()
	if r.ChannelMap[messageId] != messageCh || r.SignOperationMap[channelId] != operation {
		r.registryMu.Unlock()
		return
	}
	delete(r.SignOperationMap, channelId)
	delete(r.ChannelMap, messageId)
	r.registryMu.Unlock()
	logging.Infof("operation %s removed for channelId %s and messageId %s for sign operation", operationName, channelId, messageId)
}

// set p2p to the variable
func (r *rosenTss) SetP2pId() error {
	p2pId, err := r.GetConnection().GetPeerId()
	if err != nil {
		return err
	}
	r.P2pId = p2pId
	return nil
}

// get p2pId
func (r *rosenTss) GetP2pId() string {
	return r.P2pId
}

// get Config
func (r *rosenTss) GetConfig() models.Config {
	return r.Config
}
