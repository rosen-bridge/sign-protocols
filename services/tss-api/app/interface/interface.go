package _interface

import (
	"rosen-bridge/tss-api/models"
	"rosen-bridge/tss-api/network"
	"rosen-bridge/tss-api/storage"
)

//	(keygen protocol)
type KeygenOperation interface {
	Init(RosenTss, []string) error
	StartAction(RosenTss, chan models.GossipMessage, chan error) error
	GetClassName() string
}

//	(sign protocol)
type SignOperation interface {
	Init(RosenTss, []models.Peer) error
	StartAction(RosenTss, chan models.GossipMessage, chan error) error
	GetClassName() string
}

//	Interface of an app
type RosenTss interface {
	StartNewKeygen(models.KeygenMessage) error
	StartNewSign(models.SignMessage) error
	MessageHandler(models.Message) error

	GetStorage() storage.Storage
	GetConnection() network.Connection

	SetMetaData(data models.MetaData, crypto string) error
	GetMetaData(crypto string) (models.MetaData, error)

	SetPeerHome(string) error
	GetPeerHome() string

	GetKeygenOperations() map[string]KeygenOperation
	GetSignOperations() map[string]SignOperation

	SetP2pId() error
	GetP2pId() string
	GetConfig() models.Config
	GetTrustKey() string
}
