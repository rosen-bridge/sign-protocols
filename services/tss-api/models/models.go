package models

import (
	ecdsaKeygen "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	eddsaKeygen "github.com/bnb-chain/tss-lib/v2/eddsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

const (
	KeygenFileExistError        = "keygen file exists"
	DuplicatedMessageIdError    = "duplicated messageId"
	OperationIsRunningError     = "operation is running"
	EDDSANoKeygenDataFoundError = "no keygen data found for eddsa"
	ECDSANoKeygenDataFoundError = "no keygen data found for ecdsa"
	EDDSANoMetaDataFoundError   = "no meta data found for eddsa"
	ECDSANoMetaDataFoundError   = "no meta data found for ecdsa"
	InvalidCryptoFoundError     = "invalid crypto algorithm"
	WrongOperationError         = "wrong operation"
	WrongCryptoProtocolError    = "wrong crypto protocol"
	WrongDerivationPathError    = "wrong derivation path"
)

const (
	ECDSA = "ecdsa"
	EDDSA = "eddsa"
)

type KeygenMessage struct {
	PeersCount       int      `json:"peersCount" validate:"required"`
	Threshold        int      `json:"threshold" validate:"required"`
	Crypto           string   `json:"crypto" validate:"required"`
	CallBackUrl      string   `json:"callBackUrl" validate:"required"`
	P2PIDs           []string `json:"p2pIDs" validate:"required"`
	OperationTimeout int      `json:"operationTimeout" validate:"required"`
}

type SignMessage struct {
	Crypto           string   `json:"crypto" validate:"required"`
	Message          string   `json:"message" validate:"required"`
	CallBackUrl      string   `json:"callBackUrl" validate:"required"`
	Peers            []Peer   `json:"peers" validate:"required"`
	OperationTimeout int      `json:"operationTimeout" validate:"required"`
	ChainCode        string   `json:"chainCode" validate:"required"`
	DerivationPath   []uint32 `json:"derivationPath"`
}

type GetPublicKey struct {
	Crypto         string   `json:"crypto" validate:"required"`
	ChainCode      string   `json:"chainCode" validate:"required"`
	DerivationPath []uint32 `json:"derivationPath"`
}

type Peer struct {
	ShareID string `json:"shareID"`
	P2PID   string `json:"p2pID"`
}

type SignData struct {
	Message           string `json:"message"`
	Signature         string `json:"signature"`
	SignatureRecovery string `json:"signatureRecovery"`
	Status            string `json:"status"`
	Error             string `json:"error"`
	TrustKey          string `json:"trustKey"`
}

type KeygenData struct {
	ShareID string `json:"shareID"`
	PubKey  string `json:"pubKey"`
	Status  string `json:"status"`
}

type FailKeygenData struct {
	Status string `json:"status"`
	Error  string `json:"error"`
}

type Message struct {
	Message string `json:"message"`
	Sender  string `json:"sender"`
	Topic   string `json:"channel"`
}

type GossipMessage struct {
	MessageId  string `json:"messageId"`
	Message    string `json:"message"`
	SenderId   string `json:"senderId"`
	ReceiverId string `json:"receiverId"`
}

type MetaData struct {
	PeersCount int `json:"peersCount"`
	Threshold  int `json:"threshold"`
}

type TssConfigEDDSA struct {
	MetaData   MetaData                       `json:"metaData"`
	KeygenData eddsaKeygen.LocalPartySaveData `json:"keygenData"`
}

type TssConfigECDSA struct {
	MetaData   MetaData                       `json:"metaData"`
	KeygenData ecdsaKeygen.LocalPartySaveData `json:"keygenData"`
}

type TssData struct {
	PartyID  *tss.PartyID
	Params   *tss.Parameters
	PartyIds tss.SortedPartyIDs
	Party    tss.Party
}

type PartyMessage struct {
	Message                 []byte
	GetFrom                 *tss.PartyID
	GetTo                   []*tss.PartyID
	IsBroadcast             bool
	IsToOldCommittee        bool
	IsToOldAndNewCommittees bool
}

type Config struct {
	HomeAddress                string  `mapstructure:"TSS_HOME_ADDRESS"`
	LogAddress                 string  `mapstructure:"TSS_LOG_ADDRESS"`
	LogLevel                   string  `mapstructure:"TSS_LOG_LEVEL"`
	LogMaxSize                 int     `mapstructure:"TSS_LOG_MAX_SIZE"`
	LogMaxBackups              int     `mapstructure:"TSS_LOG_MAX_BACKUPS"`
	LogMaxAge                  int     `mapstructure:"TSS_LOG_MAX_AGE"`
	MessageTimeout             int     `mapstructure:"TSS_MESSAGE_TIMEOUT"`
	WriteMsgRetryTime          int     `mapstructure:"TSS_WRITE_MSG_RETRY_TIME"`
	LeastProcessRemainingTime  int64   `mapstructure:"TSS_LEAST_PROCESS_REMAINING_TIME"`
	SetupBroadcastInterval     int64   `mapstructure:"TSS_SETUP_BROADCAST_INTERVAL"`
	SignStartTimeTracker       float64 `mapstructure:"TSS_SIGN_START_TIME_TRACKER"`
	TurnDuration               int64   `mapstructure:"TSS_TURN_DURATION"`
	WaitInPartyMessageHandling int64   `mapstructure:"TSS_WAIT_IN_PARTY_MESSAGE_HANDLING"`
}

type Payload struct {
	MessageId string `json:"messageId"`
	Message   string `json:"message"`
	SenderId  string `json:"senderId"`
}
