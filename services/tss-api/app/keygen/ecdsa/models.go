package ecdsa

import (
	ecdsaKeygen "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"rosen-bridge/tss-api/app/keygen"
	"rosen-bridge/tss-api/models"
)

type ECDSAHandler interface {
	StartParty(
		localTssData *models.TssData,
		threshold int,
		outCh chan tss.Message,
		endCh chan *ecdsaKeygen.LocalPartySaveData,
	) error
}

type operationECDSAKeygen struct {
	keygen.StructKeygen
	ECDSAHandler
}

type handler struct{}
