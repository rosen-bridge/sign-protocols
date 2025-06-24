package eddsa

import (
	eddsaKeygen "github.com/bnb-chain/tss-lib/v2/eddsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"rosen-bridge/tss-api/app/keygen"
	"rosen-bridge/tss-api/models"
)

type EDDSAHandler interface {
	StartParty(
		localTssData *models.TssData,
		threshold int,
		outCh chan tss.Message,
		endCh chan *eddsaKeygen.LocalPartySaveData,
	) error
}

type operationEDDSAKeygen struct {
	keygen.StructKeygen
	EDDSAHandler
}

type handler struct{}
