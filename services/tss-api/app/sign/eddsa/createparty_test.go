package eddsa

import (
	"errors"
	"math/big"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"go.uber.org/zap"

	_interface "rosen-bridge/tss-api/app/interface"
	"rosen-bridge/tss-api/app/sign"
	"rosen-bridge/tss-api/models"
	"rosen-bridge/tss-api/network"
	"rosen-bridge/tss-api/storage"
)

// cpFakeParty is a tss.Party that already exists, so a successful
// StartParty never needs real tss-lib crypto.
type cpFakeParty struct {
	tss.BaseParty
}

func (p *cpFakeParty) Start() *tss.Error { return nil }

func (p *cpFakeParty) UpdateFromBytes([]byte, *tss.PartyID, bool) (bool, *tss.Error) {
	return true, nil
}

func (p *cpFakeParty) Update(tss.ParsedMessage) (bool, *tss.Error) { return true, nil }

func (p *cpFakeParty) StoreMessage(tss.ParsedMessage) (bool, *tss.Error) {
	return true, nil
}

func (p *cpFakeParty) FirstRound() tss.Round      { return nil }
func (p *cpFakeParty) PartyID() *tss.PartyID      { return nil }
func (p *cpFakeParty) WaitingFor() []*tss.PartyID { return nil }

// cpFakeRosenTss is a minimal RosenTss: CreateParty only reads the metadata.
type cpFakeRosenTss struct {
	metaData models.MetaData
	metaErr  error
}

func (f *cpFakeRosenTss) StartNewKeygen(models.KeygenMessage) error { return nil }
func (f *cpFakeRosenTss) StartNewSign(models.SignMessage) error     { return nil }
func (f *cpFakeRosenTss) MessageHandler(models.Message) error       { return nil }
func (f *cpFakeRosenTss) GetStorage() storage.Storage               { return nil }
func (f *cpFakeRosenTss) GetConnection() network.Connection         { return nil }
func (f *cpFakeRosenTss) SetMetaData(models.MetaData, string) error { return nil }
func (f *cpFakeRosenTss) SetPeerHome(string) error                  { return nil }
func (f *cpFakeRosenTss) GetPeerHome() string                       { return "" }
func (f *cpFakeRosenTss) SetP2pId() error                           { return nil }
func (f *cpFakeRosenTss) GetP2pId() string                          { return "fake-peer" }
func (f *cpFakeRosenTss) GetPublicKey(models.GetPublicKey) (string, error) {
	return "", nil
}
func (f *cpFakeRosenTss) GetMetaData(string) (models.MetaData, error) {
	return f.metaData, f.metaErr
}
func (f *cpFakeRosenTss) GetKeygenOperations() map[string]_interface.KeygenOperation {
	return nil
}
func (f *cpFakeRosenTss) GetSignOperations() map[string]_interface.SignOperation {
	return nil
}
func (f *cpFakeRosenTss) GetConfig() models.Config {
	return models.Config{WaitInPartyMessageHandling: 10}
}

// cpFakeHandler records StartParty calls and returns a configured error.
type cpFakeHandler struct {
	startCalls atomic.Int32
	startErr   error
}

func (h *cpFakeHandler) LoadData(_interface.RosenTss) (*tss.PartyID, error) {
	return nil, nil
}

func (h *cpFakeHandler) GetData() ([]*big.Int, *big.Int) { return nil, nil }

func (h *cpFakeHandler) StartParty(
	localTssData *models.TssData,
	_ int,
	_ models.SignMessage,
	_ chan tss.Message,
	_ chan *common.SignatureData,
) error {
	h.startCalls.Add(1)
	if h.startErr != nil {
		return h.startErr
	}
	localTssData.Party = &cpFakeParty{}
	return nil
}

func cpNewTestOperation(handler sign.Handler, partyIds []*tss.PartyID) *operationEDDSASign {
	op := &operationEDDSASign{
		StructSign: sign.StructSign{
			SignMessage: models.SignMessage{Crypto: models.EDDSA},
			Logger:      zap.NewNop().Sugar(),
			Handler:     handler,
		},
	}
	op.LocalTssData.PartyIds = partyIds
	return op
}

func cpPartyID(id string, key int64) *tss.PartyID {
	return tss.NewPartyID(id, "tssPeer/"+id, big.NewInt(key))
}

func cpRunStartAction(
	op *operationEDDSASign,
	rosenTss _interface.RosenTss,
) chan error {
	done := make(chan error, 1)
	go func() {
		done <- op.StartAction(
			rosenTss,
			make(chan models.GossipMessage),
			make(chan error),
		)
	}()
	return done
}

func cpExpectReturn(t *testing.T, done chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal(
			"StartAction did not return; a party-creation failure must end " +
				"the operation instead of deadlocking it",
		)
		return nil
	}
}

// Regression test for the CreateParty deadlock in sign-protocols#4:
// CreateParty runs on StartAction's own goroutine, which is also the only
// reader of the unbuffered errorCh, so sending a party-start failure on
// that channel blocked forever and the operation slot was never released.
func TestStartActionReturnsPartyStartError(t *testing.T) {
	startErr := errors.New("tss-lib refused to start the party")
	handler := &cpFakeHandler{startErr: startErr}
	op := cpNewTestOperation(handler, []*tss.PartyID{
		cpPartyID("peer-a", 1),
		cpPartyID("peer-b", 2),
		cpPartyID("peer-c", 3),
	})
	rosenTss := &cpFakeRosenTss{
		metaData: models.MetaData{PeersCount: 3, Threshold: 2},
	}

	err := cpExpectReturn(t, cpRunStartAction(op, rosenTss))
	if !errors.Is(err, startErr) {
		t.Fatalf("expected StartAction to return the party-start error, got %v", err)
	}
}

// The metadata lookup failing inside CreateParty hit the same deadlock.
func TestStartActionReturnsMetaDataError(t *testing.T) {
	metaErr := errors.New("no metadata")
	handler := &cpFakeHandler{}
	op := cpNewTestOperation(handler, []*tss.PartyID{
		cpPartyID("peer-a", 1),
		cpPartyID("peer-b", 2),
	})
	rosenTss := &cpFakeRosenTss{metaErr: metaErr}

	err := cpExpectReturn(t, cpRunStartAction(op, rosenTss))
	if !errors.Is(err, metaErr) {
		t.Fatalf("expected StartAction to return the metadata error, got %v", err)
	}
	if got := handler.startCalls.Load(); got != 0 {
		t.Fatalf("expected no StartParty call without metadata, got %d", got)
	}
}

// A guard listed twice must be rejected before the party is created:
// tss-lib panics with "index of two parties are equal" on duplicate share
// indices, in a goroutine with no recover, and the process exits.
func TestStartActionRejectsDuplicateParties(t *testing.T) {
	handler := &cpFakeHandler{}
	op := cpNewTestOperation(handler, []*tss.PartyID{
		cpPartyID("peer-a", 1),
		cpPartyID("peer-b", 2),
		cpPartyID("peer-a", 1),
	})
	rosenTss := &cpFakeRosenTss{
		metaData: models.MetaData{PeersCount: 3, Threshold: 1},
	}

	err := cpExpectReturn(t, cpRunStartAction(op, rosenTss))
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected a duplicate-party error, got %v", err)
	}
	if got := handler.startCalls.Load(); got != 0 {
		t.Fatalf("expected the party not to be created, got %d StartParty calls", got)
	}
}

// Too few distinct parties for the threshold must be rejected before the
// party is created: a signing set of threshold or fewer parties can never
// produce a signature, and tss-lib's round-1 refusal deadlocked tss-api.
func TestStartActionRejectsTooFewParties(t *testing.T) {
	handler := &cpFakeHandler{}
	op := cpNewTestOperation(handler, []*tss.PartyID{
		cpPartyID("peer-a", 1),
		cpPartyID("peer-b", 2),
	})
	rosenTss := &cpFakeRosenTss{
		metaData: models.MetaData{PeersCount: 2, Threshold: 2},
	}

	err := cpExpectReturn(t, cpRunStartAction(op, rosenTss))
	if err == nil || !strings.Contains(err.Error(), "threshold") {
		t.Fatalf("expected a threshold error, got %v", err)
	}
	if got := handler.startCalls.Load(); got != 0 {
		t.Fatalf("expected the party not to be created, got %d StartParty calls", got)
	}
}
