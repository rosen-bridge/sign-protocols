package eddsa

import (
	"errors"
	"math/big"
	"sync/atomic"
	"syscall"
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

// fakeParty is a tss.Party that already exists, so StartAction runs with a
// started party and never needs to create one.
type fakeParty struct {
	tss.BaseParty
}

func (p *fakeParty) Start() *tss.Error { return nil }

func (p *fakeParty) UpdateFromBytes([]byte, *tss.PartyID, bool) (bool, *tss.Error) {
	return true, nil
}

func (p *fakeParty) Update(tss.ParsedMessage) (bool, *tss.Error) { return true, nil }

func (p *fakeParty) StoreMessage(tss.ParsedMessage) (bool, *tss.Error) { return true, nil }

func (p *fakeParty) FirstRound() tss.Round { return nil }

func (p *fakeParty) PartyID() *tss.PartyID { return nil }

// fakeRosenTss is a minimal RosenTss: StartAction only reads the config and,
// when it has to create the party, the metadata.
type fakeRosenTss struct {
	metaData models.MetaData
	metaErr  error
}

func (f *fakeRosenTss) StartNewKeygen(models.KeygenMessage) error { return nil }
func (f *fakeRosenTss) StartNewSign(models.SignMessage) error     { return nil }
func (f *fakeRosenTss) MessageHandler(models.Message) error       { return nil }
func (f *fakeRosenTss) GetStorage() storage.Storage               { return nil }
func (f *fakeRosenTss) GetConnection() network.Connection         { return nil }
func (f *fakeRosenTss) SetMetaData(models.MetaData, string) error { return nil }
func (f *fakeRosenTss) SetPeerHome(string) error                  { return nil }
func (f *fakeRosenTss) GetPeerHome() string                       { return "" }
func (f *fakeRosenTss) SetP2pId() error                           { return nil }
func (f *fakeRosenTss) GetP2pId() string                          { return "fake-peer" }
func (f *fakeRosenTss) GetPublicKey(models.GetPublicKey) (string, error) {
	return "", nil
}
func (f *fakeRosenTss) GetMetaData(string) (models.MetaData, error) {
	return f.metaData, f.metaErr
}
func (f *fakeRosenTss) GetKeygenOperations() map[string]_interface.KeygenOperation {
	return nil
}
func (f *fakeRosenTss) GetSignOperations() map[string]_interface.SignOperation {
	return nil
}
func (f *fakeRosenTss) GetConfig() models.Config {
	return models.Config{WaitInPartyMessageHandling: 10}
}

// fakeSignHandler records StartParty calls and installs a fake party, like
// the real handler does on success.
type fakeSignHandler struct {
	startCalls atomic.Int32
}

func (h *fakeSignHandler) LoadData(_interface.RosenTss) (*tss.PartyID, error) {
	return nil, nil
}

func (h *fakeSignHandler) GetData() ([]*big.Int, *big.Int) { return nil, nil }

func (h *fakeSignHandler) StartParty(
	localTssData *models.TssData,
	_ int,
	_ models.SignMessage,
	_ chan tss.Message,
	_ chan *common.SignatureData,
) error {
	h.startCalls.Add(1)
	localTssData.Party = &fakeParty{}
	return nil
}

func newTestOperation(handler sign.Handler) *operationEDDSASign {
	return &operationEDDSASign{
		StructSign: sign.StructSign{
			SignMessage: models.SignMessage{Crypto: models.EDDSA},
			Logger:      zap.NewNop().Sugar(),
			Handler:     handler,
		},
	}
}

func processCPUTime(t *testing.T) time.Duration {
	t.Helper()
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		t.Fatalf("getrusage failed: %v", err)
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

// Regression test for the busy-spin reported in sign-protocols#7: with the
// party already started and no message, error or result arriving, StartAction
// must block in its select instead of spinning on the `default` branch and
// keeping a CPU core at 100% for the whole operation.
func TestStartActionWaitsWithoutBusySpinning(t *testing.T) {
	op := newTestOperation(&fakeSignHandler{})
	op.LocalTssData.Party = &fakeParty{}

	rosenTss := &fakeRosenTss{}
	messageCh := make(chan models.GossipMessage)
	errorCh := make(chan error)
	done := make(chan error, 1)
	go func() {
		done <- op.StartAction(rosenTss, messageCh, errorCh)
	}()

	// let StartAction settle into its wait, then measure the CPU the
	// process burns while nothing happens
	time.Sleep(50 * time.Millisecond)
	const window = 600 * time.Millisecond
	startCPU := processCPUTime(t)
	startWall := time.Now()
	time.Sleep(window)
	cpuDelta := processCPUTime(t) - startCPU
	wallDelta := time.Since(startWall)

	if cpuDelta > wallDelta/2 {
		t.Fatalf(
			"StartAction burned %v of CPU during a %v idle wait; it should block waiting for the next message",
			cpuDelta, wallDelta,
		)
	}

	// an error on the error channel must still end the operation
	errorCh <- errors.New("boom")
	select {
	case err := <-done:
		if err == nil || err.Error() != "boom" {
			t.Fatalf("expected StartAction to return the channel error, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("StartAction did not return after an error was sent")
	}
}

// The party must still be created exactly once, before StartAction settles
// into waiting for messages.
func TestStartActionCreatesPartyOnce(t *testing.T) {
	handler := &fakeSignHandler{}
	op := newTestOperation(handler)

	rosenTss := &fakeRosenTss{
		metaData: models.MetaData{PeersCount: 1, Threshold: 1},
	}
	messageCh := make(chan models.GossipMessage)
	errorCh := make(chan error)
	done := make(chan error, 1)
	go func() {
		done <- op.StartAction(rosenTss, messageCh, errorCh)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for handler.startCalls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := handler.startCalls.Load(); got != 1 {
		t.Fatalf("expected the party to be created exactly once, got %d StartParty calls", got)
	}
	if op.LocalTssData.Party == nil {
		t.Fatal("expected the created party to be stored on the operation")
	}

	errorCh <- errors.New("boom")
	select {
	case err := <-done:
		if err == nil || err.Error() != "boom" {
			t.Fatalf("expected StartAction to return the channel error, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("StartAction did not return after an error was sent")
	}
	if got := handler.startCalls.Load(); got != 1 {
		t.Fatalf("expected no further StartParty calls while waiting, got %d", got)
	}
}

// A closed communication channel must still end the operation with an error.
func TestStartActionReturnsWhenMessageChannelCloses(t *testing.T) {
	op := newTestOperation(&fakeSignHandler{})
	op.LocalTssData.Party = &fakeParty{}

	rosenTss := &fakeRosenTss{}
	messageCh := make(chan models.GossipMessage)
	errorCh := make(chan error)
	done := make(chan error, 1)
	go func() {
		done <- op.StartAction(rosenTss, messageCh, errorCh)
	}()

	close(messageCh)
	select {
	case err := <-done:
		if err == nil || err.Error() != "communication channel is closed" {
			t.Fatalf("expected the closed-channel error, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("StartAction did not return after the message channel closed")
	}
}
