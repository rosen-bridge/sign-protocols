package app

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"rosen-bridge/tss-api/app/interface"
	"rosen-bridge/tss-api/logger"
	"rosen-bridge/tss-api/models"
)

// The app methods log through the package-level `logging` sugar, which is
// backed by the logger package's global logger. Initialize it once
// (against a throwaway file) so the tests can call the methods.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "tss-api-app-test")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	err = logger.Init(
		filepath.Join(dir, "test.log"),
		models.Config{LogLevel: "error", LogMaxSize: 1, LogMaxBackups: 1, LogMaxAge: 1},
		false,
	)
	if err != nil {
		panic(err)
	}
	logging = logger.NewSugar("app-test")
	os.Exit(m.Run())
}

type fakeSignOperation struct{}

func (fakeSignOperation) Init(_interface.RosenTss, []models.Peer) error {
	return nil
}

func (fakeSignOperation) StartAction(_interface.RosenTss, chan models.GossipMessage, chan error) error {
	return nil
}

func (fakeSignOperation) GetClassName() string {
	return "eddsaSign"
}

type fakeKeygenOperation struct{}

func (fakeKeygenOperation) Init(_interface.RosenTss, []string) error {
	return nil
}

func (fakeKeygenOperation) StartAction(_interface.RosenTss, chan models.GossipMessage, chan error) error {
	return nil
}

func (fakeKeygenOperation) GetClassName() string {
	return "eddsaKeygen"
}

func newTestRosenTss() *rosenTss {
	return &rosenTss{
		ChannelMap:         make(map[string]chan models.GossipMessage),
		KeygenOperationMap: make(map[string]_interface.KeygenOperation),
		SignOperationMap:   make(map[string]_interface.SignOperation),
	}
}

// Regression test for the crash reported in sign-protocols#6: a sign fails
// early and is cleaned up, the same message is signed again, and then the
// first sign's timeout goroutine fires. It must not touch the retried
// operation (on the old code it sent the timeout error on the first sign's
// closed error channel and panicked, taking tss-api down).
func TestTimeoutDoesNotActOnRetriedOperation(t *testing.T) {
	r := newTestRosenTss()
	messageId := "eddsaSign0123abcd"
	channelId := "eddsaSignchain" + messageId

	oldMessageCh := make(chan models.GossipMessage, 100)
	r.ChannelMap[messageId] = oldMessageCh
	oldErrorCh := make(chan error)
	r.SignOperationMap[channelId] = fakeSignOperation{}
	r.timeOutGoRoutine("eddsaSign", 1, messageId, oldErrorCh)

	// the first sign fails early and its instance is deleted
	r.deleteSignInstance(messageId, channelId, oldErrorCh)

	// the same message is signed again: a new operation registers new
	// channels under the same messageId
	newMessageCh := make(chan models.GossipMessage, 100)
	r.ChannelMap[messageId] = newMessageCh
	newErrorCh := make(chan error)
	newReceived := make(chan error, 1)
	go func() {
		newReceived <- <-newErrorCh
	}()

	// let the first sign's timeout fire
	time.Sleep(1600 * time.Millisecond)

	select {
	case err := <-newReceived:
		t.Fatalf("stale timeout delivered an error to the retried operation: %v", err)
	default:
	}

	// the retried operation's channel must still be open (sending on a
	// closed channel panics)
	newMessageCh <- models.GossipMessage{}
	if got := len(newMessageCh); got != 1 {
		t.Fatalf("expected the retried operation's channel to hold the probe message, len = %d", got)
	}
}

// A sign that is still running when its timeout fires must receive the
// timeout error, and its channel must be closed afterwards.
func TestTimeoutFailsTheRunningOperation(t *testing.T) {
	r := newTestRosenTss()
	messageId := "eddsaSign4567efgh"

	messageCh := make(chan models.GossipMessage, 100)
	r.ChannelMap[messageId] = messageCh
	errorCh := make(chan error)
	received := make(chan error, 1)
	go func() {
		received <- <-errorCh
	}()

	r.timeOutGoRoutine("eddsaSign", 1, messageId, errorCh)

	select {
	case err := <-received:
		if err == nil || err.Error() != "eddsaSign operation timeout" {
			t.Fatalf("unexpected timeout error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the running operation did not receive the timeout error")
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		select {
		case _, ok := <-messageCh:
			if !ok {
				return
			}
			t.Fatal("unexpected gossip message on the operation channel")
		default:
			if time.Now().After(deadline) {
				t.Fatal("the operation channel was not closed after the timeout")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// A sign that finished before its timeout must be left alone: the timeout
// goroutine fires, finds nothing registered for the messageId, and exits
// without panicking.
func TestTimeoutAfterOperationFinishedIsNoOp(t *testing.T) {
	r := newTestRosenTss()
	messageId := "eddsaSign89abijkl"
	channelId := "eddsaSignchain" + messageId

	messageCh := make(chan models.GossipMessage, 100)
	r.ChannelMap[messageId] = messageCh
	errorCh := make(chan error)
	r.SignOperationMap[channelId] = fakeSignOperation{}
	r.timeOutGoRoutine("eddsaSign", 1, messageId, errorCh)

	r.deleteSignInstance(messageId, channelId, errorCh)

	// let the timeout fire; reaching the end of the test is the assertion
	time.Sleep(1600 * time.Millisecond)
}

// Deleting an instance must not close its error channel: the channel has
// several concurrent senders (party goroutines, message handlers, the
// timeout goroutine) and any of them reporting after cleanup would panic
// on a closed channel. A late error must still be deliverable.
func TestDeleteSignInstanceDoesNotCloseErrorChannel(t *testing.T) {
	r := newTestRosenTss()
	messageId := "eddsaSigncdefmnop"
	channelId := "eddsaSignchain" + messageId

	r.ChannelMap[messageId] = make(chan models.GossipMessage, 100)
	errorCh := make(chan error)
	r.SignOperationMap[channelId] = fakeSignOperation{}
	received := make(chan error, 1)
	go func() {
		received <- <-errorCh
	}()

	r.deleteSignInstance(messageId, channelId, errorCh)

	if _, ok := r.ChannelMap[messageId]; ok {
		t.Fatal("expected the instance channel to be removed")
	}
	if _, ok := r.SignOperationMap[channelId]; ok {
		t.Fatal("expected the sign operation to be removed")
	}

	// panics on the old code, where delete closed the channel
	errorCh <- errors.New("late party error")
	if err := <-received; err == nil || err.Error() != "late party error" {
		t.Fatalf("unexpected late error: %v", err)
	}
}

// Same guarantee for keygen instances.
func TestDeleteKeygenInstanceDoesNotCloseErrorChannel(t *testing.T) {
	r := newTestRosenTss()
	messageId := "eddsaKeygen"
	channelId := "eddsaKeygen"

	r.ChannelMap[messageId] = make(chan models.GossipMessage, 100)
	errorCh := make(chan error)
	r.KeygenOperationMap[channelId] = fakeKeygenOperation{}
	received := make(chan error, 1)
	go func() {
		received <- <-errorCh
	}()

	r.deleteKeygenInstance(messageId, channelId, errorCh)

	if _, ok := r.ChannelMap[messageId]; ok {
		t.Fatal("expected the instance channel to be removed")
	}
	if _, ok := r.KeygenOperationMap[channelId]; ok {
		t.Fatal("expected the keygen operation to be removed")
	}

	// panics on the old code, where delete closed the channel
	errorCh <- errors.New("late party error")
	if err := <-received; err == nil || err.Error() != "late party error" {
		t.Fatalf("unexpected late error: %v", err)
	}
}
