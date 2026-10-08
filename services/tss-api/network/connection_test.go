package network

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"rosen-bridge/tss-api/logger"
	"rosen-bridge/tss-api/models"
)

// The connection methods log through the package-level `logging` sugar,
// which is backed by the logger package's global logger. Initialize it
// once (against a throwaway file) so the tests can call the methods.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "tss-api-connection-test")
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
	logging = logger.NewSugar("connection-test")
	os.Exit(m.Run())
}

// trackingBody records whether the body was read to EOF and closed.
type trackingBody struct {
	io.Reader
	closed    bool
	readToEOF bool
}

func (b *trackingBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	if errors.Is(err, io.EOF) {
		b.readToEOF = true
	}
	return n, err
}

func (b *trackingBody) Close() error {
	b.closed = true
	return nil
}

type fakeHTTPClient struct {
	status int
	body   *trackingBody
}

func (f *fakeHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: f.status,
		Header:     make(http.Header),
		Body:       f.body,
	}, nil
}

func newTestConnect(status int, responseBody string) (*connect, *trackingBody) {
	body := &trackingBody{Reader: strings.NewReader(responseBody)}
	return &connect{
		publishUrl:      "http://guard/p2p/send",
		subscriptionUrl: "http://guard/p2p/channel/subscribe",
		getPeerIDUrl:    "http://guard/p2p/getPeerID",
		apiKey:          "test-key",
		Client:          &fakeHTTPClient{status: status, body: body},
	}, body
}

func TestInitConnectionSetsHTTPTimeout(t *testing.T) {
	conn := InitConnection(
		"/p2p/send",
		"/p2p/channel/subscribe",
		"http://guard",
		"/p2p/getPeerID",
		"test-key",
	)
	c, ok := conn.(*connect)
	if !ok {
		t.Fatalf("InitConnection returned %T, expected *connect", conn)
	}
	client, ok := c.Client.(*http.Client)
	if !ok {
		t.Fatalf("connection client is %T, expected *http.Client", c.Client)
	}
	if client.Timeout != 30*time.Second {
		t.Errorf(
			"http client timeout = %v, expected 30s: a guard that stops answering must not block a call forever",
			client.Timeout,
		)
	}
}

func TestPublishClosesResponseBody(t *testing.T) {
	conn, body := newTestConnect(http.StatusOK, `{"message":"ok"}`)
	err := conn.Publish(models.GossipMessage{MessageId: "1", Message: "hello"})
	if err != nil {
		t.Fatalf("Publish returned unexpected error: %v", err)
	}
	if !body.closed {
		t.Error("Publish did not close the response body")
	}
}

func TestPublishClosesResponseBodyOnErrorStatus(t *testing.T) {
	conn, body := newTestConnect(http.StatusInternalServerError, `{"message":"no"}`)
	err := conn.Publish(models.GossipMessage{MessageId: "1", Message: "hello"})
	if err == nil {
		t.Fatal("Publish expected an error for a 500 response, got nil")
	}
	if !body.closed {
		t.Error("Publish did not close the response body on the error-status path")
	}
}

func TestSubscribeClosesResponseBodyOnErrorStatus(t *testing.T) {
	conn, body := newTestConnect(http.StatusInternalServerError, `{"message":"no"}`)
	err := conn.Subscribe("http://localhost:4000")
	if err == nil {
		t.Fatal("Subscribe expected an error for a 500 response, got nil")
	}
	if !body.closed {
		t.Error("Subscribe did not close the response body on the error-status path")
	}
}

// CallBack never reads its response body, so unless it drains and closes
// it, every callback leaks the connection for the life of the process.
func TestCallBackDrainsAndClosesResponseBody(t *testing.T) {
	conn, body := newTestConnect(http.StatusOK, `{"message":"ok"}`)
	err := conn.CallBack("http://guard/callback", map[string]string{"status": "done"})
	if err != nil {
		t.Fatalf("CallBack returned unexpected error: %v", err)
	}
	if !body.readToEOF {
		t.Error("CallBack did not read the response body to EOF, so the connection cannot be reused")
	}
	if !body.closed {
		t.Error("CallBack did not close the response body")
	}
}

func TestGetPeerIdClosesResponseBody(t *testing.T) {
	conn, body := newTestConnect(http.StatusOK, `{"status":"ok","message":"peer-1"}`)
	peerId, err := conn.GetPeerId()
	if err != nil {
		t.Fatalf("GetPeerId returned unexpected error: %v", err)
	}
	if peerId != "peer-1" {
		t.Errorf("GetPeerId = %q, expected %q", peerId, "peer-1")
	}
	if !body.closed {
		t.Error("GetPeerId did not close the response body")
	}
}

func TestGetPeerIdClosesResponseBodyOnErrorStatus(t *testing.T) {
	conn, body := newTestConnect(http.StatusInternalServerError, `{"status":"error"}`)
	_, err := conn.GetPeerId()
	if err == nil {
		t.Fatal("GetPeerId expected an error for a 500 response, got nil")
	}
	if !body.closed {
		t.Error("GetPeerId did not close the response body on the error-status path")
	}
}
