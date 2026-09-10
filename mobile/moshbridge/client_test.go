package moshbridge

import (
	"bytes"
	"encoding/base64"
	"io"
	"sync"
	"testing"
	"time"

	mosh "github.com/unixshells/mosh-go"
)

func TestDecodeKeyValidation(t *testing.T) {
	valid := base64.RawStdEncoding.EncodeToString(make([]byte, 16))
	if _, err := decodeKey(valid); err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
	for _, key := range []string{"", "bad", base64.StdEncoding.EncodeToString(make([]byte, 15))} {
		if _, err := decodeKey(key); err == nil {
			t.Fatalf("invalid key %q accepted", key)
		}
	}
}

func TestEncryptedClientServerTerminalJourney(t *testing.T) {
	server, err := mosh.NewServer("", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	echo := newEchoReadWriteCloser()
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.ServeRW(echo, func(cols, rows uint16) {}) }()

	client, err := Dial("127.0.0.1", server.Port(), server.KeyBase64())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Resize(100, 40); err != nil {
		t.Fatal(err)
	}
	if err := client.Send([]byte("echo-through-mosh")); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	var output []byte
	for time.Now().Before(deadline) && !bytes.Contains(output, []byte("echo-through-mosh")) {
		chunk, err := client.Receive(250)
		if err != nil {
			t.Fatal(err)
		}
		output = append(output, chunk...)
	}
	if !bytes.Contains(output, []byte("echo-through-mosh")) {
		t.Fatalf("encrypted terminal output missing from %q", output)
	}

	// The idle path, which the loop above never reaches while output is
	// flowing. gomobile emits Receive as `-receive:error:` returning a
	// nullable NSData, and Swift imports that under Objective-C's "nil means
	// failure" convention: nil with no NSError set makes Swift synthesize an
	// error and throw. The Swift receive loop reads a throw as a dropped
	// session, so a nil here kills a healthy Mosh session on its first quiet
	// poll -- and the client then reconnects, spawning a server per attempt.
	sawIdlePoll := false
	for i := 0; i < 40; i++ {
		chunk, err := client.Receive(50)
		if err != nil {
			t.Fatal(err)
		}
		if chunk == nil {
			t.Fatal("Receive returned nil on an idle poll; must be empty-but-non-nil")
		}
		if len(chunk) == 0 {
			sawIdlePoll = true
			break
		}
	}
	if !sawIdlePoll {
		t.Fatal("never observed an idle Receive; the nil-vs-empty path went untested")
	}
	echo.Close()
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not stop")
	}
}

type echoReadWriteCloser struct {
	data chan []byte
	once sync.Once
}

func newEchoReadWriteCloser() *echoReadWriteCloser {
	return &echoReadWriteCloser{data: make(chan []byte, 16)}
}

func (e *echoReadWriteCloser) Read(buffer []byte) (int, error) {
	data, ok := <-e.data
	if !ok {
		return 0, io.EOF
	}
	return copy(buffer, data), nil
}

func (e *echoReadWriteCloser) Write(data []byte) (int, error) {
	copyOfData := append([]byte(nil), data...)
	select {
	case e.data <- copyOfData:
		return len(data), nil
	case <-time.After(time.Second):
		return 0, io.ErrClosedPipe
	}
}

func (e *echoReadWriteCloser) Close() error {
	e.once.Do(func() { close(e.data) })
	return nil
}

func TestDialRejectsInvalidArgumentsBeforeOpeningSession(t *testing.T) {
	if _, err := Dial("127.0.0.1", 0, "bad"); err == nil {
		t.Fatal("invalid port accepted")
	}
	if _, err := Dial("127.0.0.1", 60000, "bad"); err == nil {
		t.Fatal("invalid key accepted")
	}
}

func TestPredictiveEchoOnlyAcceptsShortPrintableUTF8(t *testing.T) {
	if got := string(PredictiveEcho([]byte("hello"))); got != "\x1b[4mhello\x1b[24m" {
		t.Fatalf("prediction = %q", got)
	}
	for _, input := range [][]byte{{'\r'}, make([]byte, 33), {0xff}} {
		if got := PredictiveEcho(input); got != nil {
			t.Fatalf("unsafe input predicted as %q", got)
		}
	}
}
