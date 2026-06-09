package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/xconnio/xconn-go"
)

// streamBroker stores an active yamux client connection per device realm.
type streamBroker struct {
	sync.RWMutex
	devices map[string]*xconn.YamuxClientConn
}

func newStreamBroker() *streamBroker {
	return &streamBroker{devices: make(map[string]*xconn.YamuxClientConn)}
}

func (r *streamBroker) register(realm string, conn *xconn.YamuxClientConn) {
	r.Lock()
	r.devices[realm] = conn
	r.Unlock()
}

func (r *streamBroker) unregister(realm string) {
	r.Lock()
	delete(r.devices, realm)
	r.Unlock()
}

func (r *streamBroker) lookup(realm string) (*xconn.YamuxClientConn, bool) {
	r.RLock()
	conn, ok := r.devices[realm]
	r.RUnlock()
	return conn, ok
}

// isDeviceSession returns true for deskconnd daemon connections.
func isDeviceSession(session xconn.BaseSession) bool {
	return strings.HasPrefix(session.AuthRole(), "xconnio:deskconn:desktop:")
}

// trackDevices reads from the Conns channel and registers/unregisters device connections.
func (r *streamBroker) trackDevices(conns <-chan *xconn.YamuxConnEvent) {
	for event := range conns {
		go r.trackDevice(event)
	}
}

func (r *streamBroker) trackDevice(event *xconn.YamuxConnEvent) {
	if !isDeviceSession(event.Session) {
		return
	}
	rlm := event.Session.Realm()
	r.register(rlm, event.Conn)
	<-event.Ctx.Done()
	r.unregister(rlm)
}

// relayRequest is sent by the CLI on its yamux stream.
// The target realm is taken from the authenticated WAMP session, not from this struct.
type relayRequest struct {
	Op        string `json:"op"` // "upload" | "download"
	Path      string `json:"path"`
	Recursive bool   `json:"recursive,omitempty"`
}

// relayStreams reads from the Streams channel and bridges each CLI stream to the target device.
func (r *streamBroker) relayStreams(streams <-chan *xconn.YamuxStreamEvent) {
	for event := range streams {
		go r.relayStream(event)
	}
}

func (r *streamBroker) relayStream(event *xconn.YamuxStreamEvent) {
	cliStream := event.Stream
	defer cliStream.Close()

	if isDeviceSession(event.Session) {
		return
	}

	rlm := event.Session.Realm()

	var req relayRequest
	if err := readRelayMsg(cliStream, &req); err != nil {
		log.Debugf("relay: failed to read relay request from %s: %v", rlm, err)
		return
	}

	deviceConn, ok := r.lookup(rlm)
	if !ok {
		log.Warnf("relay: device for realm %s not connected", rlm)
		writeRelayError(cliStream, fmt.Sprintf("device for realm %q is not connected", rlm))
		return
	}

	deviceStream, err := deviceConn.OpenStream()
	if err != nil {
		log.Errorf("relay: failed to open stream to device in realm %s: %v", rlm, err)
		writeRelayError(cliStream, "failed to open stream to device")
		return
	}
	defer deviceStream.Close()

	// Forward the request to the device so it knows op/path.
	if err := writeRelayMsg(deviceStream, req); err != nil {
		log.Debugf("relay: failed to forward request to device: %v", err)
		return
	}

	log.Debugf("relay: bridging %s for realm=%s", req.Op, rlm)
	bridge(cliStream, deviceStream)
	log.Debugf("relay: bridge done for realm=%s", rlm)
}

// bridge copies data between two connections concurrently until both sides are done.
func bridge(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(a, b)
		_ = a.Close()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
		_ = b.Close()
	}()
	wg.Wait()
}

func writeRelayMsg(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(b))) // nolint:gosec
	if _, err = w.Write(length[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func readRelayMsg(r io.Reader, v any) error {
	var length [4]byte
	if _, err := io.ReadFull(r, length[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(length[:])
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	return json.Unmarshal(buf, v)
}

func writeRelayError(w io.Writer, msg string) {
	_ = writeRelayMsg(w, map[string]string{"error": msg})
}
