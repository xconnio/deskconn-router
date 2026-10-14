package router_test

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/xconnio/deskconn-router/router"
	"github.com/xconnio/wampproto-go/auth"
	"github.com/xconnio/xconn-go"
)

const (
	userRole        = "user"
	procedurePing   = "io.xconn.deskconn.deskconnd.ping"
	machineAuthID   = "machine-1"
	machineRealm    = "realm-1"
	userAuthID      = "alice"
	secondAuthID    = "machine-2"
	secondRealmName = "realm-2"
)

type keyPair struct{ public, private string }

func newKeyPair(t *testing.T) keyPair {
	t.Helper()
	public, private, err := auth.GenerateCryptoSignKeyPair()
	require.NoError(t, err)
	return keyPair{public, private}
}

// startRouter serves config on a raw socket and returns its URI.
func startRouter(t *testing.T, config router.Config) (*router.Router, string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	require.NoError(t, listener.Close())

	config.RawSocketAddress = address
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	r, err := router.New(ctx, config)
	require.NoError(t, err)
	go func() { _ = r.Serve(ctx) }()

	require.Eventually(t, func() bool {
		conn, err := net.Dial("tcp", address)
		if err == nil {
			_ = conn.Close()
		}
		return err == nil
	}, 5*time.Second, 20*time.Millisecond)
	return r, "rs://" + address
}

func connect(t *testing.T, uri, realm, authid, privateKey string) (*xconn.Session, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return xconn.ConnectCryptosign(ctx, uri, realm, authid, privateKey)
}

// A router with its own callbacks, no account service: it admits and refuses sessions
// itself, and serves the machines it's told about.
func TestCustomCallbacks(t *testing.T) {
	machineKey, secondKey, userKey, strangerKey := newKeyPair(t), newKeyPair(t), newKeyPair(t), newKeyPair(t)

	r, uri := startRouter(t, router.Config{
		Machines: func(context.Context) ([]router.Machine, error) {
			return []router.Machine{{AuthID: machineAuthID, Realm: machineRealm}}, nil
		},
		Authenticate: func(request auth.Request) (auth.Response, error) {
			cryptosign, ok := request.(*auth.RequestCryptoSign)
			if !ok {
				return nil, errors.New("cryptosign only")
			}
			switch {
			case request.AuthID() == machineAuthID && cryptosign.PublicKey() == machineKey.public:
				return auth.NewResponse(machineAuthID, router.MachineAuthRole(machineAuthID), 0)
			case request.AuthID() == secondAuthID && cryptosign.PublicKey() == secondKey.public:
				return auth.NewResponse(secondAuthID, router.MachineAuthRole(secondAuthID), 0)
			case request.AuthID() == userAuthID && cryptosign.PublicKey() == userKey.public:
				return auth.NewResponse(userAuthID, userRole, 0)
			}
			return nil, errors.New("unknown key")
		},
		UserRoles: []xconn.RealmRole{{Name: userRole, Permissions: router.MachineUserPermissions()}},
	})

	// The machine from the Machines callback serves its realm, and the user reaches it.
	machine, err := connect(t, uri, machineRealm, machineAuthID, machineKey.private)
	require.NoError(t, err)
	resp := machine.Register(procedurePing, func(context.Context, *xconn.Invocation) *xconn.InvocationResult {
		return xconn.NewInvocationResult("pong")
	}).Do()
	require.NoError(t, resp.Err)

	user, err := connect(t, uri, machineRealm, userAuthID, userKey.private)
	require.NoError(t, err)
	callResp := user.Call(procedurePing).Do()
	require.NoError(t, callResp.Err)
	require.Equal(t, "pong", callResp.ArgStringOr(0, ""))

	// Authenticate refuses who it doesn't know.
	_, err = connect(t, uri, machineRealm, userAuthID, strangerKey.private)
	require.Error(t, err)

	// A machine added at runtime is served from then on, and not after it's removed.
	second := router.Machine{AuthID: secondAuthID, Realm: secondRealmName}
	require.NoError(t, r.AddMachine(second))
	secondSession, err := connect(t, uri, secondRealmName, secondAuthID, secondKey.private)
	require.NoError(t, err)
	resp = secondSession.Register(procedurePing, func(context.Context, *xconn.Invocation) *xconn.InvocationResult {
		return xconn.NewInvocationResult("pong 2")
	}).Do()
	require.NoError(t, resp.Err)
	secondUser, err := connect(t, uri, secondRealmName, userAuthID, userKey.private)
	require.NoError(t, err)
	callResp = secondUser.Call(procedurePing).Do()
	require.NoError(t, callResp.Err)
	require.Equal(t, "pong 2", callResp.ArgStringOr(0, ""))

	require.NoError(t, r.RemoveMachine(second))
	if late, err := connect(t, uri, secondRealmName, userAuthID, userKey.private); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		require.Error(t, late.Call(procedurePing).DoContext(ctx).Err, "no longer served")
	}
}

func TestAuthenticateRequired(t *testing.T) {
	_, err := router.New(context.Background(), router.Config{})
	require.ErrorContains(t, err, "Authenticate is required")
}
