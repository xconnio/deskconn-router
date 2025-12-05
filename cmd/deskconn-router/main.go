package main

import (
	"fmt"
	"os"
	"os/signal"

	log "github.com/sirupsen/logrus"

	"github.com/xconnio/wampproto-go/auth"
	"github.com/xconnio/xconn-go"
)

const (
	realm = "io.xconn.deskconn"

	ProcedureCRAVerify = "io.xconn.deskconn.account.cra.verify"
)

type Authenticator struct {
	session *xconn.Session
}

func NewAuthenticator(session *xconn.Session) *Authenticator {
	return &Authenticator{
		session: session,
	}
}

func (a *Authenticator) Methods() []auth.Method {
	return []auth.Method{auth.MethodAnonymous, auth.MethodCRA}
}

func (a *Authenticator) Authenticate(request auth.Request) (auth.Response, error) {
	switch request.AuthMethod() {
	case auth.Anonymous:
		return auth.NewResponse(request.AuthID(), "anonymous", 0)
	case auth.MethodCRA:
		callResp := a.session.Call(ProcedureCRAVerify).Arg(request.AuthID()).Do()
		if callResp.Err != nil {
			return nil, callResp.Err
		}

		dict, err := callResp.ArgDict(0)
		if err != nil {
			return nil, err
		}

		authrole, err := dict.String("authrole")
		if err != nil {
			return nil, fmt.Errorf("failed to get authrole for user(%s): %w", request.AuthID(), err)
		}
		secret, err := dict.String("password")
		if err != nil {
			return nil, fmt.Errorf("failed to get secret for user(%s): %w", request.AuthID(), err)
		}
		salt, err := dict.String("salt")
		if err != nil {
			return nil, fmt.Errorf("failed to get salt for user(%s): %w", request.AuthID(), err)
		}
		iteration := dict.Int64Or("iteration", 1000)
		keyLength := dict.Int64Or("key_length", 32)
		return auth.NewCRAResponseSalted(request.AuthID(), authrole, secret, salt, int(iteration), int(keyLength), 0), nil

	default:
		return nil, fmt.Errorf("unsupported authentication method: %v", request.AuthMethod())
	}
}

func main() {
	router, err := xconn.NewRouter(xconn.DefaultRouterConfig())
	if err != nil {
		log.Fatal(err)
	}

	err = router.AddRealm(realm, &xconn.RealmConfig{
		AutoDiscloseCaller: true,
		Roles: []xconn.RealmRole{
			{
				Name: "anonymous",
				Permissions: []xconn.Permission{
					{
						URI:           "io.xconn.",
						MatchPolicy:   "prefix",
						AllowCall:     true,
						AllowRegister: true,
					},
				},
			},
			{
				Name: "user",
				Permissions: []xconn.Permission{
					{
						URI:           "io.xconn.deskconn.account.",
						MatchPolicy:   "prefix",
						AllowCall:     true,
						AllowRegister: true,
					},
				},
			},
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	session, err := xconn.ConnectInMemory(router, realm)
	if err != nil {
		log.Fatal(err)
	}
	server := xconn.NewServer(router, NewAuthenticator(session), &xconn.ServerConfig{})
	listener, err := server.ListenAndServeWebSocket(xconn.NetworkTCP, "0.0.0.0:8080")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("listening on %s", listener.Addr().String())
	defer listener.Close()

	// Close server if SIGINT (CTRL-c) received.
	closeChan := make(chan os.Signal, 1)
	signal.Notify(closeChan, os.Interrupt)
	<-closeChan
}
