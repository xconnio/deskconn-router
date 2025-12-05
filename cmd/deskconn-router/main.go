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

	procedureCRAVerify        = "io.xconn.deskconn.account.cra.verify"
	procedureCryptosignVerify = "io.xconn.deskconn.account.cryptosign.verify"

	accountServiceAuthRole  = "xconnio:deskconn:cloud:service:account"
	accountServiceAuthID    = "deskconn-account-service"
	accountServicePublicKey = "c98fb454dfda50be26b74818d3c20caf6810970b9de4a01fe5cd6282603400f1"

	webAppAuthRole  = "xconnio:deskconn:app:web"
	webAppAuthID    = "deskconn-web-app"
	webAppPublicKey = "3339ee2adba8cb27c6ed72a222645e88475ef96a3704185efa1084ace56f3fd0"
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
	return []auth.Method{auth.MethodCRA, auth.MethodCryptoSign}
}

func (a *Authenticator) Authenticate(request auth.Request) (auth.Response, error) {
	switch request.AuthMethod() {
	case auth.MethodCRA:
		callResp := a.session.Call(procedureCRAVerify).Arg(request.AuthID()).Do()
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

	case auth.MethodCryptoSign:
		cryptosignRequest, ok := request.(*auth.RequestCryptoSign)
		if !ok {
			return nil, fmt.Errorf("invalid request")
		}
		if cryptosignRequest.PublicKey() == accountServicePublicKey && cryptosignRequest.AuthID() == accountServiceAuthID {
			return auth.NewResponse(cryptosignRequest.AuthID(), accountServiceAuthRole, 0)
		}
		if cryptosignRequest.PublicKey() == webAppPublicKey && cryptosignRequest.AuthID() == webAppAuthID {
			return auth.NewResponse(cryptosignRequest.AuthID(), webAppAuthRole, 0)
		}

		callResp := a.session.Call(procedureCryptosignVerify).Args(request.AuthID(), cryptosignRequest.PublicKey()).Do()
		if callResp.Err != nil {
			return nil, callResp.Err
		}

		dict, err := callResp.ArgDict(0)
		if err != nil {
			return nil, err
		}

		authid, err := dict.String("authid")
		if err != nil {
			return nil, fmt.Errorf("failed to get authid for user(%s): %w", request.AuthID(), err)
		}

		authrole, err := dict.String("authrole")
		if err != nil {
			return nil, fmt.Errorf("failed to get authrole for user(%s): %w", request.AuthID(), err)
		}

		return auth.NewResponse(authid, authrole, 0)
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
				Name: accountServiceAuthRole,
				Permissions: []xconn.Permission{
					{
						URI:           "io.xconn.deskconn.",
						MatchPolicy:   "prefix",
						AllowRegister: true,
					},
				},
			},
			{
				Name: webAppAuthRole,
				Permissions: []xconn.Permission{
					{
						URI:         "io.xconn.deskconn.account.create",
						MatchPolicy: "exact",
						AllowCall:   true,
					},
				},
			},
			{
				Name: "user",
				Permissions: []xconn.Permission{
					{
						URI:           "io.xconn.deskconn.",
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
