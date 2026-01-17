package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"github.com/joho/godotenv"
	log "github.com/sirupsen/logrus"

	"github.com/xconnio/wampproto-go/auth"
	"github.com/xconnio/wampproto-go/messages"
	"github.com/xconnio/xconn-go"
)

const (
	realm = "io.xconn.deskconn"

	procedureCRAVerify        = "io.xconn.deskconn.account.cra.verify"
	procedureCryptosignVerify = "io.xconn.deskconn.account.cryptosign.verify"
	procedureDesktopAccess    = "io.xconn.deskconn.desktop.access"
	procedureAddRealm         = "io.xconn.deskconn.realm.add"
	procedureRemoveRealm      = "io.xconn.deskconn.realm.remove"

	accountServiceAuthRole  = "xconnio:deskconn:cloud:service:account"
	accountServiceAuthID    = "deskconn-account-service"
	accountServicePublicKey = "c98fb454dfda50be26b74818d3c20caf6810970b9de4a01fe5cd6282603400f1"

	webAppAuthRole  = "xconnio:deskconn:app:web"
	webAppAuthID    = "deskconn-web-app"
	webAppPublicKey = "3339ee2adba8cb27c6ed72a222645e88475ef96a3704185efa1084ace56f3fd0"

	ErrInvalidArgument = "wamp.error.invalid_argument"
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
		if cryptosignRequest.AuthID() == accountServiceAuthID {
			if cryptosignRequest.PublicKey() == accountServicePublicKey {
				return auth.NewResponse(cryptosignRequest.AuthID(), accountServiceAuthRole, 0)
			}

			return nil, fmt.Errorf("invalid private key for account service")
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
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}

	path, ok := os.LookupEnv("DESKCONN_DBPATH")
	if !ok || path == "" {
		log.Fatalln("SQLITE_DB_PATH not set")
	}
	address, ok := os.LookupEnv("DESKCONN_ROUTER_ADDRESS")
	if !ok || address == "" {
		address = "0.0.0.0:8080"
	}
	db, err := openReadOnlyDB(path)
	if err != nil {
		log.Fatalf("Error opening read-only DB: %v", err)
	}

	realms, err := getRealms(db)
	if err != nil {
		log.Fatalf("Error getting realms from db: %v", err)
	}

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
					{
						URI:         procedureAddRealm,
						MatchPolicy: "exact",
						AllowCall:   true,
					},
					{
						URI:         procedureRemoveRealm,
						MatchPolicy: "exact",
						AllowCall:   true,
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
					{
						URI:         "io.xconn.deskconn.account.verify",
						MatchPolicy: "exact",
						AllowCall:   true,
					},
					{
						URI:         "io.xconn.deskconn.account.otp.resend",
						MatchPolicy: "exact",
						AllowCall:   true,
					},
					{
						URI:         "io.xconn.deskconn.account.password.forget",
						MatchPolicy: "exact",
						AllowCall:   true,
					},
					{
						URI:         "io.xconn.deskconn.account.password.reset",
						MatchPolicy: "exact",
						AllowCall:   true,
					},
					{
						URI:         "io.xconn.deskconn.account.upgrade",
						MatchPolicy: "exact",
						AllowCall:   true,
					},
				},
			},
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	for _, rlm := range realms {
		err = router.AddRealm(rlm, &xconn.RealmConfig{
			Roles: []xconn.RealmRole{
				{
					Name: "desktop",
					Permissions: []xconn.Permission{{
						URI:           "io.xconn.deskconn.deskconnd.",
						MatchPolicy:   "prefix",
						AllowRegister: true,
					}},
				},
				{
					Name: "user",
					Permissions: []xconn.Permission{{
						URI:         "io.xconn.deskconn.deskconnd.",
						MatchPolicy: "prefix",
						AllowCall:   true,
					}},
				},
			},
		})
		if err != nil {
			log.Fatal(err)
		}
	}

	session, err := xconn.ConnectInMemory(router, realm)
	if err != nil {
		log.Fatal(err)
	}

	registerResp := session.Register(procedureAddRealm,
		func(ctx context.Context, invocation *xconn.Invocation) *xconn.InvocationResult {
			if len(invocation.Args()) != 1 {
				return xconn.NewInvocationError(ErrInvalidArgument, "must be called with single argument(realm)")
			}
			rlm, err := invocation.ArgString(0)
			if err != nil {
				return xconn.NewInvocationError(ErrInvalidArgument, err.Error())
			}
			err = router.AddRealm(rlm, &xconn.RealmConfig{
				Roles: []xconn.RealmRole{
					{
						Name: "user",
						Permissions: []xconn.Permission{
							{
								URI:         "io.xconn.deskconn.deskconnd.",
								MatchPolicy: "prefix",
								AllowCall:   true,
							},
						},
					},
					{
						Name: "desktop",
						Permissions: []xconn.Permission{
							{
								URI:           "io.xconn.deskconn.deskconnd.",
								MatchPolicy:   "prefix",
								AllowRegister: true,
							},
						},
					},
				},
			})
			if err != nil {
				return xconn.NewInvocationError("wamp.error.operation_failed", err)
			}
			return xconn.NewInvocationResult()
		}).Do()
	if registerResp.Err != nil {
		log.Fatal(registerResp.Err)
	}
	fmt.Printf("Registered procedure %s\n", procedureAddRealm)

	removeRealmResp := session.Register(procedureRemoveRealm,
		func(ctx context.Context, invocation *xconn.Invocation) *xconn.InvocationResult {
			if len(invocation.Args()) != 1 {
				return xconn.NewInvocationError(ErrInvalidArgument, "must be called with single argument(realm)")
			}
			userRealm, err := invocation.ArgString(0)
			if err != nil {
				return xconn.NewInvocationError(ErrInvalidArgument, err.Error())
			}
			router.RemoveRealm(userRealm)
			return xconn.NewInvocationResult()
		}).Do()
	if removeRealmResp.Err != nil {
		log.Fatal(removeRealmResp.Err)
	}
	fmt.Printf("Registered procedure %s\n", procedureRemoveRealm)

	if err := router.SetRealmAuthorizer(realm, &deskconnAuthorizer{session: session}); err != nil {
		log.Fatal(err)
	}

	server := xconn.NewServer(router, NewAuthenticator(session), &xconn.ServerConfig{})
	listener, err := server.ListenAndServeWebSocket(xconn.NetworkTCP, address)
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

type deskconnAuthorizer struct {
	session *xconn.Session
}

func (a *deskconnAuthorizer) Authorize(baseSession xconn.BaseSession, msg messages.Message) (bool, error) {
	const prefix = "io.xconn.deskconn.deskconnd."

	switch baseSession.AuthRole() {
	case "user":
		callMessage, ok := msg.(*messages.Call)
		if !ok {
			return false, nil
		}

		if strings.HasPrefix(callMessage.Procedure(), "io.xconn.deskconn.organization.") ||
			strings.HasPrefix(callMessage.Procedure(), "io.xconn.deskconn.account.") ||
			strings.HasPrefix(callMessage.Procedure(), "io.xconn.deskconn.desktop.") ||
			strings.HasPrefix(callMessage.Procedure(), "io.xconn.deskconn.device.") ||
			(callMessage.Procedure() == "io.xconn.deskconn.device.key.list") {
			return true, nil
		}

		if strings.HasPrefix(callMessage.Procedure(), prefix) {
			rest := strings.TrimPrefix(callMessage.Procedure(), prefix)
			desktopID := strings.SplitN(rest, ".", 2)[0]

			callResp := a.session.Call(procedureDesktopAccess).Args(baseSession.AuthID(), desktopID).Do()
			if callResp.Err == nil {
				return true, nil
			}
		}
	case "desktop":
		registerMessage, ok := msg.(*messages.Register)
		if !ok {
			return false, nil
		}

		if strings.HasPrefix(registerMessage.Procedure(), prefix) {
			rest := strings.TrimPrefix(registerMessage.Procedure(), prefix)
			desktopID := strings.SplitN(rest, ".", 2)[0]

			if desktopID == baseSession.AuthID() {
				return true, nil
			}
		}

	default:
		return false, nil
	}

	return false, nil
}
