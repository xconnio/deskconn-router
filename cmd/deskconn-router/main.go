package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/joho/godotenv"
	log "github.com/sirupsen/logrus"

	"github.com/xconnio/wampproto-go/auth"
	"github.com/xconnio/xconn-go"
)

const (
	realm = "io.xconn.deskconn"

	procedureCRAVerify        = "io.xconn.deskconn.account.cra.verify"
	procedureCryptosignVerify = "io.xconn.deskconn.account.cryptosign.verify"
	procedureAddRealm         = "io.xconn.deskconn.realm.add"
	procedureRemoveRealm      = "io.xconn.deskconn.realm.remove"
	procedureCoturnCreate     = "io.xconn.deskconn.coturn.credentials.create"

	accountServiceAuthRole  = "xconnio:deskconn:cloud:service:account"
	accountServiceAuthID    = "deskconn-account-service"
	accountServicePublicKey = "c98fb454dfda50be26b74818d3c20caf6810970b9de4a01fe5cd6282603400f1"

	anonymousAuthRole = "anonymous"
	webAppAuthID      = "deskconn-web-app"

	ciAuthRole  = "xconnio:deskconn:ci"
	ciAuthID    = "deskconn-ci"
	ciPublicKey = "af12b0d04d8e2e468e31115d6c7ca665ff39d7dd78455ae2e3f73f61962e16bb"

	ErrInvalidArgument = "wamp.error.invalid_argument"
	ErrOperationFailed = "wamp.error.operation_failed"

	procedureWebRTCOffer     = "io.xconn.webrtc.offer"
	topicOffererOnCandidate  = "io.xconn.webrtc.offerer.on_candidate"
	topicAnswererOnCandidate = "io.xconn.webrtc.answerer.on_candidate"

	desktopAuthRoleFormat = "xconnio:deskconn:desktop:%s"
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
	return []auth.Method{auth.MethodCRA, auth.MethodCryptoSign, auth.MethodAnonymous}
}

func (a *Authenticator) Authenticate(request auth.Request) (auth.Response, error) {
	switch request.AuthMethod() {
	case auth.MethodCRA:
		callResp := a.session.Call(procedureCRAVerify).Args(request.AuthID(), request.Realm()).Do()
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

		if cryptosignRequest.PublicKey() == ciPublicKey && cryptosignRequest.AuthID() == ciAuthID {
			return auth.NewResponse(cryptosignRequest.AuthID(), ciAuthRole, 0)
		}

		callResp := a.session.Call(procedureCryptosignVerify).Args(request.AuthID(), cryptosignRequest.PublicKey(),
			request.Realm()).Do()
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

	case auth.Anonymous:
		if request.AuthID() == webAppAuthID && request.Realm() == realm {
			return auth.NewResponse(request.AuthID(), anonymousAuthRole, 0)
		}

		return nil, fmt.Errorf("invalid authid or realm")

	default:
		return nil, fmt.Errorf("unsupported authentication method: %v", request.AuthMethod())
	}
}

func main() {
	_ = godotenv.Load()

	databaseURL, ok := os.LookupEnv("DESKCONN_POSTGRES_URL")
	if !ok || databaseURL == "" {
		log.Fatalln("DESKCONN_POSTGRES_URL not set")
	}
	address, ok := os.LookupEnv("DESKCONN_ROUTER_ADDRESS")
	if !ok || address == "" {
		address = "0.0.0.0:8080"
	}
	db, err := openDB(databaseURL)
	if err != nil {
		log.Fatalf("Error opening database: %v", err)
	}

	desktops, err := getDesktops(db)
	if err != nil {
		log.Fatalf("Error getting desktops from db: %v", err)
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
					{
						URI:          "io.xconn.deskconn.desktop.*.key.add",
						MatchPolicy:  "wildcard",
						AllowPublish: true,
					},
					{
						URI:          "io.xconn.deskconn.desktop.*.key.remove",
						MatchPolicy:  "wildcard",
						AllowPublish: true,
					},
					{
						URI:          "io.xconn.deskconn.desktop.*.detach",
						MatchPolicy:  "wildcard",
						AllowPublish: true,
					},
					{
						URI:         "wamp.session.kill_by_authid",
						MatchPolicy: "exact",
						AllowCall:   true,
					},
				},
			},
			{
				Name: anonymousAuthRole,
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
				},
			},
			{
				Name: ciAuthRole,
				Permissions: []xconn.Permission{
					{
						URI:         "io.xconn.deskconn.app.update",
						MatchPolicy: "exact",
						AllowCall:   true,
					},
				},
			},
			{
				Name: "user",
				Permissions: []xconn.Permission{
					{
						URI:         "io.xconn.deskconn.organization.",
						MatchPolicy: "prefix",
						AllowCall:   true,
					},
					{
						URI:         "io.xconn.deskconn.account.get",
						MatchPolicy: "exact",
						AllowCall:   true,
					},
					{
						URI:         "io.xconn.deskconn.account.principal.",
						MatchPolicy: "prefix",
						AllowCall:   true,
					},
					{
						URI:         "io.xconn.deskconn.account.update",
						MatchPolicy: "exact",
						AllowCall:   true,
					},
					{
						URI:         "io.xconn.deskconn.account.delete",
						MatchPolicy: "exact",
						AllowCall:   true,
					},
					{
						URI:         "io.xconn.deskconn.desktop.",
						MatchPolicy: "prefix",
						AllowCall:   true,
					},
					{
						URI:         "io.xconn.deskconn.device.",
						MatchPolicy: "prefix",
						AllowCall:   true,
					},
					{
						URI:         "io.xconn.deskconn.app.",
						MatchPolicy: "prefix",
						AllowCall:   true,
					},
					{
						URI:         procedureCoturnCreate,
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

	if err := router.EnableMetaAPI(realm); err != nil {
		log.Fatal(err)
	}

	for _, desktop := range desktops {
		if err := addRealm(router, desktop.Realm, desktop.AuthID); err != nil {
			log.Fatal(err)
		}
	}

	session, err := xconn.ConnectInMemory(router, realm)
	if err != nil {
		log.Fatal(err)
	}

	registerResp := session.Register(procedureAddRealm,
		func(ctx context.Context, invocation *xconn.Invocation) *xconn.InvocationResult {
			if len(invocation.Args()) != 2 {
				return xconn.NewInvocationError(ErrInvalidArgument, "must be called with two arguments(realm and authid)")
			}
			rlm, err := invocation.ArgString(0)
			if err != nil {
				return xconn.NewInvocationError(ErrInvalidArgument, err)
			}
			authid, err := invocation.ArgString(1)
			if err != nil {
				return xconn.NewInvocationError(ErrInvalidArgument, err)
			}
			if err := addRealm(router, rlm, authid); err != nil {
				return xconn.NewInvocationError(ErrOperationFailed, err)
			}
			return xconn.NewInvocationResult()
		}).Do()
	if registerResp.Err != nil {
		log.Fatal(registerResp.Err)
	}
	fmt.Printf("Registered procedure %s\n", procedureAddRealm)

	removeRealmResp := session.Register(procedureRemoveRealm,
		func(ctx context.Context, invocation *xconn.Invocation) *xconn.InvocationResult {
			if len(invocation.Args()) != 2 {
				return xconn.NewInvocationError(ErrInvalidArgument, "must be called with two argument(realm and authid)")
			}
			userRealm, err := invocation.ArgString(0)
			if err != nil {
				return xconn.NewInvocationError(ErrInvalidArgument, err.Error())
			}
			router.RemoveRealm(userRealm)
			authid, err := invocation.ArgString(1)
			if err != nil {
				return xconn.NewInvocationError(ErrInvalidArgument, err)
			}
			if err := router.RemoveRealmRole(realm, fmt.Sprintf(desktopAuthRoleFormat, authid)); err != nil {
				return xconn.NewInvocationError(ErrOperationFailed, err)
			}
			return xconn.NewInvocationResult()
		}).Do()
	if removeRealmResp.Err != nil {
		log.Fatal(removeRealmResp.Err)
	}
	fmt.Printf("Registered procedure %s\n", procedureRemoveRealm)

	server := xconn.NewServer(router, NewAuthenticator(session), &xconn.ServerConfig{
		KeepAliveInterval: 30 * time.Second,
		KeepAliveTimeout:  10 * time.Second,
	})
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

func addRealm(router *xconn.Router, rlm string, authid string) error {
	err := router.AddRealm(rlm, &xconn.RealmConfig{
		AutoDiscloseCaller: true,
		Roles: []xconn.RealmRole{
			{
				Name: fmt.Sprintf(desktopAuthRoleFormat, authid),
				Permissions: []xconn.Permission{
					{
						URI:           "io.xconn.deskconn.deskconnd.",
						MatchPolicy:   "prefix",
						AllowRegister: true,
					},
					{
						URI:           procedureWebRTCOffer,
						MatchPolicy:   "exact",
						AllowRegister: true,
					},
					{
						URI:            topicAnswererOnCandidate,
						MatchPolicy:    "exact",
						AllowSubscribe: true,
					},
					{
						URI:          topicOffererOnCandidate,
						MatchPolicy:  "exact",
						AllowPublish: true,
					},
					{
						URI:            "wamp.session.on_leave",
						MatchPolicy:    "exact",
						AllowSubscribe: true,
					},
				},
			},
			{
				Name: "user",
				Permissions: []xconn.Permission{
					{
						URI:         "io.xconn.deskconn.deskconnd.",
						MatchPolicy: "prefix",
						AllowCall:   true,
					},
					{
						URI:         procedureWebRTCOffer,
						MatchPolicy: "exact",
						AllowCall:   true,
					},
					{
						URI:          topicAnswererOnCandidate,
						MatchPolicy:  "exact",
						AllowPublish: true,
					},
					{
						URI:            topicOffererOnCandidate,
						MatchPolicy:    "exact",
						AllowSubscribe: true,
					},
				},
			},
		},
	})
	if err != nil {
		return err
	}

	err = router.AddRealmRole(realm, xconn.RealmRole{
		Name: fmt.Sprintf(desktopAuthRoleFormat, authid),
		Permissions: []xconn.Permission{
			{
				URI:         "io.xconn.deskconn.desktop.access.key.list",
				MatchPolicy: "exact",
				AllowCall:   true,
			},
			{
				URI:            fmt.Sprintf("io.xconn.deskconn.desktop.%s.key.add", authid),
				MatchPolicy:    "exact",
				AllowSubscribe: true,
			},
			{
				URI:            fmt.Sprintf("io.xconn.deskconn.desktop.%s.key.remove", authid),
				MatchPolicy:    "exact",
				AllowSubscribe: true,
			},
			{
				URI:            fmt.Sprintf("io.xconn.deskconn.desktop.%s.detach", authid),
				MatchPolicy:    "exact",
				AllowSubscribe: true,
			},
			{
				URI:         procedureCoturnCreate,
				MatchPolicy: "exact",
				AllowCall:   true,
			},
		},
	})
	return err
}
