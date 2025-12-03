package main

import (
	"os"
	"os/signal"

	log "github.com/sirupsen/logrus"

	"github.com/xconnio/xconn-go"
)

func main() {
	router, err := xconn.NewRouter(xconn.DefaultRouterConfig())
	if err != nil {
		log.Fatal(err)
	}

	err = router.AddRealm("realm1", &xconn.RealmConfig{
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
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	server := xconn.NewServer(router, nil, &xconn.ServerConfig{})
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
