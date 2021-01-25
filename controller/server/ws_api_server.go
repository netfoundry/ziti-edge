/*
	Copyright NetFoundry, Inc.

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/edge/controller/config"
	"github.com/openziti/edge/controller/env"
	"io"
	"log"
	"net/http"
	"time"
)

var upgrader = websocket.Upgrader{}

type wsapiServer struct {
	config                   *config.Config
	AppEnv                   *env.AppEnv
	httpServer               *http.Server
	tlsConfig                *tls.Config
	logWriter                *io.PipeWriter
	tlsConn                  *tls.Conn
	tlsConnHandshakeComplete bool
}

/**
 *	Accept incoming HTTP connection, and upgrade it to a websocket suitable for comms between ziti-sdk-js and Ziti Edge Router
 */
func (wsas *wsapiServer) handleWebsocket(w http.ResponseWriter, r *http.Request) {
	logger := pfxlog.Logger()
	logger.Info("WSAPI received request to open websocket from ", r.RemoteAddr)

	c, err := upgrader.Upgrade(w, r, nil) // upgrade from HTTP to binary socket

	if err != nil {
		logger.Error("websocket upgrade failed. Failure not recoverable.")
	} else {

		wsConnection := &WSConnection{
			ws:        c,
			AppEnv:    wsas.AppEnv,
			logger:    logger,
			rxbuf:     newSafeBuffer(logger),
			txbuf:     newSafeBuffer(logger),
			tlsrxbuf:  newSafeBuffer(logger),
			tlstxbuf:  newSafeBuffer(logger),
			done:      make(chan struct{}),
			config:    wsas.config,
			tlsConfig: wsas.tlsConfig,
		}

		err := wsConnection.tlsHandshake() // Do not proceed until the JS client can successfully complete the mTLS handshake
		if err == nil {
			go wsConnection.requestHandler()
		}
	}
}

func newWSApiServer(c *config.Config, ae *env.AppEnv, r http.Handler) *wsapiServer {
	logWriter := pfxlog.Logger().Writer()

	// Set up the HTTP -> Websocket upgrader options (once, before we start listening)
	upgrader.HandshakeTimeout = c.WSApi.HandshakeTimeout
	upgrader.ReadBufferSize = c.WSApi.ReadBufferSize
	upgrader.WriteBufferSize = c.WSApi.WriteBufferSize
	upgrader.EnableCompression = c.WSApi.EnableCompression
	upgrader.CheckOrigin = func(r *http.Request) bool { return true } // Allow all origins

	router := mux.NewRouter()

	wsas := &wsapiServer{
		config:    c,
		AppEnv:    ae,
		logWriter: logWriter,
		httpServer: &http.Server{
			Addr:         c.WSApi.Listener,
			WriteTimeout: time.Second * 10,
			ReadTimeout:  time.Second * 5,
			IdleTimeout:  time.Second * 5,
			Handler:      router,
			ErrorLog:     log.New(logWriter, "", 0),
		},
		tlsConfig: c.WSApi.Identity.ServerTLSConfig(),
	}

	router.HandleFunc("/ws", wsas.handleWebsocket).Methods("GET")

	return wsas
}

func (wsas *wsapiServer) Start() error {
	logger := pfxlog.Logger()
	logger.Info("starting WSAPI to listen and serve on: ", wsas.httpServer.Addr)
	logger.Debug("starting Edge Controller WSAPI")

	err := wsas.httpServer.ListenAndServe()
	if err != http.ErrServerClosed {
		return fmt.Errorf("error listening: %s", err)
	}

	return nil
}

func (wsas *wsapiServer) Shutdown(ctx context.Context) {
	_ = wsas.logWriter.Close()
	_ = wsas.httpServer.Shutdown(ctx)
}
