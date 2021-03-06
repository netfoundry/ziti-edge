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

package xgress_edge_transport

import (
	"fmt"
	"github.com/openziti/edge/router/xgress_common"
	"github.com/openziti/fabric/controller/xt"
	"github.com/openziti/fabric/router/xgress"
	"github.com/openziti/foundation/identity/identity"
	"github.com/openziti/foundation/transport"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/sirupsen/logrus"
)

type dialer struct {
	ctrl    xgress.CtrlChannel
	options *xgress.Options
}

func (txd *dialer) IsTerminatorValid(string, string) bool {
	return true
}

func newDialer(ctrl xgress.CtrlChannel, options *xgress.Options) (xgress.Dialer, error) {
	txd := &dialer{
		ctrl:    ctrl,
		options: options,
	}
	return txd, nil
}

func (txd *dialer) Dial(destination string, sessionId *identity.TokenId, address xgress.Address, bindHandler xgress.BindHandler) (xt.PeerData, error) {
	txDestination, err := transport.ParseAddress(destination)
	if err != nil {
		return nil, fmt.Errorf("cannot dial on invalid address [%s] (%s)", destination, err)
	}

	peer, err := txDestination.Dial("x/"+sessionId.Token, sessionId, txd.options.ConnectTimeout, nil)
	if err != nil {
		return nil, err
	}

	logrus.Infof("successful connection to %v from %v (s/%v)", destination, peer.Conn().LocalAddr(), sessionId.Token)

	xgConn := xgress_common.NewXgressConn(peer.Conn(), true)
	peerData := make(xt.PeerData, 1)
	if peerKey, ok := sessionId.Data[edge.PublicKeyHeader]; ok {
		if publicKey, err := xgConn.SetupServerCrypto(peerKey); err != nil {
			return nil, err
		} else {
			peerData[edge.PublicKeyHeader] = publicKey
		}
	}

	x := xgress.NewXgress(sessionId, address, xgConn, xgress.Terminator, txd.options)
	bindHandler.HandleXgressBind(x)
	x.Start()

	return peerData, nil
}
