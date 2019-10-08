package scionutils

import (
	"fmt"
	"github.com/scionproto/scion/go/lib/appconf"
	"regexp"

	"github.com/lucas-clemente/quic-go"

	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/squic"

	"github.com/netsec-ethz/scion-apps/lib/scionutil"
	"github.com/netsec-ethz/scion-apps/ssh/quicconn"
)

var addressPortSplitRegex, _ = regexp.Compile(`(.*,\[.*\]):(\d+)`)

// SplitHostPort splits a host:port string into host and port variables
func SplitHostPort(hostport string) (host, port string, err error) {
	split := addressPortSplitRegex.FindAllStringSubmatch(hostport, -1)
	if len(split) == 1 {
		return split[0][1], split[0][2], nil
	}
	// Shouldn't happen
	return "", "", fmt.Errorf("Invalid SCION address provided")
}

// DialSCION dials a SCION host and opens a new QUIC stream
func DialSCION(localAddress string, remoteAddress string, appConf *appconf.AppConf) (*quicconn.QuicConn, error) {
	if localAddress == "" {
		localhost, err := scionutil.GetLocalhostString()
		if err != nil {
			return nil, err
		}

		localAddress = fmt.Sprintf("%v:%v", localhost, 0)
	}
	localCCAddr, err := snet.AddrFromString(localAddress)
	if err != nil {
		return nil, err
	}

	remoteCCAddr, err := snet.AddrFromString(remoteAddress)
	if err != nil {
		return nil, err
	}

	quicConfig := &quic.Config{
		KeepAlive: true,
	}

	sess, err := squic.DialSCIONWithConf(nil, localCCAddr, remoteCCAddr, quicConfig, appConf)
	if err != nil {
		return nil, err
	}

	stream, err := sess.OpenStreamSync()
	if err != nil {
		return nil, err
	}

	return &quicconn.QuicConn{Session: sess, Stream: stream}, nil
}

// ListenSCION listens on the given port with the QUIC protocol, and returns a listener
func ListenSCION(port uint16) (quic.Listener, error) {
	localhost, err := scionutil.GetLocalhostString()
	if err != nil {
		return nil, err
	}

	localAddress := fmt.Sprintf("%v:%v", localhost, port)

	localCCAddr, err := snet.AddrFromString(localAddress)
	if err != nil {
		return nil, err
	}

	listener, err := squic.ListenSCION(nil, localCCAddr, nil)
	if err != nil {
		return nil, err
	}

	return listener, nil
}

//func GetPredicateEval() (bool, error){
//	return
//}
