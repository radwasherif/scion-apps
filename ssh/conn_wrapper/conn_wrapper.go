package conn_wrapper



import (
	"context"
	"fmt"
	"github.com/netsec-ethz/scion-apps/ssh/appconf"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/spath/spathmeta"
	"net"
	"time"
)

const (
	ErrNoPath     = "path not found"
	ErrInitPath   = "raw forwarding path offsets could not be initialized"
	ErrBadOverlay = "unable to extract next hop from sciond path entry"
)
var _ net.PacketConn = (*ConnWrapper)(nil)
var _ net.Conn = (*ConnWrapper) (nil)
var _ snet.Conn = (*ConnWrapper) (nil)

type ConnWrapper struct {
	conn *snet.SCIONConn
	conf *appconf.AppConf
	pathMap spathmeta.AppPathSet
	pathKeys []spathmeta.PathKey
	nextKeyIndex int
}

func NewConnWrapper (c snet.Conn, conf *appconf.AppConf) *ConnWrapper{
	cw := ConnWrapper{conn: c.(*snet.SCIONConn), conf: conf}
	return &cw
}


func (c *ConnWrapper) Read(b []byte) (int, error) {
	return c.conn.Read(b)
}

func (c *ConnWrapper) ReadFrom(b []byte) (int, net.Addr, error) {
	return c.conn.ReadFrom(b)
}

func (c *ConnWrapper) ReadFromSCION(b []byte) (int, *snet.Addr, error) {
	return c.conn.ReadFromSCION(b)
}

func (c *ConnWrapper) Write(b []byte) (int, error) {
	return c.conn.Write(b)
}

func (c *ConnWrapper) WriteTo(b []byte, raddr net.Addr) (int, error) {
	sraddr, ok := raddr.(*snet.Addr)
	if !ok {
		return 0, common.NewBasicError("Unable to write to non-SCION address", nil, "addr", raddr)
	}

	return c.WriteToSCION(b, sraddr)
}

func (c *ConnWrapper) WriteToSCION(b []byte, address *snet.Addr) (int, error) {
	resolver := snet.DefNetwork.PathResolver()
	localIA := c.conn.LocalSnetAddr().IA
	remoteAddr := address.Copy()
	var appPath *spathmeta.AppPath
	var nextHop *overlay.OverlayAddr
	var path *spath.Path
	var err error
	log.Debug(fmt.Sprintf("CONF TEST VAL = %d", c.conf.Test))
	c.conf.Test += 1
	//resolver called with empty context and not timeout enforcement for now
	if c.conf.PathSelection().IsStatic() {
		log.Debug("STATIC PATH ===> ")
		staticNextHop , staticPath := c.conf.GetStaticPath()
		//if we're using a static path, query resolver only if this is the first call to write
		if  staticNextHop == nil && staticPath == nil {
			log.Debug("Querying Resolver - First Time")
			pathSet := resolver.QueryFilter(context.Background(), localIA, address.IA, c.conf.Policy())
			appPath = pathSet.GetAppPath("")
			nextHop, path, err = c.getSCIONPath(appPath)
			if err != nil {
				return 0, common.NewBasicError("Writer: error creating SCION path", err)
			}
			c.conf.SetStaticPath(nextHop, path)
			_, pathTest := c.conf.GetStaticPath()
			log.Debug(fmt.Sprintf("Retrieved Path Test: %t", pathTest.Raw.String() == path.Raw.String()))
		} else if staticNextHop != nil && staticPath != nil {
			nextHop, path = staticNextHop, staticPath
			log.Debug("FOUND OLD PATH: %v", staticPath)
		} else {
			return 0, common.NewBasicError("Next hop and path must both be either defined or undefined", nil)
		}

	} else if c.conf.PathSelection().IsArbitrary() {
		log.Debug("ARBITRARY PATH ===> ")
		pathSet := resolver.Query(context.Background(), localIA, address.IA, sciond.PathReqFlags{})
		appPath = pathSet.GetAppPath("")
		nextHop, path, err = c.getSCIONPath(appPath)
		if err != nil {
			return 0, common.NewBasicError("Writer: error creating SCION path", err)
		}
	} else if c.conf.PathSelection().IsRoundRobin() {
		log.Debug("ROUND ROBIN ===> ")
		if len(c.pathKeys) == 0 {
			c.pathMap = resolver.QueryFilter(context.Background(), localIA, address.IA, c.conf.Policy())
			for k, _ := range c.pathMap {
				c.pathKeys = append(c.pathKeys, k)
			}
		}

		//sanity checks
		if c.nextKeyIndex >= len(c.pathKeys) || len(c.pathKeys) != len(c.pathMap) {
			return 0, common.NewBasicError("Writer: inconsistent path keys array/map length", err)
		}

		appPath, ok := c.pathMap[c.pathKeys[c.nextKeyIndex]]
		log.Debug(fmt.Sprintf("SELECTED PATH # %d: %s\n", c.nextKeyIndex, appPath.Entry.Path.String()))
		if !ok {
			return 0, common.NewBasicError("Writer: Path key not found", nil )
		}
		c.nextKeyIndex = (c.nextKeyIndex + 1) % len(c.pathKeys)

		nextHop, path, err = c.getSCIONPath(appPath)
		if err != nil {
			return 0, common.NewBasicError("Writer: error creating SCION path", err)
		}

	} else {
		return 0, common.NewBasicError("Path selection option not yet supported" , nil)
	}
	remoteAddr.NextHop, remoteAddr.Path = nextHop, path
	return c.conn.WriteToSCION(b, remoteAddr)
}

//func (c *ConnWrapper) write(b []byte, address *snet.Addr) (int, error) {
//	resolver := snet.DefNetwork.PathResolver()
//	localIA := c.conn.LocalAddr()
//	remoteAddr := address.Copy()
//	var nextHop *overlay.OverlayAddr
//	var path *spath.Path
//	var err error
//	log.Debug(fmt.Sprintf("CONF TEST VAL = %d", c.conf.Test))
//	c.conf.Test += 1
//	//resolver called with empty context and not timeout enforcement for now
//	if c.conf.PathSelection().IsStatic() {
//		log.Debug("STATIC PATH ===> ")
//		staticNextHop , staticPath := c.conf.GetStaticPath()
//		//if we're using a static path, query resolver only if this is the first call to write
//		if  staticNextHop == nil && staticPath == nil {
//			log.Debug("Querying Resolver - First Time")
//			pathSet := resolver.QueryFilter(context.Background(), localIA, address.IA, c.conf.Policy())
//			if err != nil {
//				return 0, common.NewBasicError("Writer: Error resolving address: ", err)
//			}
//			c.conf.SetStaticPath(nextHop, path)
//			_, pathTest := c.conf.GetStaticPath()
//			log.Debug(fmt.Sprintf("Retrieved Path Test: %t", pathTest.Raw.String() == path.Raw.String()))
//		} else if staticNextHop != nil && staticPath != nil {
//			nextHop, path = staticNextHop, staticPath
//			log.Debug("FOUND OLD PATH: %v", staticPath)
//		} else {
//			return 0, common.NewBasicError("Next hop and path must both be either defined or undefined", nil)
//		}
//
//	} else if c.conf.PathSelection().IsArbitrary() {
//		log.Debug("ARBITRARY PATH ===> ")
//		nextHop, path, err = resolver.GetFilter(context.Background(), localIA, address.IA, c.conf.Policy())
//		if err != nil {
//			return 0, common.NewBasicError("Writer: Error resolving address: ", err)
//		}
//	} else if c.conf.PathSelection().IsRoundRobin() {
//		log.Debug("ROUND ROBIN ===> ")
//		if len(c.pathKeys) == 0 {
//			c.pathMap, err = resolver.GetSetFilter(context.Background(), localIA, address.IA, c.conf.Policy())
//			if err != nil {
//				return 0, common.NewBasicError("Writer: Error resolving address: ", err)
//			}
//			for k, _ := range c.pathMap {
//				c.pathKeys = append(c.pathKeys, k)
//			}
//		}
//
//		//sanity checks
//		if c.nextKeyIndex >= len(c.pathKeys) || len(c.pathKeys) != len(c.pathMap) {
//			return 0, common.NewBasicError("Writer: inconsistent path keys array/map length", err)
//		}
//
//		sciondPath, ok := c.pathMap[c.pathKeys[c.nextKeyIndex]]
//		log.Debug(fmt.Sprintf("SELECTED PATH # %d: %s\n", c.nextKeyIndex, sciondPath.Entry.Path.String()))
//		if !ok {
//			return 0, common.NewBasicError("Writer: Path key not found", nil )
//		}
//		c.nextKeyIndex = (c.nextKeyIndex + 1) % len(c.pathKeys)
//
//		path = &spath.Path{Raw: sciondPath.Entry.Path.FwdPath}
//		if err := path.InitOffsets(); err != nil {
//			return 0, common.NewBasicError(ErrInitPath, nil)
//		}
//		nextHop, err = sciondPath.Entry.HostInfo.Overlay()
//		if err != nil {
//			return 0,  common.NewBasicError(snet.ErrBadOverlay, nil)
//		}
//
//	} else {
//		return 0, common.NewBasicError("Path selection option not yet supported" , nil)
//	}
//	remoteAddr.NextHop, remoteAddr.Path = nextHop, path
//	return c.conn.writeWithLock(b, remoteAddr)
//
//}

func (c *ConnWrapper) Close() error {
	return c.conn.Close()
}

func (c *ConnWrapper) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *ConnWrapper) BindAddr() net.Addr {
	return c.conn.BindAddr()
}
func (c *ConnWrapper) SVC() addr.HostSVC {
	return c.conn.SVC()
}
func (c *ConnWrapper) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}
func (c *ConnWrapper) SetDeadline(deadline time.Time) error {
	return c.conn.SetDeadline(deadline)
}
func  (c *ConnWrapper) SetReadDeadline(deadline time.Time) error {
	return c.conn.SetReadDeadline(deadline)
}

func (c *ConnWrapper) SetWriteDeadline(deadline time.Time) error {
	return c.conn.SetWriteDeadline(deadline)
}

func (c *ConnWrapper) getSCIONPath(appPath *spathmeta.AppPath) (*overlay.OverlayAddr, *spath.Path, error) {
	if appPath == nil {
		return nil, nil, common.NewBasicError(ErrNoPath, nil)
	}
	path := &spath.Path{Raw: appPath.Entry.Path.FwdPath}
	if err := path.InitOffsets(); err != nil {
		return nil, nil, common.NewBasicError(ErrInitPath, nil)
	}
	overlayAddr, err := appPath.Entry.HostInfo.Overlay()
	if err != nil {
		return nil, nil, common.NewBasicError(ErrBadOverlay, nil)
	}
	return overlayAddr, path, nil

}





