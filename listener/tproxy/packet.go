package tproxy

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/common/pool"
	"github.com/metacubex/mihomo/common/xsync"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

type packet struct {
	pc        net.PacketConn
	lAddr     netip.AddrPort
	buf       []byte
	tunnel    C.Tunnel
	additions []inbound.Addition
}

func (c *packet) Data() []byte {
	return c.buf
}

// WriteBack opens a new socket binding `addr` to write UDP packet back
func (c *packet) WriteBack(b []byte, addr net.Addr) (n int, err error) {
	rAddr := addr.(*net.UDPAddr).AddrPort() // tunnel's handleUDPToLocal will ensure addr is *net.UDPAddr
	tc, err := createOrGetLocalConn(rAddr, c.lAddr, c.tunnel, c.additions...)
	if err != nil {
		return
	}
	n, err = tc.Write(b)
	return
}

// LocalAddr returns the source IP/Port of UDP Packet
func (c *packet) LocalAddr() net.Addr {
	return net.UDPAddrFromAddrPort(c.lAddr)
}

func (c *packet) Drop() {
	_ = pool.Put(c.buf)
	c.buf = nil
}

func (c *packet) InAddr() net.Addr {
	return c.pc.LocalAddr()
}

// this function listen at rAddr and write to lAddr
// for here, rAddr is the ip/port client want to access
// lAddr is the ip/port client opened
func createOrGetLocalConn(rAddr, lAddr netip.AddrPort, tunnel C.Tunnel, additions ...inbound.Addition) (*net.UDPConn, error) {
	remote := rAddr.String()
	local := lAddr.String()
	natTable := tunnel.NatTable()
	localConn := natTable.GetForLocalConn(local, remote)
	// localConn not exist
	if localConn == nil {
		cond, loaded := natTable.GetOrCreateLockForLocalConn(local, remote)
		if loaded {
			cond.L.Lock()
			cond.Wait()
			// we should get localConn here
			localConn = natTable.GetForLocalConn(local, remote)
			if localConn == nil {
				return nil, fmt.Errorf("localConn is nil, nat entry not exist")
			}
			cond.L.Unlock()
		} else {
			if cond == nil {
				return nil, fmt.Errorf("cond is nil, nat entry not exist")
			}
			defer func() {
				natTable.DeleteLockForLocalConn(local, remote)
				cond.Broadcast()
			}()
			conn, err := listenLocalConn(rAddr, lAddr, tunnel, additions...)
			if err != nil {
				log.Errorln("listenLocalConn failed with error: %s, packet loss (rAddr[%T]=%s lAddr[%T]=%s)", err.Error(), rAddr, remote, lAddr, local)
				// The bind failed because a previous socket for this exact
				// (lAddr, rAddr) pair still exists somewhere: either as an
				// orphaned fd whose NAT entry was already timed out, or as a
				// tracked conn that lost its table entry. Deleting only the
				// mapping cannot free the port — the kernel keeps honoring
				// the old fd's bind. Close the phantom via the process-wide
				// registry, evict any stale mapping, then retry ONCE so the
				// triggering packet is not lost.
				natTable.DeleteForLocalConn(local, remote)
				closePhantomLocalConn(lAddr, rAddr)
				conn, err = listenLocalConn(rAddr, lAddr, tunnel, additions...)
				if err != nil {
					return nil, err
				}
			}
			if !natTable.AddForLocalConn(local, remote, conn) {
				// Entry vanished between listen and add — close immediately,
				// otherwise this bound socket becomes an untracked orphan that
				// pins the port forever (the next createOrGetLocalConn for the
				// same pair would hit EADDRINUSE against it).
				conn.Close()
			}
			localConn = conn
		}
	}
	return localConn, nil
}

// this function listen at rAddr
// and send what received to program itself, then send to real remote
func listenLocalConn(rAddr, lAddr netip.AddrPort, tunnel C.Tunnel, additions ...inbound.Addition) (*net.UDPConn, error) {
	lc, err := dialUDP("udp", rAddr, lAddr)
	if err != nil {
		return nil, err
	}
	trackLocalConn(lAddr, rAddr, lc)
	go func() {
		log.Debugln("TProxy listenLocalConn rAddr=%s lAddr=%s", rAddr, lAddr)
		for {
			buf := pool.Get(pool.UDPBufferSize)
			br, err := lc.Read(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					log.Debugln("TProxy local conn listener exit.. rAddr=%s lAddr=%s", rAddr, lAddr)
					pool.Put(buf)
					return
				}
			}
			// since following localPackets are pass through this socket which listen rAddr
			// I choose current listener as packet's packet conn
			handlePacketConn(lc, tunnel, buf[:br], lAddr, rAddr, additions...)
		}
	}()
	return lc, nil
}

// localConnRegistry tracks every transparent reverse socket created by
// listenLocalConn for the lifetime of the process, keyed by (lAddr, rAddr).
//
// Why this exists: the NAT table (tunnel.NatTable) evicts its entries on a
// udpTimeout timer, but eviction does NOT close the sockets stored in
// LocalUDPConnMap — closeAllLocalCoon only runs when the parent UDP session
// (handleUDPToLocal) ends. If the session outlives the NAT entry, or the
// entry is dropped while a bind retry is in flight, a socket can end up
// referenced by nothing: a live fd that still pins its kernel bind, invisible
// to every future createOrGetLocalConn lookup. Any later bind for the same
// (lAddr, rAddr) pair then fails with EADDRINUSE forever ("address already
// in use, packet loss") — the observed Tailscale :41641 outage. The registry
// gives us a way to find and Close such phantoms.
var localConnRegistry = xsync.Map[string, *net.UDPConn]{}

func localConnKey(lAddr, rAddr netip.AddrPort) string {
	return lAddr.String() + "|" + rAddr.String()
}

func trackLocalConn(lAddr, rAddr netip.AddrPort, lc *net.UDPConn) {
	localConnRegistry.Store(localConnKey(lAddr, rAddr), lc)
}

// closePhantomLocalConn closes any still-open socket previously created for
// this (lAddr, rAddr) pair and removes it from the registry. Safe to call
// when no phantom exists.
func closePhantomLocalConn(lAddr, rAddr netip.AddrPort) {
	key := localConnKey(lAddr, rAddr)
	if old, ok := localConnRegistry.Load(key); ok {
		_ = old.Close()
		localConnRegistry.Delete(key)
	}
}
