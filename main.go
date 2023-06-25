package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// parts copied from Tailscale/Wireguard

const (
	// TODO: upstream to x/sys/unix
	socketOptionLevelUDP   = 17
	socketOptionUDPSegment = 103
	socketOptionUDPGRO     = 104
)

func supportsUDPOffload(conn *net.UDPConn) (txOffload, rxOffload bool) {
	rc, err := conn.SyscallConn()
	if err != nil {
		return
	}
	err = rc.Control(func(fd uintptr) {
		_, errSyscall := unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, socketOptionUDPSegment)
		if errSyscall != nil {
			return
		}
		txOffload = true
		opt, errSyscall := unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, socketOptionUDPGRO)
		if errSyscall != nil {
			return
		}
		rxOffload = opt == 1
	})
	if err != nil {
		return false, false
	}
	return txOffload, rxOffload
}

// controlFn is the callback function signature from net.ListenConfig.Control.
// It is used to apply platform specific configuration to the socket prior to
// bind.
type controlFn func(network, address string, c syscall.RawConn) error

// controlFns is a list of functions that are called from the listen config
// that can apply socket options.
var controlFns = []controlFn{}

// listenConfig returns a net.ListenConfig that applies the controlFns to the
// socket prior to bind. This is used to apply socket buffer sizing and packet
// information OOB configuration for sticky sockets.
func listenConfig() *net.ListenConfig {
	return &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			for _, fn := range controlFns {
				if err := fn(network, address, c); err != nil {
					return err
				}
			}
			return nil
		},
	}
}
func listenNet(network string, port int) (*net.UDPConn, int, error) {
	conn, err := listenConfig().ListenPacket(context.Background(), network, ":"+strconv.Itoa(port))
	if err != nil {
		return nil, 0, err
	}

	// Retrieve port.
	laddr := conn.LocalAddr()
	uaddr, err := net.ResolveUDPAddr(
		laddr.Network(),
		laddr.String(),
	)
	if err != nil {
		return nil, 0, err
	}
	return conn.(*net.UDPConn), uaddr.Port, nil
}

const (
	sizeOfGSOData = 2
)

func setGSOSize(control *[]byte, gsoSize uint16) {
	existingLen := len(*control)
	avail := cap(*control) - existingLen
	space := unix.CmsgSpace(sizeOfGSOData)
	if avail < space {
		return
	}
	*control = (*control)[:cap(*control)]
	gsoControl := (*control)[existingLen:]
	hdr := (*unix.Cmsghdr)(unsafe.Pointer(&(gsoControl)[0]))
	hdr.Level = socketOptionLevelUDP
	hdr.Type = socketOptionUDPSegment
	hdr.SetLen(unix.CmsgLen(sizeOfGSOData))
	copy((gsoControl)[unix.SizeofCmsghdr:], unsafe.Slice((*byte)(unsafe.Pointer(&gsoSize)), sizeOfGSOData))
	*control = (*control)[:existingLen+space]
}

func main() {

	if runtime.GOOS != "linux" {
		log.Fatal("only for Linux!")
	}

	v4conn, port4, err := listenNet("udp4", 0)
	if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
		log.Fatal(err)
	}
	gsoV4, groV4 := supportsUDPOffload(v4conn)

	v6conn, port6, err := listenNet("udp6", 0)
	if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
		log.Fatal(err)
	}
	gsoV6, groV6 := supportsUDPOffload(v6conn)

	fmt.Println("Kernel detection:")
	fmt.Printf("  IPv4 GSO: %t, GRO: %t\n", gsoV4, groV4)
	fmt.Printf("  IPv6 GSO: %t, GRO: %t\n", gsoV6, groV6)
	fmt.Println("Write dectection:")
	testWrite(v4conn, net.IPv4(127, 0, 0, 1), port4, gsoV4, nil)
	testWrite(v6conn, net.IPv6loopback, port6, gsoV6, nil)
	fmt.Println("Write with batch:")
	testWrite(v4conn, net.IPv4(127, 0, 0, 1), port4, gsoV4, ipv4.NewPacketConn(v4conn))
	testWrite(v6conn, net.IPv6loopback, port6, gsoV6, ipv6.NewPacketConn(v6conn))

}
func errShouldDisableUDPGSO(err error) bool {
	var serr *os.SyscallError
	if errors.As(err, &serr) {
		// EIO is returned by udp_send_skb() if the device driver does not have
		// tx checksumming enabled, which is a hard requirement of UDP_SEGMENT.
		// See:
		// https://git.kernel.org/pub/scm/docs/man-pages/man-pages.git/tree/man7/udp.7?id=806eabd74910447f21005160e90957bde4db0183#n228
		// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/udp.c?h=v6.2&id=c9c3395d5e3dcc6daee66c6908354d47bf98cb0c#n942
		return serr.Err == unix.EIO
	}
	return false
}

type batchWriter interface {
	WriteBatch([]ipv6.Message, int) (int, error)
}

func testWrite(conn *net.UDPConn, addr net.IP, port int, gso bool, br batchWriter) {
	buff := make([]byte, 2000)
	buffs := make([][]byte, 1)
	buffs[0] = buff
	// remote = self
	remote := &net.UDPAddr{
		IP:   addr,
		Port: port,
	}
	oob := make([]byte, 0, unix.CmsgSpace(sizeOfGSOData))
	if gso {
		setGSOSize(&oob, 2000)
	}
	msg := []ipv6.Message{{
		Buffers: buffs,
		OOB:     oob,
		Addr:    remote,
	}, {
		Buffers: buffs,
		OOB:     oob,
		Addr:    remote,
	}}
	var n, noob int
	var err error

	if br != nil {
		nn, err2 := br.WriteBatch(msg, 0)
		if nn != len(msg) {
			fmt.Println("unexpected number of msg sent")
		}
		noob = msg[0].NN
		n = msg[0].N
		err = err2
	} else {
		n, noob, err = conn.WriteMsgUDP(buff, oob, remote)
	}
	if gso && err != nil && errShouldDisableUDPGSO(err) {
		fmt.Println("  gso issue detected")
	}
	fmt.Printf("  n,nb,err = %d,%d,%s\n", n, noob, err)

}
