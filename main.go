package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"strconv"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// parts copied from Tailscale/Wireguard

func supportsUDPOffload(conn *net.UDPConn) (txOffload, rxOffload bool) {
	rc, err := conn.SyscallConn()
	if err != nil {
		return
	}
	err = rc.Control(func(fd uintptr) {
		size, errSyscall := unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_SEGMENT)
		fmt.Println("gso size = ", size)
		if errSyscall != nil {
			return
		}
		txOffload = true
		// not sure that one is correct
		opt, errSyscall := unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO)
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

func listenNet(network string, port int) (*net.UDPConn, int, error) {
	lc := &net.ListenConfig{}
	conn, err := lc.ListenPacket(context.Background(), network, ":"+strconv.Itoa(port))
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
	hdr.Level = unix.IPPROTO_UDP
	hdr.Type = unix.UDP_SEGMENT
	hdr.SetLen(unix.CmsgLen(sizeOfGSOData))
	copy((gsoControl)[unix.SizeofCmsghdr:], unsafe.Slice((*byte)(unsafe.Pointer(&gsoSize)), sizeOfGSOData))
	*control = (*control)[:existingLen+space]
}

var optV4remote = flag.String("r4", "127.0.0.1:0", "remote v4 addr")
var optV6remote = flag.String("r6", "["+net.IPv6loopback.String()+"]:0", "remote v6 addr")

func parseRemote(remote string) (net.IP, int) {
	host, port, err := net.SplitHostPort(remote)
	if err != nil {
		log.Fatalf("bad remote %v", remote)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		log.Fatalf("bad remote port: %v", remote)
	}
	return net.ParseIP(host), p
}

func main() {

	if runtime.GOOS != "linux" {
		log.Fatal("only for Linux!")
	}

	flag.Parse()

	remote4, port4 := parseRemote(*optV4remote)
	fmt.Printf("remote v4 = %s:%d\n", remote4, port4)
	remote6, port6 := parseRemote(*optV6remote)
	fmt.Printf("remote v6 = %s:%d\n", remote6, port6)

	v4conn, localport4, err := listenNet("udp4", 0)
	if err != nil {
		log.Fatal(err)
	}
	if port4 == 0 {
		port4 = localport4
	}
	gsoV4, rsoV4 := supportsUDPOffload(v4conn)

	v6conn, localport6, err := listenNet("udp6", 0)
	if err != nil {
		log.Fatal(err)
	}
	if port6 == 0 {
		port6 = localport6
	}
	gsoV6, rsov6 := supportsUDPOffload(v6conn)

	fmt.Println("Kernel detection:")
	fmt.Printf("  IPv4 GSO: %t - %t\n", gsoV4, rsoV4)
	fmt.Printf("  IPv6 GSO: %t - %t\n", gsoV6, rsov6)
	size := 4000
	if gsoV4 {
		doTests("IPv4", size, v4conn, remote4, port4, ipv4.NewPacketConn(v4conn))
	}
	if gsoV6 {
		doTests("IPv6", size, v6conn, remote6, port6, ipv6.NewPacketConn(v6conn))
	}

}

func doTests(version string, size int, conn *net.UDPConn, addr net.IP, port int, br batchWriter) {
	fmt.Println(version, "with GSO:")
	fmt.Printf("  Write:")
	testWrite(size, conn, addr, port, true, nil)
	fmt.Printf("  Write with batch:")
	testWrite(size, conn, addr, port, true, br)

	fmt.Println(version, "without GSO:")
	fmt.Printf("  Write:")
	testWrite(size, conn, addr, port, false, nil)
	fmt.Printf("  Write with batch:")
	testWrite(size, conn, addr, port, false, br)
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

func testWrite(size int, conn *net.UDPConn, addr net.IP, port int, gso bool, br batchWriter) {
	buff := make([]byte, size)
	buffs := make([][]byte, 1)
	buffs[0] = buff
	// remote = self
	remote := &net.UDPAddr{
		IP:   addr,
		Port: port,
	}
	oob := make([]byte, 0, unix.CmsgSpace(sizeOfGSOData))
	if gso {
		setGSOSize(&oob, 1200) // should be maxmtu for remote ?
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
	errmsg := "nil"
	if err != nil {
		errmsg = err.Error()
	}
	fmt.Printf("  n,nb,err = %d,%d,%s\n", n, noob, errmsg)

}
