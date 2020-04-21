package cbpfc

import (
	"bytes"
	"net"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// kernelBackend is a backend that runs cBPF in the kernel
func kernelBackend(tb testing.TB, insns []bpf.Instruction, in []byte) result {
	filter, err := bpf.Assemble(insns)
	if err != nil {
		tb.Fatal(err)
	}

	// Use a unix socket to test the filter
	// This doesn't risk interfering with any other network traffic, doesn't require / add special
	// headers (as would be the case if we used UDP for example) that the XDP tests don't deal with,
	// and doesn't require any special permissions
	read, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: "", Net: "unixgram"})
	if err != nil {
		tb.Fatal(err)
	}
	defer read.Close()
	readConn, err := read.SyscallConn()
	if err != nil {
		tb.Fatal(err)
	}
	err = readConn.Control(func(fd uintptr) {
		err := unix.SetsockoptSockFprog(int(fd), unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{
			Len:    uint16(len(filter)),
			Filter: (*unix.SockFilter)(unsafe.Pointer(&filter[0])),
		})
		if err != nil {
			tb.Fatal(err)
		}
	})
	if err != nil {
		tb.Fatal(err)
	}

	write, err := net.Dial("unixgram", read.LocalAddr().String())
	if err != nil {
		tb.Fatal(err)
	}
	defer write.Close()

	if _, err := write.Write(in); err != nil {
		tb.Fatal(err)
	}

	read.SetDeadline(time.Now().Add(50 * time.Millisecond))

	// SocketFilters only allow matching packets through
	// If the packet does not match, the only signal we have is the absence of a packet
	var out [1500]byte
	n, err := read.Read(out[:])
	if err != nil {
		if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
			return noMatch
		}

		tb.Fatal(err)
	}

	// Sanity check we received the right packet
	// Received packet is truncated to the SocketFilter's return value
	if !bytes.Equal(in[:n], out[:n]) {
		tb.Fatalf("Received unexpected packet:\nSent: %v\nGot: %v\n", in, out[:n])
	}

	return match
}
