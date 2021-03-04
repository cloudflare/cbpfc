package cbpfc

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"text/template"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cloudflare/cbpfc/clang"
	"github.com/pkg/errors"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

type result int

const (
	match result = iota
	noMatch
)

func (r result) String() string {
	switch r {
	case match:
		return "match"
	case noMatch:
		return "no match"
	default:
		return fmt.Sprintf("result(%d)", int(r))
	}
}

type backend func(filter []bpf.Instruction, pkt []byte) (result, error)

type xdpAction int

func (r xdpAction) String() string {
	switch r {
	case xdpAborted:
		return "xdpAborted"
	case xdpDrop:
		return "xdpDrop"
	case xdpPass:
		return "xdpPass"
	case xdpTx:
		return "xdpTx"
	default:
		return fmt.Sprintf("xdpAction(%d)", int(r))
	}
}

const (
	xdpAborted xdpAction = iota
	xdpDrop
	xdpPass
	xdpTx
)

// testProg runs an eBPF program and checks it has not modified the packet
func runProg(progSpec *ebpf.ProgramSpec, in []byte) (result, error) {
	prog, err := ebpf.NewProgram(progSpec)
	if err != nil {
		return 0, err
	}
	defer prog.Close()

	ret, out, err := prog.Test(in)
	if err != nil {
		return 0, err
	}

	if !bytes.Equal(in, out) {
		return 0, fmt.Errorf("Program modified input:\nIn: %v\nOut: %v\n", in, out)
	}

	// The XDP programs we build drop matching packets
	switch r := xdpAction(ret); r {
	case xdpDrop:
		return match, nil
	case xdpPass:
		return noMatch, nil
	default:
		return 0, fmt.Errorf("Unexpected XDP return code %v", r)
	}
}

var filterTemplate = template.Must(template.New("filter").Parse(`
#define __section(NAME) __attribute__((section(NAME), used))

char __license[] __section("license") = "BSD";

// Shim out all the definitions required by cbpfc
// Real programs should use the proper headers
typedef unsigned int uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;

typedef char bool;
#define false 0
#define true 1

#define ntohs __builtin_bswap16
#define ntohl __builtin_bswap32

struct xdp_md {
        uint32_t data;
        uint32_t data_end;
};

enum xdp_action {
        XDP_DROP = 1,
        XDP_PASS,
};

// Converted cBPF filter
{{.}}

__section("xdp") int xdp_filter(struct xdp_md *ctx) {
        uint8_t *data = (uint8_t *)(long)ctx->data;
        uint8_t const *data_end = (uint8_t *)(long)ctx->data_end;

        if (filter(data, data_end)) {
                return XDP_DROP;
        }

        return XDP_PASS;
}
`))

// buildC compiles a cBPF filter to C, embeds it in a C template,
// and compiles the resulting C program to eBPF / XDP using clang.
// The XDP program XDP_DROP's incoming packets that match the filter.
// Returns the compiled ELF
func cBackend(filter []bpf.Instruction, in []byte) (result, error) {
	// convert filter to C
	ebpfFilter, err := ToC(filter, COpts{
		FunctionName: "filter",
	})
	if err != nil {
		return 0, errors.Wrap(err, "converting filter to C")
	}

	// embed filter in C template
	c := bytes.Buffer{}
	err = filterTemplate.Execute(&c, ebpfFilter)
	if err != nil {
		return 0, errors.Wrap(err, "executing template with C filter")
	}

	// lookup clang binary to use
	// TODO - do we need this?
	clangBin, ok := os.LookupEnv("CLANG")
	if !ok {
		clangBin = "/usr/bin/clang"
	}

	// compile C program
	elf, err := clang.Compile(c.Bytes(), "xdp_filter", clang.Opts{
		Clang:     clangBin,
		EmitDebug: true, // For BTF
	})
	if err != nil {
		return 0, errors.Wrap(err, "compiling C")
	}

	// load ELF
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(elf))
	if err != nil {
		return 0, err
	}

	return runProg(spec.Programs["xdp_filter"], in)
}

// buildEBPF compiles a cBPF filter to eBPF, and embeds it an eBPF program.
// The XDP program XDP_DROP's incoming packets that match the filter.
// Returns the eBPF program instructions
func ebpfBackend(filter []bpf.Instruction, in []byte) (result, error) {
	ebpfFilter, err := ToEBPF(filter, EBPFOpts{
		// Pass packet start and end pointers in these registers
		PacketStart: asm.R2,
		PacketEnd:   asm.R3,
		// Result of filter
		Result:      asm.R4,
		ResultLabel: "result",
		// Registers used by generated code
		Working:     [4]asm.Register{asm.R4, asm.R5, asm.R6, asm.R7},
		LabelPrefix: "filter",
	})
	if err != nil {
		return 0, errors.Wrap(err, "converting filter to eBPF")
	}

	prog := asm.Instructions{
		// R1 holds XDP context

		// Packet start
		asm.LoadMem(asm.R2, asm.R1, 0, asm.Word),

		// Packet end
		asm.LoadMem(asm.R3, asm.R1, 4, asm.Word),

		// Fall through to filter
	}

	prog = append(prog, ebpfFilter...)

	prog = append(prog,
		asm.Mov.Imm(asm.R0, int32(xdpPass)).Sym("result"),
		asm.JEq.Imm(asm.R4, 0, "return"),
		asm.Mov.Imm(asm.R0, int32(xdpDrop)),
		asm.Return().Sym("return"),
	)

	return runProg(&ebpf.ProgramSpec{
		Name:         "ebpf_filter",
		Type:         ebpf.XDP,
		Instructions: prog,
		License:      "BSD",
	}, in)
}

// kernelBackend is a backend that runs cBPF in the kernel
func kernelBackend(insns []bpf.Instruction, in []byte) (result, error) {
	// To mimick cbpfc's behavior.
	if len(insns) == 0 {
		return 0, fmt.Errorf("can't compile 0 instructions")
	}

	filter, err := bpf.Assemble(insns)
	if err != nil {
		return 0, err
	}

	// Use a unix socket to test the filter
	// This doesn't risk interfering with any other network traffic, doesn't require / add special
	// headers (as would be the case if we used UDP for example) that the XDP tests don't deal with,
	// and doesn't require any special permissions
	read, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: "", Net: "unixgram"})
	if err != nil {
		return 0, err
	}
	defer read.Close()
	readConn, err := read.SyscallConn()
	if err != nil {
		return 0, err
	}
	var innerErr error
	err = readConn.Control(func(fd uintptr) {
		innerErr = unix.SetsockoptSockFprog(int(fd), unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{
			Len:    uint16(len(filter)),
			Filter: (*unix.SockFilter)(unsafe.Pointer(&filter[0])),
		})
	})
	if innerErr != nil {
		return 0, innerErr
	}
	if err != nil {
		return 0, err
	}

	write, err := net.Dial("unixgram", read.LocalAddr().String())
	if err != nil {
		return 0, err
	}
	defer write.Close()

	if _, err := write.Write(in); err != nil {
		return 0, err
	}

	read.SetDeadline(time.Now().Add(50 * time.Millisecond))

	// SocketFilters only allow matching packets through
	// If the packet does not match, the only signal we have is the absence of a packet
	var out [1500]byte
	n, err := read.Read(out[:])
	if err != nil {
		if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
			return noMatch, nil
		}

		return 0, err
	}

	// Sanity check we received the right packet
	// Received packet is truncated to the SocketFilter's return value
	if !bytes.Equal(in[:n], out[:n]) {
		return 0, fmt.Errorf("Received unexpected packet:\nSent: %v\nGot: %v\n", in, out[:n])
	}

	return match, nil
}
