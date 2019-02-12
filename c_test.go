package cbpfc

import (
	"bytes"
	"os"
	"testing"
	"text/template"

	"github.com/cloudflare/cbpfc/clang"

	"github.com/newtools/ebpf"
	"golang.org/x/net/bpf"
)

// Env var of clang binary to use
const clangEnv = "CLANG"

const (
	filterName = "filter"
	entryPoint = "xdp_filter"
)

var testTemplate = template.Must(template.New(entryPoint).Parse(`
#define __section(NAME) __attribute__((section(NAME), used))

char __license[] __section("license") = "BSD";

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

{{.Filter}}

__section("xdp") int xdp_filter(struct xdp_md *ctx) {
	uint8_t *data = (uint8_t *)(long)ctx->data;
	uint8_t const *data_end = (uint8_t *)(long)ctx->data_end;

	if ({{.FilterName}}(data, data_end)) {
		return XDP_DROP;
	}

	return XDP_PASS;
}
`))

type testTemplateOpts struct {
	// Definition of the filter
	Filter string

	// Name of the filter
	FilterName string
}

// loadC compiles classic BPF to C, which is compiled with clang, and loaded in the kernel
// XDPDrop on match, XDPPass otherwise
func loadC(tb testing.TB, insns []bpf.Instruction) *ebpf.Program {
	tb.Helper()

	// generate C
	filter, err := ToC(insns, filterName)
	if err != nil {
		tb.Fatal(err)
	}

	c := bytes.Buffer{}
	err = testTemplate.Execute(&c, testTemplateOpts{
		Filter:     filter,
		FilterName: filterName,
	})
	if err != nil {
		tb.Fatal(err)
	}

	// compile to ELF
	clangBin, ok := os.LookupEnv(clangEnv)
	if !ok {
		clangBin = "/usr/bin/clang"
	}

	elf, err := clang.Compile(c.Bytes(), entryPoint, clang.Opts{
		Clang: clangBin,
	})
	if err != nil {
		tb.Fatal(err)
	}

	// load ELF
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(elf))
	if err != nil {
		tb.Fatal(err)
	}

	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		tb.Fatal(err)
	}
	defer collection.Close()

	return collection.DetachProgram(entryPoint)
}
