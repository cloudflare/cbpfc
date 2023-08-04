package cbpfc

import (
	"bytes"
	"os"
	"text/template"

	"github.com/cloudflare/cbpfc/clang"

	"github.com/pkg/errors"
	"golang.org/x/net/bpf"
)

var testTemplate = template.Must(template.New(entryPoint).Parse(`
#define __section(NAME) __attribute__((section(NAME), used))

char __license[] __section("license") = "BSD";

// Shim out all the definitions required by cbpfc
// Real programs should use the proper headers
typedef unsigned long long uint64_t;
typedef long long int64_t;
typedef unsigned int uint32_t;
typedef int int32_t;
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

__section("xdp") int {{.ProgramName}}(struct xdp_md *ctx) {
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

	// Function name of the filter
	FilterName string

	// Name of the eBPF program
	ProgramName string
}

// ExampleToC demonstrates how to use ToC() to embed a cBPF filter
// in a C program, and compile it to eBPF.
func ExampleToC() {
	// simple cBPF filter that matches all packets
	filter := []bpf.Instruction{
		bpf.RetConstant{Val: 1},
	}

	elf, err := buildC(filter, "example", COpts{FunctionName: "example_filter"})
	if err != nil {
		panic(err)
	}

	// ELF with a single eBPF program 'example'
	// Can be loaded with cilium/ebpf or libbpf
	_ = elf
}

// buildC compiles a cBPF filter to C, embeds it in a C template,
// and compiles the resulting C program to eBPF / XDP using clang.
// The XDP program XDP_DROP's incoming packets that match the filter.
// Returns the compiled ELF
func buildC(filter []bpf.Instruction, programName string, opts COpts) ([]byte, error) {
	// convert filter to C
	ebpfFilter, err := ToC(filter, opts)
	if err != nil {
		return nil, errors.Wrap(err, "converting filter to C")
	}

	// embed filter in C template
	c := bytes.Buffer{}
	err = testTemplate.Execute(&c, testTemplateOpts{
		Filter:      ebpfFilter,
		FilterName:  opts.FunctionName,
		ProgramName: programName,
	})
	if err != nil {
		return nil, errors.Wrap(err, "executing template with C filter")
	}

	// lookup clang binary to use
	clangBin, ok := os.LookupEnv("CLANG")
	if !ok {
		clangBin = "/usr/bin/clang"
	}

	// compile C program
	elf, err := clang.Compile(c.Bytes(), entryPoint, clang.Opts{
		Clang:     clangBin,
		EmitDebug: true, // For BTF
	})
	if err != nil {
		return nil, errors.Wrap(err, "compiling C")
	}

	return elf, nil
}
