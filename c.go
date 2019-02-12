package cbpfc

import (
	"fmt"
	"strings"
	"text/template"

	"github.com/pkg/errors"
	"golang.org/x/net/bpf"
)

const funcTemplate = `
// True if packet matches, false otherwise
static inline
bool {{.Name}}(const uint8_t *const data, const uint8_t *const data_end) {
	__attribute__((unused))
	uint32_t m[16];

	__attribute__((unused))
	uint32_t a = 0;

	__attribute__((unused))
	uint32_t x = 0;

{{range $i, $b := .Blocks}}
{{if $b.IsTarget}}{{$b.Label}}:{{end}}
{{- range $i, $s := $b.Statements}}
	{{$s}}
{{- end}}
{{end}}
}`

type cFunction struct {
	Name   string
	Blocks []cBlock
}

// cBPF reg to C symbol
var regToCSym = map[bpf.Register]string{
	bpf.RegA: "a",
	bpf.RegX: "x",
}

// alu operation to C operator
var aluToCOp = map[bpf.ALUOp]string{
	bpf.ALUOpAdd:        "+",
	bpf.ALUOpSub:        "-",
	bpf.ALUOpMul:        "*",
	bpf.ALUOpDiv:        "/",
	bpf.ALUOpOr:         "|",
	bpf.ALUOpAnd:        "&",
	bpf.ALUOpShiftLeft:  "<<",
	bpf.ALUOpShiftRight: ">>",
	bpf.ALUOpMod:        "%",
	bpf.ALUOpXor:        "^",
}

// jump test to a C fmt string for condition
var condToCFmt = map[bpf.JumpTest]string{
	bpf.JumpEqual:          "a == %v",
	bpf.JumpNotEqual:       "a != %v",
	bpf.JumpGreaterThan:    "a > %v",
	bpf.JumpLessThan:       "a < %v",
	bpf.JumpGreaterOrEqual: "a >= %v",
	bpf.JumpLessOrEqual:    "a <= %v",
	bpf.JumpBitsSet:        "a & %v",
	bpf.JumpBitsNotSet:     "!(a & %v)",
}

// cBLock is a block of compiled C
type cBlock struct {
	*block

	Statements []string
}

// ToC compiles a cBPF program to a C function, named "funcName", with a signature of:
//
//     bool funcName(const uint8_t *const data, const uint8_t *const data_end)
//
// The function returns true IFF the packet in "data" matches the cBPF program (cBPF program returns != 0).
func ToC(insns []bpf.Instruction, funcName string) (string, error) {
	blocks, err := compile(insns)
	if err != nil {
		return "", err
	}

	fun := cFunction{
		Name:   funcName,
		Blocks: make([]cBlock, len(blocks)),
	}

	// Compile blocks to C
	for i, block := range blocks {
		fun.Blocks[i], err = blockToC(block)
		if err != nil {
			return "", err
		}
	}

	// Fill in the template
	tmpl, err := template.New("cbfp_func").Parse(funcTemplate)
	if err != nil {
		return "", errors.Wrapf(err, "unable to parse func template")
	}

	c := strings.Builder{}

	if err := tmpl.Execute(&c, fun); err != nil {
		return "", errors.Wrapf(err, "unable to execute func template")
	}

	return c.String(), nil
}

// blockToC compiles a block to C.
func blockToC(blk *block) (cBlock, error) {
	cBlk := cBlock{
		block:      blk,
		Statements: make([]string, len(blk.insns)),
	}

	for i, insn := range blk.insns {
		stat, err := insnToC(insn, blk)
		if err != nil {
			return cBlk, errors.Wrapf(err, "unable to compile %v", insn)
		}

		cBlk.Statements[i] = stat
	}

	return cBlk, nil
}

// insnToC compiles an instruction to a single C line / statement.
func insnToC(insn instruction, blk *block) (string, error) {
	switch i := insn.Instruction.(type) {

	case bpf.LoadConstant:
		return stat("%s = %d;", regToCSym[i.Dst], i.Val)
	case bpf.LoadScratch:
		return stat("%s = m[%d];", regToCSym[i.Dst], i.N)
	case bpf.LoadAbsolute:
		return packetLoadToC(i.Size, "data + %d", i.Off)
	case bpf.LoadIndirect:
		return packetLoadToC(i.Size, "data + x + %d", i.Off)
	case bpf.LoadMemShift:
		return stat("x = 4*(*(data + %d) & 0xf);", i.Off)

	case bpf.StoreScratch:
		return stat("m[%d] = %s;", i.N, regToCSym[i.Src])

	case bpf.ALUOpConstant:
		return stat("a %s= %d;", aluToCOp[i.Op], i.Val)
	case bpf.ALUOpX:
		return stat("a %s= x;", aluToCOp[i.Op])
	case bpf.NegateA:
		return stat("a = -a;")

	case bpf.Jump:
		return stat("goto %s;", blk.skipToBlock(skip(i.Skip)).Label())
	case bpf.JumpIf:
		return condToC(skip(i.SkipTrue), skip(i.SkipFalse), blk, condToCFmt[i.Cond], i.Val)
	case bpf.JumpIfX:
		return condToC(skip(i.SkipTrue), skip(i.SkipFalse), blk, condToCFmt[i.Cond], "x")

	// From man iptables-extensions, non-zero is match (which they call "pass" in their example because the iptables
	// action is "ACCEPT", but gatesetter uses iptable rules with "DROP")
	case bpf.RetA:
		return stat("return a != 0;")
	case bpf.RetConstant:
		if i.Val == 0 {
			return stat("return false;")
		} else {
			return stat("return true;")
		}

	case bpf.TXA:
		return stat("a = x;")
	case bpf.TAX:
		return stat("x = a;")

	case packetGuardAbsolute:
		return stat("if (data + %d > data_end) return false;", i.Len)
	case packetGuardIndirect:
		return stat("if (data + x + %d > data_end) return false;", i.Len)

	default:
		return "", errors.Errorf("unsupported instruction %v", insn)
	}
}

func packetLoadToC(size int, offsetFmt string, offsetArgs ...interface{}) (string, error) {
	offset := fmt.Sprintf(offsetFmt, offsetArgs...)

	switch size {
	case 1:
		return stat("a = *(%s);", offset)
	case 2:
		return stat("a = ntohs(*((uint16_t *) (%s)));", offset)
	case 4:
		return stat("a = ntohl(*((uint32_t *) (%s)));", offset)
	}

	return "", errors.Errorf("unsupported load size %d", size)
}

func condToC(skipTrue, skipFalse skip, blk *block, condFmt string, condArgs ...interface{}) (string, error) {
	cond := fmt.Sprintf(condFmt, condArgs...)

	if skipTrue > 0 {
		if skipFalse > 0 {
			return stat("if (%s) goto %s; else goto %s;", cond, blk.skipToBlock(skipTrue).Label(), blk.skipToBlock(skipFalse).Label())
		}
		return stat("if (%s) goto %s;", cond, blk.skipToBlock(skipTrue).Label())
	}
	return stat("if (!(%s)) goto %s;", cond, blk.skipToBlock(skipFalse).Label())
}

func stat(format string, a ...interface{}) (string, error) {
	return fmt.Sprintf(format, a...), nil
}
