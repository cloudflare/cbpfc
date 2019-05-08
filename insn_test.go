package cbpfc

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"github.com/newtools/ebpf"
	"golang.org/x/net/bpf"
	// syscall has a wonky RLIM_INFINITY, and no RLIMIT_MEMLOCK
	"golang.org/x/sys/unix"
)

type XDPAction int

func (r XDPAction) String() string {
	switch r {
	case XDPAborted:
		return "XDPAborted"
	case XDPDrop:
		return "XDPDrop"
	case XDPPass:
		return "XDPPass"
	case XDPTx:
		return "XDPTx"
	default:
		return fmt.Sprintf("XDPResult(%d)", int(r))
	}
}

const (
	XDPAborted XDPAction = iota
	XDPDrop
	XDPPass
	XDPTx
)

func TestMain(m *testing.M) {
	// Remove any locked memory limits so we can load BPF programs
	err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	})
	if err != nil {
		panic(err)
	}

	os.Exit(m.Run())
}

func TestZeroInitA(t *testing.T) {
	t.Parallel()

	filter := []bpf.Instruction{
		bpf.RetA{},
	}

	checkBackends(t, filter, []byte{}, XDPPass)
}

func TestZeroInitX(t *testing.T) {
	t.Parallel()

	filter := []bpf.Instruction{
		bpf.TXA{},
		bpf.RetA{},
	}

	checkBackends(t, filter, []byte{}, XDPPass)
}

func TestZeroInitScratch(t *testing.T) {
	t.Parallel()

	filter := []bpf.Instruction{
		bpf.LoadScratch{Dst: bpf.RegA, N: 7},
		bpf.RetA{},
	}

	checkBackends(t, filter, []byte{}, XDPPass)
}

func TestLoadConstantA(t *testing.T) {
	t.Parallel()

	filter := func(val uint32) []bpf.Instruction {
		return []bpf.Instruction{
			bpf.LoadConstant{Dst: bpf.RegA, Val: val},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: val, SkipTrue: 1},
			bpf.RetConstant{Val: 0},
			bpf.RetConstant{Val: 1},
		}
	}

	checkBackends(t, filter(1), []byte{}, XDPDrop)
	checkBackends(t, filter(28), []byte{}, XDPDrop)
	checkBackends(t, filter(0), []byte{}, XDPDrop)
}

func TestLoadConstantX(t *testing.T) {
	t.Parallel()

	filter := func(val uint32) []bpf.Instruction {
		return []bpf.Instruction{
			bpf.LoadConstant{Dst: bpf.RegX, Val: val},
			bpf.TXA{},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: val, SkipTrue: 1},
			bpf.RetConstant{Val: 0},
			bpf.RetConstant{Val: 1},
		}
	}

	checkBackends(t, filter(1), []byte{}, XDPDrop)
	checkBackends(t, filter(28), []byte{}, XDPDrop)
	checkBackends(t, filter(0), []byte{}, XDPDrop)
}

func TestLoadAbsolute(t *testing.T) {
	t.Parallel()

	filter := func(val uint32, size int) []bpf.Instruction {
		return []bpf.Instruction{
			bpf.LoadAbsolute{Off: 2, Size: size},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: val, SkipTrue: 1},
			bpf.RetConstant{Val: 0},
			bpf.RetConstant{Val: 1},
		}
	}

	// 1
	checkBackends(t, filter(5, 1), []byte{0, 0, 5}, XDPDrop)
	checkBackends(t, filter(6, 1), []byte{0, 0, 5}, XDPPass)

	// 2
	checkBackends(t, filter(0xDEAD, 2), []byte{0, 0, 0xDE, 0xAD}, XDPDrop)
	checkBackends(t, filter(0xDEAF, 2), []byte{0, 0, 0xDE, 0xAD}, XDPPass)

	// 4
	checkBackends(t, filter(0xDEADBEEF, 4), []byte{0, 0, 0xDE, 0xAD, 0xBE, 0xEF}, XDPDrop)
	checkBackends(t, filter(0xDEAFBEEF, 4), []byte{0, 0, 0xDE, 0xAD, 0xBE, 0xEF}, XDPPass)
}

func TestLoadIndirect(t *testing.T) {
	t.Parallel()

	filter := func(val uint32, size int) []bpf.Instruction {
		return []bpf.Instruction{
			bpf.LoadConstant{Dst: bpf.RegX, Val: 1},
			bpf.LoadIndirect{Off: 2, Size: size},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: val, SkipTrue: 1},
			bpf.RetConstant{Val: 0},
			bpf.RetConstant{Val: 1},
		}
	}

	// 1
	checkBackends(t, filter(5, 1), []byte{0, 0, 0, 5}, XDPDrop)
	checkBackends(t, filter(6, 1), []byte{0, 0, 0, 5}, XDPPass)

	// 2
	checkBackends(t, filter(0xDEAD, 2), []byte{0, 0, 0, 0xDE, 0xAD}, XDPDrop)
	checkBackends(t, filter(0xDEAF, 2), []byte{0, 0, 0, 0xDE, 0xAD}, XDPPass)

	// 4
	checkBackends(t, filter(0xDEADBEEF, 4), []byte{0, 0, 0, 0xDE, 0xAD, 0xBE, 0xEF}, XDPDrop)
	checkBackends(t, filter(0xDEAFBEEF, 4), []byte{0, 0, 0, 0xDE, 0xAD, 0xBE, 0xEF}, XDPPass)
}

func TestScratchA(t *testing.T) {
	t.Parallel()

	filter := func(val uint32) []bpf.Instruction {
		return []bpf.Instruction{
			bpf.LoadConstant{Dst: bpf.RegA, Val: val},
			bpf.StoreScratch{Src: bpf.RegA, N: 7},

			// clobber the reg in the mean time
			bpf.LoadConstant{Dst: bpf.RegA, Val: 0},

			// load garbage in the adjacent slots
			bpf.LoadConstant{Dst: bpf.RegA, Val: 0xFFFFFFFF},
			bpf.StoreScratch{Src: bpf.RegA, N: 6},
			bpf.LoadConstant{Dst: bpf.RegA, Val: 0xFFFFFFFF},
			bpf.StoreScratch{Src: bpf.RegA, N: 8},

			bpf.LoadScratch{Dst: bpf.RegA, N: 7},

			bpf.JumpIf{Cond: bpf.JumpEqual, Val: val, SkipTrue: 1},
			bpf.RetConstant{Val: 0},
			bpf.RetConstant{Val: 1},
		}
	}

	checkBackends(t, filter(0xdeadbeef), []byte{}, XDPDrop)
	checkBackends(t, filter(0), []byte{}, XDPDrop)
}

func TestScratchX(t *testing.T) {
	t.Parallel()

	filter := func(val uint32) []bpf.Instruction {
		return []bpf.Instruction{
			bpf.LoadConstant{Dst: bpf.RegX, Val: val},
			bpf.StoreScratch{Src: bpf.RegX, N: 7},

			// clobber the reg in the mean time
			bpf.LoadConstant{Dst: bpf.RegX, Val: 0},

			// load garbage in the adjacent slots
			bpf.LoadConstant{Dst: bpf.RegX, Val: 0xFFFFFFFF},
			bpf.StoreScratch{Src: bpf.RegX, N: 6},
			bpf.LoadConstant{Dst: bpf.RegX, Val: 0xFFFFFFFF},
			bpf.StoreScratch{Src: bpf.RegX, N: 8},

			bpf.LoadScratch{Dst: bpf.RegX, N: 7},
			bpf.TXA{},

			bpf.JumpIf{Cond: bpf.JumpEqual, Val: val, SkipTrue: 1},
			bpf.RetConstant{Val: 0},
			bpf.RetConstant{Val: 1},
		}
	}

	checkBackends(t, filter(0xdeadbeef), []byte{}, XDPDrop)
	checkBackends(t, filter(0), []byte{}, XDPDrop)
}

func TestMemShift(t *testing.T) {
	t.Parallel()

	filter := func(val uint32) []bpf.Instruction {
		return []bpf.Instruction{
			bpf.LoadConstant{Dst: bpf.RegA, Val: val},
			bpf.LoadMemShift{Off: 2},
			bpf.JumpIfX{Cond: bpf.JumpEqual, SkipTrue: 1},
			bpf.RetConstant{Val: 0},
			bpf.RetConstant{Val: 1},
		}
	}

	checkBackends(t, filter(40), []byte{0, 0, 0xAA}, XDPDrop)
	checkBackends(t, filter(0), []byte{0, 0, 0xF0}, XDPDrop)
}

// check a OP b == res for both ALUOpConstant and ALUOpX
func checkAlu(t *testing.T, op bpf.ALUOp, a, b, res uint32) {
	t.Helper()

	constFilter := []bpf.Instruction{
		bpf.LoadConstant{Dst: bpf.RegA, Val: a},
		bpf.ALUOpConstant{Op: op, Val: b},

		bpf.JumpIf{Cond: bpf.JumpEqual, Val: res, SkipTrue: 1},
		bpf.RetConstant{Val: 0},
		bpf.RetConstant{Val: 1},
	}

	checkBackends(t, constFilter, []byte{}, XDPDrop)

	xFilter := []bpf.Instruction{
		bpf.LoadConstant{Dst: bpf.RegA, Val: a},
		bpf.LoadConstant{Dst: bpf.RegX, Val: b},

		bpf.ALUOpX{Op: op},

		bpf.JumpIf{Cond: bpf.JumpEqual, Val: res, SkipTrue: 1},
		bpf.RetConstant{Val: 0},
		bpf.RetConstant{Val: 1},
	}

	checkBackends(t, xFilter, []byte{}, XDPDrop)
}

func TestALUAdd(t *testing.T) {
	t.Parallel()

	checkAlu(t, bpf.ALUOpAdd, 1, 0, 1)
	checkAlu(t, bpf.ALUOpAdd, 4, 13, 17)
}

func TestALUSub(t *testing.T) {
	t.Parallel()

	checkAlu(t, bpf.ALUOpSub, 1, 1, 0)
	checkAlu(t, bpf.ALUOpSub, 13, 9, 4)
}

func TestALUMul(t *testing.T) {
	t.Parallel()

	checkAlu(t, bpf.ALUOpMul, 0, 1, 0)
	checkAlu(t, bpf.ALUOpMul, 4, 13, 52)
	// overflow - 2^31 * 2
	checkAlu(t, bpf.ALUOpMul, 2, 0x80000000, 0)
}

func TestALUDiv(t *testing.T) {
	t.Parallel()

	checkAlu(t, bpf.ALUOpDiv, 2, 2, 1)
	checkAlu(t, bpf.ALUOpDiv, 19, 3, 6)
}

func TestALUDivZero(t *testing.T) {
	t.Parallel()

	filter := []bpf.Instruction{
		bpf.LoadAbsolute{Size: 1, Off: 0},
		bpf.TAX{},

		bpf.LoadConstant{Dst: bpf.RegA, Val: 10},

		bpf.ALUOpX{Op: bpf.ALUOpDiv},

		bpf.RetConstant{Val: 1},
	}

	checkBackends(t, filter, []byte{0}, XDPPass)
	checkBackends(t, filter, []byte{1}, XDPDrop)
}

func TestALUOr(t *testing.T) {
	t.Parallel()

	checkAlu(t, bpf.ALUOpOr, 1, 0, 1)
	checkAlu(t, bpf.ALUOpOr, 0xF0, 0x0F, 0xFF)
}

func TestALUAnd(t *testing.T) {
	t.Parallel()

	checkAlu(t, bpf.ALUOpAnd, 1, 0, 0)
	checkAlu(t, bpf.ALUOpAnd, 0xF0, 0x80, 0x80)
	checkAlu(t, bpf.ALUOpAnd, 0xF0, 0x0F, 0x00)
}

func TestALUShiftLeft(t *testing.T) {
	t.Parallel()

	checkAlu(t, bpf.ALUOpShiftLeft, 1, 0, 1)
	checkAlu(t, bpf.ALUOpShiftLeft, 1, 4, 0x10)
}

func TestALUShiftRight(t *testing.T) {
	t.Parallel()

	checkAlu(t, bpf.ALUOpShiftRight, 0xF0, 4, 0x0F)
	checkAlu(t, bpf.ALUOpShiftRight, 0xF0, 8, 0)
}

func TestALUMod(t *testing.T) {
	t.Parallel()

	checkAlu(t, bpf.ALUOpMod, 16, 4, 0)
	checkAlu(t, bpf.ALUOpMod, 17, 4, 1)
}

func TestALUXor(t *testing.T) {
	t.Parallel()

	checkAlu(t, bpf.ALUOpXor, 1, 1, 0)
	checkAlu(t, bpf.ALUOpMod, 6, 4, 2)
}

func TestNegateA(t *testing.T) {
	t.Parallel()

	filter := []bpf.Instruction{
		bpf.LoadConstant{Dst: bpf.RegA, Val: 26},

		bpf.NegateA{},

		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(26 | 0x80000000), SkipTrue: 1},
		bpf.RetConstant{Val: 0},
		bpf.RetConstant{Val: 1},
	}

	checkBackends(t, filter, []byte{}, XDPPass)
}

func TestJump(t *testing.T) {
	t.Parallel()

	filter := []bpf.Instruction{
		// "dummy" jump so the unreachable code after the real jump isn't removed
		bpf.LoadAbsolute{Off: 0, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 1, SkipTrue: 1},

		bpf.Jump{Skip: 1},

		bpf.LoadConstant{Dst: bpf.RegA, Val: 1},
		bpf.RetA{},
	}

	checkBackends(t, filter, []byte{}, XDPPass)
}

// a needs to be != 0
func checkJump(t *testing.T, cond bpf.JumpTest, a, b uint32, result bool) {
	t.Helper()

	if a == 0 {
		t.Fatal("a must be non 0")
	}

	// match if cond is true
	action := XDPPass
	if result {
		action = XDPDrop
	}

	// constant skipTrue
	constTrueFilter := []bpf.Instruction{
		bpf.LoadConstant{Dst: bpf.RegA, Val: a},

		bpf.JumpIf{Cond: cond, Val: b, SkipTrue: 1},
		bpf.RetConstant{Val: 0},
		bpf.RetConstant{Val: 1},
	}
	checkBackends(t, constTrueFilter, []byte{}, action)

	// constant skipTrue & skipFalse
	constBothFilter := []bpf.Instruction{
		bpf.LoadConstant{Dst: bpf.RegA, Val: a},

		// "dummy" interleaved jump so the actual test jump can use both skipFalse and skipTrue
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipTrue: 1},

		bpf.JumpIf{Cond: cond, Val: b, SkipTrue: 2, SkipFalse: 1},

		// "dummy" target
		bpf.RetConstant{Val: 1},

		bpf.RetConstant{Val: 0},
		bpf.RetConstant{Val: 1},
	}
	checkBackends(t, constBothFilter, []byte{}, action)

	// X skipTrue
	xTrueFilter := []bpf.Instruction{
		bpf.LoadConstant{Dst: bpf.RegA, Val: a},
		bpf.LoadConstant{Dst: bpf.RegX, Val: b},

		bpf.JumpIfX{Cond: cond, SkipTrue: 1},
		bpf.RetConstant{Val: 0},
		bpf.RetConstant{Val: 1},
	}
	checkBackends(t, xTrueFilter, []byte{}, action)

	// X skipTrue & skipFalse
	xBothFilter := []bpf.Instruction{
		bpf.LoadConstant{Dst: bpf.RegA, Val: a},
		bpf.LoadConstant{Dst: bpf.RegX, Val: b},

		// "dummy" interleaved jump so the actual test jump can use both skipFalse and skipTrue
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipTrue: 1},

		bpf.JumpIfX{Cond: cond, SkipTrue: 2, SkipFalse: 1},

		// "dummy" target
		bpf.RetConstant{Val: 1},

		bpf.RetConstant{Val: 0},
		bpf.RetConstant{Val: 1},
	}
	checkBackends(t, xBothFilter, []byte{}, action)
}

func TestJumpIfEqual(t *testing.T) {
	t.Parallel()

	checkJump(t, bpf.JumpEqual, 23, 23, true)
	checkJump(t, bpf.JumpEqual, 23, 21, false)
}

func TestJumpIfNotEqual(t *testing.T) {
	t.Parallel()

	checkJump(t, bpf.JumpNotEqual, 23, 23, false)
	checkJump(t, bpf.JumpNotEqual, 23, 21, true)
}

func TestJumpIfGreaterThan(t *testing.T) {
	t.Parallel()

	checkJump(t, bpf.JumpGreaterThan, 24, 23, true)
	checkJump(t, bpf.JumpGreaterThan, 23, 23, false)
	checkJump(t, bpf.JumpGreaterThan, 22, 23, false)
}

func TestJumpIfLessThan(t *testing.T) {
	t.Parallel()

	checkJump(t, bpf.JumpLessThan, 24, 23, false)
	checkJump(t, bpf.JumpLessThan, 23, 23, false)
	checkJump(t, bpf.JumpLessThan, 22, 23, true)
}

func TestJumpIfGreaterOrEqual(t *testing.T) {
	t.Parallel()

	checkJump(t, bpf.JumpGreaterOrEqual, 24, 23, true)
	checkJump(t, bpf.JumpGreaterOrEqual, 23, 23, true)
	checkJump(t, bpf.JumpGreaterOrEqual, 22, 23, false)
}

func TestJumpIfLessOrEqual(t *testing.T) {
	t.Parallel()

	checkJump(t, bpf.JumpLessOrEqual, 24, 23, false)
	checkJump(t, bpf.JumpLessOrEqual, 23, 23, true)
	checkJump(t, bpf.JumpLessOrEqual, 22, 23, true)
}

func TestJumpIfBitsSet(t *testing.T) {
	t.Parallel()

	checkJump(t, bpf.JumpBitsSet, 6, 4, true)
	checkJump(t, bpf.JumpBitsSet, 6, 2, true)
	checkJump(t, bpf.JumpBitsSet, 6, 8, false)
}

func TestJumpIfBitsNotSet(t *testing.T) {
	t.Parallel()

	checkJump(t, bpf.JumpBitsNotSet, 6, 4, false)
	checkJump(t, bpf.JumpBitsNotSet, 6, 2, false)
	checkJump(t, bpf.JumpBitsNotSet, 6, 8, true)
}

func TestRetA(t *testing.T) {
	t.Parallel()

	filter := []bpf.Instruction{
		bpf.LoadConstant{Dst: bpf.RegA, Val: 1},
		bpf.RetA{},
	}

	checkBackends(t, filter, []byte{}, XDPDrop)
}

func TestRetConstant(t *testing.T) {
	t.Parallel()

	filter := []bpf.Instruction{
		bpf.RetConstant{Val: 1},
	}

	checkBackends(t, filter, []byte{}, XDPDrop)

	filter = []bpf.Instruction{
		bpf.RetConstant{Val: 0},
	}

	checkBackends(t, filter, []byte{}, XDPPass)
}

func TestTXA(t *testing.T) {
	t.Parallel()

	filter := []bpf.Instruction{
		bpf.LoadConstant{Dst: bpf.RegX, Val: 1},
		bpf.TXA{},
		bpf.RetA{},
	}

	checkBackends(t, filter, []byte{}, XDPDrop)
}

func TestTAX(t *testing.T) {
	t.Parallel()

	filter := []bpf.Instruction{
		bpf.LoadConstant{Dst: bpf.RegA, Val: 1},
		bpf.TAX{},
		bpf.TXA{},
		bpf.RetA{},
	}

	checkBackends(t, filter, []byte{}, XDPDrop)
}

// checkBackends builds an eBPF program using each backend, and checks it returns the correct action
// Input packet is 0 padded to min ethernet length, and output is checked to be unchanged
func checkBackends(tb testing.TB, filter []bpf.Instruction, in []byte, res XDPAction) {
	tb.Helper()

	if len(in) < 14 {
		t := make([]byte, 14)
		copy(t, in)
		in = t
	}

	checkAction(tb, loadC(tb, filter), in, res)
	checkAction(tb, loadEBPF(tb, filter), in, res)
}

func checkAction(tb testing.TB, progSpec *ebpf.ProgramSpec, in []byte, action XDPAction) {
	tb.Helper()

	if testing.Short() {
		tb.SkipNow()
	}

	prog, err := ebpf.NewProgram(progSpec)
	if err != nil {
		tb.Fatal(err)
	}

	ret, out, err := prog.Test(in)
	if err != nil {
		tb.Fatal(err)
	}

	if !bytes.Equal(in, out) {
		tb.Fatalf("Program modified input:\nIn: %v\nOut: %v\n", in, out)
	}

	retAction := XDPAction(ret)

	if retAction != action {
		tb.Fatalf("Program returned %v, expected %v\n", retAction, action)
	}
}
