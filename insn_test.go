package cbpfc

import (
	"bytes"
	"flag"
	"fmt"
	"math"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/net/bpf"

	// syscall has a wonky RLIM_INFINITY, and no RLIMIT_MEMLOCK
	"golang.org/x/sys/unix"
)

func TestMain(m *testing.M) {
	// Needed for testing.Short
	flag.Parse()

	if !testing.Short() {
		// Remove any locked memory limits so we can load BPF programs
		err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
			Cur: unix.RLIM_INFINITY,
			Max: unix.RLIM_INFINITY,
		})
		if err != nil {
			panic(err)
		}
	}

	os.Exit(m.Run())
}

func TestZeroInitA(t *testing.T) {
	t.Parallel()

	filter := []bpf.Instruction{
		bpf.RetA{},
	}

	checkBackends(t, filter, []byte{}, noMatch)
}

func TestZeroInitX(t *testing.T) {
	t.Parallel()

	filter := []bpf.Instruction{
		bpf.TXA{},
		bpf.RetA{},
	}

	checkBackends(t, filter, []byte{}, noMatch)
}

func TestPartialZeroInitX(t *testing.T) {
	t.Parallel()

	filter := []bpf.Instruction{
		bpf.LoadAbsolute{Off: 0, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 3, SkipTrue: 0, SkipFalse: 1}, // jump to block 1 or 2

		// block 1
		bpf.TAX{}, // initialize RegX
		// Fall through

		// block 2
		bpf.TXA{}, // RegX used potentially uninitialized
		bpf.RetA{},
	}

	checkBackends(t, filter, []byte{0}, noMatch)
	checkBackends(t, filter, []byte{3}, match)
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

	checkBackends(t, filter(1), []byte{}, match)
	checkBackends(t, filter(28), []byte{}, match)
	checkBackends(t, filter(0), []byte{}, match)
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

	checkBackends(t, filter(1), []byte{}, match)
	checkBackends(t, filter(28), []byte{}, match)
	checkBackends(t, filter(0), []byte{}, match)
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
	checkBackends(t, filter(5, 1), []byte{0, 0, 5}, match)
	checkBackends(t, filter(6, 1), []byte{0, 0, 5}, noMatch)

	// 2
	checkBackends(t, filter(0xDEAD, 2), []byte{0, 0, 0xDE, 0xAD}, match)
	checkBackends(t, filter(0xDEAF, 2), []byte{0, 0, 0xDE, 0xAD}, noMatch)

	// 4
	checkBackends(t, filter(0xDEADBEEF, 4), []byte{0, 0, 0xDE, 0xAD, 0xBE, 0xEF}, match)
	checkBackends(t, filter(0xDEAFBEEF, 4), []byte{0, 0, 0xDE, 0xAD, 0xBE, 0xEF}, noMatch)
}

func TestLoadAbsoluteBigOffset(t *testing.T) {
	t.Parallel()

	// XDP limits packets to one page, so there's no way to feed a packet big enough to test the offsets
	// we want through BPF_PROG_TEST_RUN.
	// All we can check is that the verifier accepts the program and it doesn't match.
	filter := func(load bpf.Instruction) []bpf.Instruction {
		return []bpf.Instruction{
			load,
			bpf.ALUOpConstant{Op: bpf.ALUOpAdd, Val: 2},
			bpf.RetA{},
		}
	}

	checkBackends(t, filter(bpf.LoadAbsolute{Off: maxPacketOffset - 1, Size: 1}), nil, noMatch)
	checkBackends(t, filter(bpf.LoadAbsolute{Off: maxPacketOffset, Size: 1}), nil, noMatch)
	checkBackends(t, filter(bpf.LoadAbsolute{Off: maxPacketOffset - 2, Size: 2}), nil, noMatch)
	checkBackends(t, filter(bpf.LoadAbsolute{Off: maxPacketOffset - 1, Size: 2}), nil, noMatch)
	checkBackends(t, filter(bpf.LoadAbsolute{Off: maxPacketOffset - 4, Size: 4}), nil, noMatch)
	checkBackends(t, filter(bpf.LoadAbsolute{Off: maxPacketOffset - 3, Size: 4}), nil, noMatch)

	checkBackends(t, filter(bpf.LoadMemShift{Off: maxPacketOffset - 1}), nil, noMatch)
	checkBackends(t, filter(bpf.LoadMemShift{Off: maxPacketOffset}), nil, noMatch)
}

func TestLoadIndirect(t *testing.T) {
	t.Parallel()

	// With a constant RegX, the verifier knows it's exact value.
	t.Run("constant_valid", func(t *testing.T) {
		filter := func(regX int32, off int32, size int, val uint32) []bpf.Instruction {
			return []bpf.Instruction{
				bpf.LoadConstant{Dst: bpf.RegX, Val: uint32(regX)},
				bpf.LoadIndirect{Off: uint32(off), Size: size},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: val, SkipTrue: 1},
				bpf.RetConstant{Val: 0},
				bpf.RetConstant{Val: 1},
			}
		}

		// RegX: INT32_MIN+4, Off: INT32_MAX, Size: 1
		checkBackends(t, filter(math.MinInt32+4, math.MaxInt32, 1, 5), []byte{0, 0, 0, 5}, match)
		checkBackends(t, filter(math.MinInt32+4, math.MaxInt32, 1, 6), []byte{0, 0, 0, 5}, noMatch)

		// RegX: 3, Off: -1, Size: 2
		checkBackends(t, filter(3, -1, 2, 0xDEAD), []byte{0, 0, 0xDE, 0xAD}, match)
		checkBackends(t, filter(3, -1, 2, 0xDEAD), []byte{0, 0, 0xDE, 0xAF}, noMatch)

		// RegX: 1, Off: 2, Size: 4
		checkBackends(t, filter(1, 2, 4, 0xDEADBEEF), []byte{0, 0, 0, 0xDE, 0xAD, 0xBE, 0xEF}, match)
		checkBackends(t, filter(1, 2, 4, 0xDEADBEEF), []byte{0, 0, 0, 0xDE, 0xAA, 0xBE, 0xEF}, noMatch)
	})

	// But with a variable RegX, the verifier only has whatever checks we perform.
	t.Run("variable_valid", func(t *testing.T) {
		filter := func(off int32, size int, val uint32) []bpf.Instruction {
			return []bpf.Instruction{
				bpf.LoadAbsolute{Off: 0, Size: 4},
				bpf.TAX{},
				bpf.LoadIndirect{Off: uint32(off), Size: size},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: val, SkipTrue: 1},
				bpf.RetConstant{Val: 0},
				bpf.RetConstant{Val: 1},
			}
		}

		// RegX: -6, Off: 13, Size: 1
		checkBackends(t, filter(13, 1, 5), []byte{0xFF, 0xFF, 0xFF, 0xFA, 0, 0, 0, 5}, match)
		checkBackends(t, filter(13, 1, 6), []byte{0xFF, 0xFF, 0xFF, 0xFA, 0, 0, 0, 5}, noMatch)

		// RegX: INT32_MAX, Off: INT32_MIN+7, Size: 2
		checkBackends(t, filter(math.MinInt32+7, 2, 0xDEAD), []byte{0x7F, 0xFF, 0xFF, 0xFF, 0, 0, 0xDE, 0xAD}, match)
		checkBackends(t, filter(math.MinInt32+7, 2, 0xDEAD), []byte{0x7F, 0xFF, 0xFF, 0xFF, 0, 0, 0xDE, 0xAF}, noMatch)

		// RegX: 3, Off: 4, Size: 4
		checkBackends(t, filter(4, 4, 0xDEADBEEF), []byte{0x00, 0x00, 0x00, 0x03, 0, 0, 0, 0xDE, 0xAD, 0xBE, 0xEF}, match)
		checkBackends(t, filter(4, 4, 0xDEADBEEF), []byte{0x00, 0x00, 0x00, 0x03, 0, 0, 0, 0xDE, 0xAA, 0xBE, 0xEF}, noMatch)
	})

	t.Run("constant_outofbounds", func(t *testing.T) {
		// Always return match to ensure noMatch comes from the packet load.
		filter := func(regX, off int32, size int) []bpf.Instruction {
			return []bpf.Instruction{
				bpf.LoadConstant{Dst: bpf.RegX, Val: uint32(regX)},
				bpf.LoadIndirect{Off: uint32(off), Size: size},
				bpf.RetConstant{Val: 1},
			}
		}

		// Not out of bounds, sanity check
		checkBackends(t, filter(-3, 3, 1), nil, match)

		// Before packet
		// RegX: -16, Off: 15
		checkBackends(t, filter(-16, 15, 1), nil, noMatch)
		// RegX: -1, Off: -2
		checkBackends(t, filter(-1, -2, 4), nil, noMatch)
		// RegX: 255, Off: -300
		checkBackends(t, filter(255, -300, 2), nil, noMatch)

		// After packet
		checkBackends(t, filter(-16, 30, 1), nil, noMatch)
	})

	t.Run("variable_outofbounds", func(t *testing.T) {
		// Always return match to ensure noMatch comes from the packet load.
		filter := func(off int32, size int) []bpf.Instruction {
			return []bpf.Instruction{
				bpf.LoadAbsolute{Off: 0, Size: 4},
				bpf.TAX{},
				bpf.LoadIndirect{Off: uint32(off), Size: size},
				bpf.RetConstant{Val: 1},
			}
		}

		// Not out of bounds, sanity check
		checkBackends(t, filter(3, 1), []byte{0xFF, 0xFF, 0xFF, 0xFD}, match)

		// Before packet
		// RegX: -16, Off: 15
		checkBackends(t, filter(15, 1), []byte{0xFF, 0xFF, 0xFF, 0xF0}, noMatch)
		// RegX: -1, Off: -2
		checkBackends(t, filter(-2, 4), []byte{0xFF, 0xFF, 0xFF, 0xFF}, noMatch)
		// RegX: 255, Off: -300
		checkBackends(t, filter(-300, 2), []byte{0x00, 0x00, 0x00, 0xFF}, noMatch)

		// After packet
		checkBackends(t, filter(30, 1), []byte{0xFF, 0xFF, 0xFF, 0xF0}, noMatch)
	})
}

func TestLoadIndirectBigOffset(t *testing.T) {
	filter := func(off uint32, size int) []bpf.Instruction {
		return []bpf.Instruction{
			// RegX is 0 initialized
			bpf.LoadIndirect{Off: off, Size: size},
			bpf.ALUOpConstant{Op: bpf.ALUOpAdd, Val: 2},
			bpf.RetA{},
		}
	}

	// XDP limits packets to one page, so there's no way to feed a packet big enough to test the offsets
	// we want through BPF_PROG_TEST_RUN.
	// All we can check is that the verifier accepts the program and it doesn't match.
	checkBackends(t, filter(0, 1), nil, match)
	checkBackends(t, filter(0, 4), nil, match)

	checkBackends(t, filter(maxPacketOffset-1, 1), nil, noMatch)
	checkBackends(t, filter(maxPacketOffset, 1), nil, noMatch)

	checkBackends(t, filter(maxPacketOffset-2, 2), nil, noMatch)
	checkBackends(t, filter(maxPacketOffset-1, 2), nil, noMatch)

	checkBackends(t, filter(maxPacketOffset-4, 4), nil, noMatch)
	checkBackends(t, filter(maxPacketOffset-3, 4), nil, noMatch)
}

// Indirect offset that would cause packetGuardIndirect.length() to overflow.
func TestLoadIndirectGuardOverflow(t *testing.T) {
	var min int32 = math.MinInt32

	checkBackends(t, []bpf.Instruction{
		// Variable RegX
		bpf.LoadAbsolute{Off: 0, Size: 4},
		bpf.TAX{},
		// Two loads, with offsets more than maxPacketOffset apart
		bpf.LoadIndirect{Off: uint32(min), Size: 1},
		bpf.LoadIndirect{Off: 0, Size: 2},
		bpf.LoadIndirect{Off: math.MaxInt32, Size: 4},
		bpf.TXA{},
		bpf.RetA{},
	}, nil, noMatch)
}

// The 0 scratch slot is usable.
func TestScratchZero(t *testing.T) {
	t.Parallel()

	filter := []bpf.Instruction{
		bpf.LoadConstant{Dst: bpf.RegA, Val: 4},
		bpf.StoreScratch{Src: bpf.RegA, N: 0},

		// clobber the reg in the mean time
		bpf.LoadConstant{Dst: bpf.RegA, Val: 0},

		bpf.LoadScratch{Dst: bpf.RegA, N: 0},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 4, SkipTrue: 1},
		bpf.RetConstant{Val: 0},
		bpf.RetConstant{Val: 1},
	}

	checkBackends(t, filter, nil, match)
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

	checkBackends(t, filter(0xdeadbeef), []byte{}, match)
	checkBackends(t, filter(0), []byte{}, match)
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

	checkBackends(t, filter(0xdeadbeef), []byte{}, match)
	checkBackends(t, filter(0), []byte{}, match)
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

	checkBackends(t, filter(40), []byte{0, 0, 0xAA}, match)
	checkBackends(t, filter(0), []byte{0, 0, 0xF0}, match)
}

func TestLoadExtLen(t *testing.T) {
	t.Parallel()

	filter := func(pktLen uint32) []bpf.Instruction {
		return []bpf.Instruction{
			bpf.LoadExtension{Num: bpf.ExtLen},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: pktLen, SkipTrue: 1},
			bpf.RetConstant{Val: 0},
			bpf.RetConstant{Val: 1},
		}
	}

	checkBackends(t, filter(16), []byte{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef}, match)
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

	checkBackends(t, constFilter, []byte{}, match)

	xFilter := []bpf.Instruction{
		bpf.LoadConstant{Dst: bpf.RegA, Val: a},
		bpf.LoadConstant{Dst: bpf.RegX, Val: b},

		bpf.ALUOpX{Op: op},

		bpf.JumpIf{Cond: bpf.JumpEqual, Val: res, SkipTrue: 1},
		bpf.RetConstant{Val: 0},
		bpf.RetConstant{Val: 1},
	}

	checkBackends(t, xFilter, []byte{}, match)
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

	checkBackends(t, filter, []byte{0}, noMatch)
	checkBackends(t, filter, []byte{1}, match)
}

// Check that ALU operations aren't signed.
// The only operator that is implemented differently for signed vs unsigned math with two's complement is division.
func TestALUDivNegative(t *testing.T) {
	checkBackends(t, []bpf.Instruction{
		bpf.LoadConstant{Dst: bpf.RegA, Val: 0x00000004}, // 4
		bpf.LoadConstant{Dst: bpf.RegX, Val: 0xFFFFFFFE}, // -2
		bpf.ALUOpX{Op: bpf.ALUOpDiv},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipTrue: 1}, // 0 means division is unsigned, -2 signed
		bpf.RetConstant{},
		bpf.RetConstant{Val: 1},
	}, nil, match)
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

	checkBackends(t, filter, []byte{}, noMatch)
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

	checkBackends(t, filter, []byte{}, noMatch)
}

// Jump that does nothing.
func TestJump0(t *testing.T) {
	t.Parallel()

	filter := []bpf.Instruction{
		bpf.LoadAbsolute{Off: 0, Size: 1},
		bpf.Jump{Skip: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual},
		bpf.JumpIfX{Cond: bpf.JumpEqual},
		bpf.RetA{},
	}

	checkBackends(t, filter, []byte{}, noMatch)
	checkBackends(t, filter, []byte{1}, match)
}

// a needs to be != 0
func checkJump(t *testing.T, cond bpf.JumpTest, a, b uint32, result bool) {
	t.Helper()

	if a == 0 {
		t.Fatal("a must be non 0")
	}

	// match if cond is true
	expected := noMatch
	if result {
		expected = match
	}

	// constant skipTrue
	constTrueFilter := []bpf.Instruction{
		bpf.LoadConstant{Dst: bpf.RegA, Val: a},

		bpf.JumpIf{Cond: cond, Val: b, SkipTrue: 1},
		bpf.RetConstant{Val: 0},
		bpf.RetConstant{Val: 1},
	}
	checkBackends(t, constTrueFilter, []byte{}, expected)

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
	checkBackends(t, constBothFilter, []byte{}, expected)

	// X skipTrue
	xTrueFilter := []bpf.Instruction{
		bpf.LoadConstant{Dst: bpf.RegA, Val: a},
		bpf.LoadConstant{Dst: bpf.RegX, Val: b},

		bpf.JumpIfX{Cond: cond, SkipTrue: 1},
		bpf.RetConstant{Val: 0},
		bpf.RetConstant{Val: 1},
	}
	checkBackends(t, xTrueFilter, []byte{}, expected)

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
	checkBackends(t, xBothFilter, []byte{}, expected)
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

	checkBackends(t, filter, []byte{}, match)
}

func TestRetConstant(t *testing.T) {
	t.Parallel()

	filter := []bpf.Instruction{
		bpf.RetConstant{Val: 1},
	}

	checkBackends(t, filter, []byte{}, match)

	filter = []bpf.Instruction{
		bpf.RetConstant{Val: 0},
	}

	checkBackends(t, filter, []byte{}, noMatch)
}

func TestTXA(t *testing.T) {
	t.Parallel()

	filter := []bpf.Instruction{
		bpf.LoadConstant{Dst: bpf.RegX, Val: 1},
		bpf.TXA{},
		bpf.RetA{},
	}

	checkBackends(t, filter, []byte{}, match)
}

func TestTAX(t *testing.T) {
	t.Parallel()

	filter := []bpf.Instruction{
		bpf.LoadConstant{Dst: bpf.RegA, Val: 1},
		bpf.TAX{},
		bpf.TXA{},
		bpf.RetA{},
	}

	checkBackends(t, filter, []byte{}, match)
}

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

// True IFF packet matches filter
type backend func(testing.TB, []bpf.Instruction, []byte) result

// checkBackends checks if all the backends match the packet as expected.
// Input packet is 0 padded to min ethernet length.
func checkBackends(t *testing.T, filter []bpf.Instruction, in []byte, expected result) {
	t.Helper()

	if len(in) < 14 {
		t := make([]byte, 14)
		copy(t, in)
		in = t
	}

	check := func(b backend) func(*testing.T) {
		return func(t *testing.T) {
			if got := b(t, filter, in); got != expected {
				t.Fatalf("Got %q, expected %q", got, expected)
			}
		}
	}

	t.Run("C", check(cBackend))
	t.Run("eBPF", check(ebpfBackend))
	t.Run("kernel", check(kernelBackend))
}

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

// testProg runs an eBPF program and checks it has not modified the packet
func testProg(tb testing.TB, progSpec *ebpf.ProgramSpec, in []byte) result {
	// -short skips tests that require permissions
	// Skipping the tests this late ensures the eBPF program still builds at least
	if testing.Short() {
		tb.SkipNow()
	}

	prog, err := ebpf.NewProgramWithOptions(progSpec, ebpf.ProgramOptions{
		LogLevel: 2, // Get full verifier logs.
	})
	if err != nil {
		tb.Fatal(err)
	}
	defer prog.Close()

	ret, out, err := prog.Test(in)
	if err != nil {
		tb.Fatal(err)
	}

	if !bytes.Equal(in, out) {
		tb.Fatalf("Program modified input:\nIn: %v\nOut: %v\n", in, out)
	}

	// The XDP programs we build drop matching packets
	switch r := XDPAction(ret); r {
	case XDPDrop:
		return match
	case XDPPass:
		return noMatch
	default:
		tb.Fatalf("Unexpected XDP return code %v", r)
		panic("unreachable")
	}
}
