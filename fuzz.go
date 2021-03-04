// +build gofuzz

// Use with https://github.com/dvyukov/go-fuzz
package cbpfc

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/net/bpf"
)

func Fuzz(data []byte) int {
	// data needs to be split into a packet and a filter.
	// Use the first two bytes as the number of instructions in the filter,
	// and the remaining as the number of packets.
	if len(data) < 2 {
		return -1
	}
	numInsns := int(binary.BigEndian.Uint16(data))
	data = data[2:]

	if numInsns*8 > len(data) {
		return -1
	}
	var insns []bpf.Instruction
	for i := 0; i < numInsns; i++ {
		raw := bpf.RawInstruction{
			Op: binary.BigEndian.Uint16(data),
			Jt: data[2],
			Jf: data[3],
			K:  binary.BigEndian.Uint32(data[4:]),
		}
		data = data[8:]

		insn := raw.Disassemble()
		// Invalid BPF instruction.
		if raw == insn {
			return -1
		}

		insns = append(insns, insn)
	}

	// Need at least 14 bytes of packet.
	pkt := data
	if len(pkt) < 14 {
		t := make([]byte, 14)
		copy(t, pkt)
		pkt = t
	}

	kernelGot, kernelErr := kernelBackend(insns, pkt)
	cGot, cErr := cBackend(insns, pkt)
	ebpfGot, ebpfErr := cBackend(insns, pkt)

	if ((kernelErr == nil) != (cErr == nil)) || ((kernelErr == nil) != (ebpfErr == nil)) {
		panic(fmt.Sprintf("backend error disagree:\nkernel error: %v\n\nc error: %v\n\nebpf error: %v\n", kernelErr, cErr, ebpfErr))
	}
	if kernelErr != nil {
		return 0
	}

	if (kernelGot != cGot) || (kernelGot != ebpfGot) {
		panic(fmt.Sprintf("backend result disagree:\nkernel result: %v\nc result: %v\nebpf result: %v\n", kernelGot, cGot, ebpfGot))
	}
	return 1
}
