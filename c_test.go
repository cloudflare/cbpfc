package cbpfc

import (
	"testing"

	"golang.org/x/net/bpf"
)

func TestFunctionName(t *testing.T) {
	checkName := func(t *testing.T, name string, valid bool) {
		t.Helper()

		_, err := ToC([]bpf.Instruction{bpf.RetA{}}, COpts{
			FunctionName: name,
		})
		if valid && err != nil {
			t.Fatalf("valid function name %s rejected: %v", name, err)
		}
		if !valid {
			requireError(t, err, "invalid FunctionName")
		}
	}

	checkName(t, "", false)
	checkName(t, "0foo", false)
	checkName(t, "0foo\nfoo", false)
	checkName(t, "foo_bar2", true)
	checkName(t, "a2", true)
}
