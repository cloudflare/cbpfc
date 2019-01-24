// Package clang implements a simple wrapper for invoking clang to
// compile C to eBPF
package clang

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
)

// CompileOpts configure how an XDP program is compiled / built
type Opts struct {
	// clang binary to use
	Clang string

	// Header directories to include
	Include []string

	// Destination directory for compiled programs.
	// Uses a temporary directory if empty.
	Output string

	// emit DWARF debug info in the XDP elf
	EmitDebug bool
}

// Compile compiles a C source string into an ELF
func Compile(source []byte, name string, opts Opts) ([]byte, error) {
	var err error

	outdir := opts.Output
	if outdir == "" {
		outdir, err = ioutil.TempDir("", "cbpfc-clang")
		if err != nil {
			return nil, errors.Wrap(err, "can't create output directory")
		}
		defer os.RemoveAll(outdir)
	} else {
		_ = os.Mkdir(outdir, 0755)
	}

	inputFile := fmt.Sprintf("%s.c", name)
	outputFile := fmt.Sprintf("%s.elf", name)
	err = ioutil.WriteFile(filepath.Join(outdir, inputFile), source, 0644)
	if err != nil {
		return nil, errors.Wrap(err, "can't write out program")
	}

	flags := []string{
		"-O2",
		"-Wall", "-Werror",
		"-nostdinc",
		"-c",
		"-target", "bpf",
		inputFile,
		"-o", outputFile,
	}

	for _, include := range opts.Include {
		// debug build script will be in a different directory, relative imports won't work
		absInclude, err := filepath.Abs(include)
		if err != nil {
			return nil, errors.Wrapf(err, "can't get absolute path to include %s", include)
		}

		flags = append(flags, "-I", absInclude)
	}

	if opts.EmitDebug {
		flags = append(flags, "-g")
	}

	cmd := exec.Command(opts.Clang, flags...)

	// debug build script
	if opts.Output != "" {
		cmdline := cmd.Path + " " + strings.Join(flags, " ") + "\n"
		err := ioutil.WriteFile(filepath.Join(outdir, "build"), []byte(cmdline), 0644)
		if err != nil {
			return nil, errors.Wrap(err, "can't write build cmdline")
		}
	}

	cmd.Dir = outdir
	_, err = cmd.Output()
	if err != nil {
		switch e := err.(type) {
		case *exec.ExitError:
			return nil, errors.Wrapf(e, "unable to compile C:\n%s", string(e.Stderr))
		default:
			return nil, errors.Wrapf(e, "unable to compile C")
		}
	}

	elf, err := ioutil.ReadFile(filepath.Join(outdir, outputFile))
	if err != nil {
		return nil, errors.Wrap(err, "can't read ELF")
	}

	return elf, nil
}
