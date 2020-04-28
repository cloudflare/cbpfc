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
			return nil, fmt.Errorf("can't create output directory: %v", err)
		}
		defer os.RemoveAll(outdir)
	} else {
		_ = os.Mkdir(outdir, 0755)
	}

	inputFile := fmt.Sprintf("%s.c", name)
	outputFile := fmt.Sprintf("%s.elf", name)
	err = ioutil.WriteFile(filepath.Join(outdir, inputFile), source, 0644)
	if err != nil {
		return nil, fmt.Errorf("can't write out program: %v", err)
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
			return nil, fmt.Errorf("can't get absolute path to include %s: %v", include, err)
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
			return nil, fmt.Errorf("can't write build cmdline: %v", err)
		}
	}

	cmd.Dir = outdir
	_, err = cmd.Output()
	if err != nil {
		switch e := err.(type) {
		case *exec.ExitError:
			return nil, fmt.Errorf("unable to compile C: %w:\n%s", err, string(e.Stderr))
		default:
			return nil, fmt.Errorf("unable to compile C: %v", err)
		}
	}

	elf, err := ioutil.ReadFile(filepath.Join(outdir, outputFile))
	if err != nil {
		return nil, fmt.Errorf("can't read ELF: %v", err)
	}

	return elf, nil
}
