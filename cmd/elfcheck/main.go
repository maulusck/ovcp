// Command elfcheck fails unless every named ELF file is a PIE with full RELRO
// (a GNU_RELRO segment and BIND_NOW); make build runs it on what it links.
package main

import (
	"debug/elf"
	"fmt"
	"os"
	"strings"
)

func main() {
	for _, path := range os.Args[1:] {
		if err := check(path); err != nil {
			fmt.Fprintf(os.Stderr, "elfcheck: %s: %v\n", path, err)
			os.Exit(1)
		}
	}
}

func check(path string) error {
	f, err := elf.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	flags, _ := f.DynValue(elf.DT_FLAGS)
	flags1, _ := f.DynValue(elf.DT_FLAGS_1)
	relro := false
	for _, p := range f.Progs {
		relro = relro || p.Type == elf.PT_GNU_RELRO
	}
	var missing []string
	if f.Type != elf.ET_DYN || !set(flags1, uint64(elf.DF_1_PIE)) {
		missing = append(missing, "PIE")
	}
	if !relro {
		missing = append(missing, "RELRO")
	}
	if !set(flags, uint64(elf.DF_BIND_NOW)) && !set(flags1, uint64(elf.DF_1_NOW)) {
		missing = append(missing, "BIND_NOW")
	}
	if len(missing) > 0 {
		return fmt.Errorf("not hardened, missing %s", strings.Join(missing, ", "))
	}
	return nil
}

func set(values []uint64, bit uint64) bool {
	for _, v := range values {
		if v&bit != 0 {
			return true
		}
	}
	return false
}
