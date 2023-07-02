package main

import (
	"fmt"
	"os"

	"github.com/yalue/elf_reader"
)

func main() {
	// Print the section names in /bin/bash. This code will work on both 32-bit
	// and 64-bit systems.
	raw, e := os.ReadFile("/bin/bash")
	if e != nil {
		fmt.Printf("Failed reading /bin/bash: %s\n", e)
		return
	}
	elf, e := elf_reader.ParseELFFile(raw)
	if e != nil {
		fmt.Printf("Failed parsing ELF file: %s\n", e)
		return
	}
	count := elf.GetSectionCount()
	for i := uint16(0); i < count; i++ {
		if i == 0 {
			fmt.Printf("Section 0: NULL section (no name)\n")
			continue
		}
		content, e := elf.GetSectionContent(uint16(i))
		if e != nil {
			fmt.Printf("Failed getting section %d content: %s\n", i, e)
			continue
		}
		fmt.Printf("Section %d content: %s\n", i, content) // TODO use this content instead of the current implementation with https://pkg.go.dev/debug/elf#File.Sections
	}

}
