package main

import (
	"debug/elf"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func ioReader(file string) io.ReaderAt {
	r, err := os.Open(file)
	check(err)
	return r
}

// mapSection returns 10 bytes hex string for a []byte section
func mapSection(b []byte) string {
	return hex.EncodeToString(b[0:10])
}

// noZeroes returns true if there are no zeros in the string
func noZeros(s string) bool {
	return (strings.Count(s, "0") <= 1)
}

func main() {

	if len(os.Args) < 2 {
		fmt.Println("Usage: mkyar <elf_file>")
		os.Exit(1)
	}
	f := ioReader(os.Args[1])
	_elf, err := elf.NewFile(f)
	check(err)

	// Read and decode ELF identifier
	var ident [16]uint8
	f.ReadAt(ident[0:], 0)
	check(err)

	if ident[0] != '\x7f' || ident[1] != 'E' || ident[2] != 'L' || ident[3] != 'F' {
		fmt.Printf("Bad magic number at %d\n", ident[0:4])
		os.Exit(1)
	}

	// Process sections
	hexCollection := []string{}
	for _, v := range _elf.Sections {
		var b []byte
		if v.SectionHeader.Type != elf.SHT_NOBITS {
			b, err = v.Data()
			check(err)
		}

		if len(b) > 10 {
			sectionEntry := mapSection(b)
			if noZeros(sectionEntry) {
				hexCollection = append(hexCollection, sectionEntry)
			}
		}
	}

	fmt.Printf("hexCollection: %v\n", hexCollection)

}
