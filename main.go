package main

import (
	"debug/elf"
	"encoding/hex"
	"fmt"
	"io"
	"os"
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

func main() {

	if len(os.Args) < 2 {
		fmt.Println("Usage: elftest elf_file")
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

	var arch string
	switch _elf.Class.String() {
	case "ELFCLASS64":
		arch = "64 bits"
	case "ELFCLASS32":
		arch = "32 bits"
	}

	var mach string
	switch _elf.Machine.String() {
	case "EM_AARCH64":
		mach = "ARM64"
	case "EM_386":
		mach = "x86"
	case "EM_X86_64":
		mach = "x86_64"
	}

	// Print info about the file
	fmt.Printf("File Header: ")
	fmt.Println(_elf.FileHeader)
	fmt.Printf("ELF Class: %s\n", arch)
	fmt.Printf("Machine: %s\n", mach)
	fmt.Printf("ELF Type: %s\n", _elf.Type)
	fmt.Printf("ELF Data: %s\n", _elf.Data)
	fmt.Printf("Entry Point: %d\n", _elf.Entry)
	fmt.Printf("Section Addresses: %v\n", _elf.Sections)

	// Process sections
	hexCollection := []string{}
	for _, v := range _elf.Sections {
		var b []byte
		if v.SectionHeader.Type != elf.SHT_NOBITS {
			b, err = v.Data()
			check(err)
		}

		if len(b) > 10 {
			sectionEntry := MapSection(b)
			if sectionEntry != "00000000000000000000" { // TODO make func to check for more than 2 consecutive zeroes
				hexCollection = append(hexCollection, sectionEntry)
			}
		}
	}

	fmt.Printf("hexCollection: %v\n", hexCollection)

}

// MapSection returns 10 bytes hex string for a []byte section
func MapSection(b []byte) string {
	return hex.EncodeToString(b[0:10])
}
