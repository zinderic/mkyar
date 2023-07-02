package main

import (
	"crypto/md5"
	"debug/elf"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"text/template"
)

var binaryFile = os.Args[1]

type YaraData struct {
	RuleName    string
	Description string
	Author      string
	Date        string
	Hexes       []string
	Hash        string
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

// mapSection returns 10 bytes hex string for a []byte section
func mapSection(b []byte) string {
	return hex.EncodeToString(b[0:10])
}

// noZeroes returns true if there are no zeros in the string
func noZeros(s string) bool {
	return (strings.Count(s, "0") <= 1)
}

// md5HashOfFile returns md5 hash sum of a file
func md5HashOfFile(f string) (string, error) {
	file, err := os.Open(f)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hasher := md5.New()
	_, err = io.Copy(hasher, file)
	if err != nil {
		return "", err
	}
	hash := hex.EncodeToString(hasher.Sum(nil)[:])
	return hash, nil
}

// createYaraRule uses the hexes and hash of a binary file to create the Yara rule
func createYaraRule(hexes []string, hash string) error {
	tmplData := YaraData{
		RuleName:    "test_name",                       // TODO fill in with better name
		Description: "created by mkyar version v0_0_1", // TODO add version of the tool here so we know what rules were created by what version
		Author:      "mkyar",
		Date:        "2023-07-02", // TODO fill that automatically based on current date in YYYY-MM-DD format
		Hexes:       hexes,
		Hash:        hash,
	}
	template, err := template.ParseFiles("yar.tmpl")
	if err != nil {
		return err
	}
	template.Execute(os.Stdout, tmplData)
	return nil
}

func main() {

	if len(os.Args) < 2 {
		fmt.Println("Usage: mkyar <elf_file>")
		os.Exit(1)
	}
	f, err := os.Open(binaryFile)
	check(err)
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
	hash, err := md5HashOfFile(binaryFile)
	check(err)
	createYaraRule(hexCollection, hash)

}
