package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"text/template"

	"github.com/yalue/elf_reader"
)

var binaryFile = ""

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
	} else {
		binaryFile = os.Args[1]
	}
	f, err := os.ReadFile(binaryFile)
	check(err)
	_elf, err := elf_reader.ParseELFFile(f)
	check(err)

	// Process sections
	hexCollection := []string{}
	count := _elf.GetSectionCount()
	var fileContent []byte
	for i := uint16(0); i < count; i++ {
		if i == 0 {
			continue
		}
		fileContent, err = _elf.GetSectionContent(uint16(i))
		if err != nil {
			log.Printf("Failed getting section %d content: %s\n", i, err)
			continue
		}
		if len(fileContent) > 10 {
			sectionEntry := mapSection(fileContent)
			if noZeros(sectionEntry) {
				hexCollection = append(hexCollection, sectionEntry)
			}
		}
	}
	hash, err := md5HashOfFile(binaryFile)
	check(err)
	err = createYaraRule(hexCollection, hash)
	check(err)

}
