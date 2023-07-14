package main

import (
	"crypto/md5"
	"embed"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"strings"
	"text/template"
	"time"

	"github.com/yalue/elf_reader"
)

const YYYYMMDD = "2006-01-02"

var (
	binaryFile = ""
	//go:embed yar.tmpl
	tmpl embed.FS

	//go:embed version.txt
	mkyarVersion string
)

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

// mapData returns 10 bytes hex string for a []byte section
func mapData(b []byte) string {
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
	now := time.Now().UTC()
	tmplData := YaraData{
		RuleName:    "rule_" + path.Base(binaryFile),
		Description: "created by mkyar " + mkyarVersion,
		Author:      "mkyar",
		Date:        now.Format(YYYYMMDD),
		Hexes:       hexes,
		Hash:        hash,
	}
	template, err := template.ParseFS(tmpl, "yar.tmpl")
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
	err, hexCollection = collectHex(_elf)
	hash, err := md5HashOfFile(binaryFile)
	check(err)
	err = createYaraRule(hexCollection, hash)
	check(err)

}

func collectHex(_elf elf_reader.ELFFile) (error, []string) {
	var err error
	var hexCollection []string
	// Sections
	countSec := _elf.GetSectionCount()
	var fileContentSec []byte
	for i := uint16(0); i < countSec; i++ {
		if i == 0 {
			continue
		}
		fileContentSec, err = _elf.GetSectionContent(i)
		if err != nil {
			log.Printf("Failed getting section %d content: %s\n", i, err)
			continue
		}
		if len(fileContentSec) > 10 {
			sectionEntry := mapData(fileContentSec)
			if noZeros(sectionEntry) {
				hexCollection = append(hexCollection, sectionEntry)
			}
		}
	}
	// Segments
	count := _elf.GetSegmentCount()
	var fileContent []byte
	for i := uint16(0); i < count; i++ {
		if i == 0 {
			continue
		}
		fileContent, err = _elf.GetSegmentContent(i)
		if err != nil {
			log.Printf("Failed getting section %d content: %s\n", i, err)
			continue
		}
		if len(fileContent) > 10 {
			sectionEntry := mapData(fileContent)
			if noZeros(sectionEntry) {
				hexCollection = append(hexCollection, sectionEntry)
			}
		}
	}
	return nil, hexCollection
}
