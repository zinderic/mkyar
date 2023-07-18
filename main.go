package main

import (
	"crypto/md5"
	"debug/elf"
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

// splithexCollection splits a hex string into chunks of specified size.
func splithexCollection(hexStr string, chunkSize int) []string {
	var chunks []string
	for i := 0; i < len(hexStr); i += chunkSize {
		end := i + chunkSize
		if end > len(hexStr) {
			end = len(hexStr)
		}
		chunks = append(chunks, hexStr[i:end])
	}
	return chunks
}

// stringsContainZero checks if a string contains any "0" characters.
func stringsContainZero(str string) bool {
	return strings.Contains(str, "0")
}

// stringsRepeatSameCharacter checks if a string repeats the same character.
func stringsRepeatSameCharacter(str string) bool {
	for i := 1; i < len(str); i++ {
		if str[i] != str[0] {
			return false
		}
	}
	return true
}

// selectRepresentativeStrings selects unique strings from the provided slice that do not contain any "0" characters
// and do not repeat the same character.
func selectRepresentativeStrings(strings []string, count int) []string {
	var selectedStrings []string
	uniqueStrings := make(map[string]bool)

	for _, str := range strings {
		if !stringsContainZero(str) && !stringsRepeatSameCharacter(str) && !uniqueStrings[str] {
			uniqueStrings[str] = true
			selectedStrings = append(selectedStrings, str)
			if len(selectedStrings) == count {
				break
			}
		}
	}

	return selectedStrings
}

// createYaraRule uses the hexes and hash of a binary file to create the Yara rule
func createYaraRule(hexes []string, hash string) error {
	ruleName := strings.Replace(path.Base(binaryFile), ".", "_", -1)
	now := time.Now().UTC()
	tmplData := YaraData{
		RuleName:    "rule_" + ruleName,
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
	file, err := elf.Open(binaryFile)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	var hexCollection []string
	for _, section := range file.Sections {
		if section.Flags&elf.SHF_EXECINSTR != 0 {
			data, err := section.Data()
			if err != nil {
				log.Fatal(err)
			}

			hexStr := hex.EncodeToString(data)
			hexCollection = append(hexCollection, splithexCollection(hexStr, 6)...)
		}
	}

	selectedHexCollection := selectRepresentativeStrings(hexCollection, 20)
	hash, err := md5HashOfFile(binaryFile)
	check(err)
	err = createYaraRule(selectedHexCollection, hash)
	check(err)

}
