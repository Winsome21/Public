package main

// The purpose of this script is to query VirusTotal for other file hashes based
// on a list of hashes provided in a file. Let's say you have threat intelligence report
// with a list of SHA1 hashes, but you need MD5 or SHA256 hashes.
// This script will return the MD5, SHA1, and SHA256 hashes for a given hash
// assuming the file is in VirusTotal.
//
// Usage: go run vt_hash_puller.go -file hashes.txt -output output.csv
//        (or if compiled: ./vt_hash_puller -file hashes.txt -output output.csv)
//
// Hashes file should contain one hash per line.

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sync"

	"golang.org/x/term"
)

const vtURL = "https://www.virustotal.com/api/v3/files"

// Regular expression pattern to validate the hash format
var hashRegex = regexp.MustCompile(`^([a-fA-F0-9]{32}|[a-fA-F0-9]{48}|[a-fA-F0-9]{64})$`)

// Struct to hold the response data from VirusTotal API
type ResponseData struct {
	Attributes struct {
		MD5    string `json:"md5"`
		SHA1   string `json:"sha1"`
		SHA256 string `json:"sha256"`
	} `json:"attributes"`
}

// Struct to hold the complete response from VirusTotal API
type Response struct {
	Data ResponseData `json:"data"`
}

func main() {
	var apikey, file, output string
	var concurrentLimit int
	flag.StringVar(&apikey, "apikey", "", "VirusTotal API key")
	flag.StringVar(&file, "file", "", "File containing hashes to query (required)")
	flag.StringVar(&output, "output", "", "Output file (required)")
	flag.IntVar(&concurrentLimit, "concurrency", 50, "Concurrency limit")
	flag.Parse()

	if file == "" || output == "" {
		fmt.Println("file and output are required parameters.")
		return
	}

	if apikey == "" {
		// Read the VirusTotal API key from the terminal
		apikey = readAPIKeyFromTerminal()
	}

	// Read hashes from the input file
	hashes, err := readHashes(file)
	if err != nil {
		fmt.Println("Error reading hashes:", err)
		return
	}

	// Create a semaphore to limit the number of concurrent requests
	sem := make(chan struct{}, concurrentLimit)
	client := &http.Client{}

	var wg sync.WaitGroup
	hashList := make([][]string, 0, len(hashes))

	// Iterate over the hashes and fetch their MD5, SHA1, and SHA256 hashes from VirusTotal
	for _, hash := range hashes {
		wg.Add(1)
		go func(hash string) {
			sem <- struct{}{}        // Acquire semaphore
			defer func() { <-sem }() // Release semaphore
			defer wg.Done()

			// Validate the hash format
			if hashRegex.MatchString(hash) {
				url := fmt.Sprintf("%s/%s", vtURL, hash)
				response, err := fetch(url, apikey, client)
				if err == nil && response.Data.Attributes.MD5 != "" && response.Data.Attributes.SHA1 != "" && response.Data.Attributes.SHA256 != "" {
					hashList = append(hashList, []string{response.Data.Attributes.MD5, response.Data.Attributes.SHA1, response.Data.Attributes.SHA256})
				}
			} else {
				fmt.Println("Invalid hash:", hash)
			}
		}(hash)
	}

	// Wait for all goroutines to complete
	wg.Wait()

	// Write the results to a CSV file
	err = writeCSV(output, hashList)
	if err != nil {
		fmt.Println("Error writing CSV:", err)
	}
}

// Function to read the VirusTotal API key from the terminal
func readAPIKeyFromTerminal() string {
	fmt.Print("Enter VirusTotal API key: ")
	apikeyBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Println("Error reading API key:", err)
		return ""
	}
	fmt.Println()
	return string(apikeyBytes)
}

// Function to read hashes from the input file
func readHashes(fileName string) ([]string, error) {
	file, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

// Function to fetch the response from VirusTotal API
func fetch(url string, apikey string, client *http.Client) (*Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Apikey", apikey)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var response Response
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

// Function to write the results to a CSV file
func writeCSV(fileName string, records [][]string) error {
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"md5", "sha1", "sha256"})
	for _, record := range records {
		writer.Write(record)
	}

	return nil
}
