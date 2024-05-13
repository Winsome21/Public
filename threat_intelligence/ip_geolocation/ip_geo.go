// Package main provides a program to fetch location information for IP addresses using the ipwhois.app API.
// Usage: go run ip_geo.go <ip1,ip2,...>
// Compiled Usage: ./ip_geo <ip1,ip2,...>

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
)

// extract_location extracts the location information from the API response data.
func extract_location(data map[string]interface{}) string {
	var city, region, country string
	var latitude, longitude float64

	if val, ok := data["city"].(string); ok {
		city = val
	} else {
		city = "N/A"
	}

	if val, ok := data["region"].(string); ok {
		region = val
	} else {
		region = "N/A"
	}

	if val, ok := data["country"].(string); ok {
		country = val
	} else {
		country = "N/A"
	}

	if val, ok := data["latitude"].(float64); ok {
		latitude = val
	} else {
		latitude = 0.0
	}

	if val, ok := data["longitude"].(float64); ok {
		longitude = val
	} else {
		longitude = 0.0
	}

	return fmt.Sprintf("City: %s, Region: %s, Country: %s (Lat: %f, Long: %f)", city, region, country, latitude, longitude)
}

// request_webpage sends an HTTP GET request to the API URL for a given IP address and sends the response to a channel.
func request_webpage(url string, ip string, ch chan<- string) {
	resp, err := http.Get(url)
	if err != nil {
		ch <- fmt.Sprintf("Error fetching URL: %s", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		ch <- fmt.Sprintf("Error reading response body: %s", err)
		return
	}

	var data map[string]interface{}
	err = json.Unmarshal(body, &data)
	if err != nil {
		ch <- fmt.Sprintf("Error parsing JSON: %s", err)
		return
	}

	location := extract_location(data)
	ch <- fmt.Sprintf("IP '%s' Location: %s", ip, location)
}

// process_ips processes a slice of IP addresses concurrently and prints the location information for each IP.
func process_ips(ips []string) {
	var wg sync.WaitGroup
	ch := make(chan string)

	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			url := "https://ipwhois.app/json/" + ip
			request_webpage(url, ip, ch)
		}(ip)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	for msg := range ch {
		fmt.Println(msg)
		fmt.Println("--------------------------------------------------")
	}
}

// main is the entry point of the program.
func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run test.go <ip1,ip2,...>")
		return
	}
	process_ips(strings.Split(os.Args[1], ","))
}
