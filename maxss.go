package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"bufio"
	"sync"
	"os/signal"
	"syscall"
)

const (
	RedColor    = "\033[31m"
	GreenColor  = "\033[32m"
	YellowColor = "\033[33m"
	BlueColor   = "\033[34m"
	ResetColor  = "\033[0m"
)

var (
	client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
)

func checkURLAllParams(targetURL string) {
	params := extractParameters(targetURL)
	for _, param := range params {
		checkURLParam(targetURL, param)
	}
}

func checkURLParam(targetURL, param string) {
	unfiltered, err := checkForUnfiltered(targetURL, param)
	if err != nil {
		return
	}

	reflected, err := checkForReflectedXSS(targetURL, param)
	if err != nil {
		return
	}

	if unfiltered {
		fmt.Printf("[%sUnfiltered%s] %s [%sParam: %s%s]\n", GreenColor, ResetColor, targetURL, YellowColor, param, ResetColor)
		return
	}

	if reflected {
		fmt.Printf("[%sReflected%s] %s [%sParam: %s%s]\n", RedColor, ResetColor, targetURL, YellowColor, param, ResetColor)
	}
}

func extractParameters(targetURL string) []string {
	parsedURL, _ := url.Parse(targetURL)
	query := parsedURL.Query()

	var params []string
	for key := range query {
		params = append(params, key)
	}

	return params
}

func checkForUnfiltered(targetURL, param string) (bool, error) {
	maliciousValue := "<maxss></maxss>"
	modifiedURL := strings.Replace(targetURL, param+"=", param+"="+url.QueryEscape(maliciousValue), 1)

	resp, err := client.Get(modifiedURL)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body := make([]byte, 8192)
	n, _ := resp.Body.Read(body)
	bodyStr := string(body[:n])

	return strings.Contains(bodyStr, maliciousValue), nil
}

func checkForReflectedXSS(targetURL, param string) (bool, error) {
	maliciousValue := "maxss"
	modifiedURL := strings.Replace(targetURL, param+"=", param+"="+url.QueryEscape(maliciousValue), 1)

	resp, err := client.Get(modifiedURL)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body := make([]byte, 8192)
	n, _ := resp.Body.Read(body)
	bodyStr := string(body[:n])

	return strings.Contains(bodyStr, maliciousValue), nil
}

func main() {
	var wg sync.WaitGroup
	concurrentWorkers := 40
	urlChan := make(chan string)

	interruptChan := make(chan os.Signal, 1)
	signal.Notify(interruptChan, syscall.SIGINT, syscall.SIGTERM)

	for i := 0; i < concurrentWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for targetURL := range urlChan {
				checkURLAllParams(targetURL)
			}
		}()
	}

	go func() {
		<-interruptChan
		fmt.Println("\n\nExit...")
		os.Exit(0)
	}()

	if len(os.Args) > 1 {
		targetURL := os.Args[1]
		urlChan <- targetURL
		close(urlChan)
	} else {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			targetURL := scanner.Text()
			urlChan <- targetURL
		}
		close(urlChan)

		if err := scanner.Err(); err != nil {
			fmt.Println("Error reading input:", err)
		}
	}

	wg.Wait()
}
