package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"./utils"
)

/*
	Subdomain Takeover Automation
	Created by Asjid Kalam on 08/04/2020

	Currently supported takeover checks are from the following services:
	- Amazon S3 bucket
	- Readme.io
	- GitHub Pages
	...more services will be added soon.
*/
var vulnHosts [3]string

// security checks
var tr = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	Dial: (&net.Dialer{
		Timeout:   15 * time.Second,
		KeepAlive: 15 * time.Second,
	}).Dial,
	TLSHandshakeTimeout: 10 * time.Second,
}

var client = &http.Client{
	Transport: tr,
	Timeout:   10 * time.Second,
}

//var wg sync.WaitGroup // handle sync

/*
	vulnHosts[ 0 => Amazon, 1 => GitHub Pages, 2 => Readme.io ]
*/
func checkAws(done chan bool, resp string, url string, status int) {
	if strings.Contains(resp, "NoSuchBucket") {
		fmt.Println("\n[>] Found Potential AWS S3 Takeover On", url)
		fmt.Println("[+] Status Code:", status)
		vulnHosts[0] = url
	}
	done <- true // channel for goroutine handling
}
func checkGpages(done chan bool, resp string, url string, status int) {
	if strings.Contains(resp, "There isn't a GitHub Pages site here.") {
		fmt.Println("\n[>] Found Potential GitHub Pages Takeover On", url)
		fmt.Println("[+] Status Code:", status)
		vulnHosts[1] = url
	}
	done <- true
}

func checkReadmeio(done chan bool, resp string, url string, status int) {
	if strings.Contains(resp, "Project doesnt exist... yet!") {
		fmt.Println("\n[>] Found Potential Readme.io Takeover On", url)
		fmt.Println("[+] Status Code:", status)
		vulnHosts[2] = url
	}
	done <- true
}

// this may not be the efficent way to line count
func lineCounter(r io.Reader, lineCounted chan int) {
	buf := make([]byte, 32*1024)
	count := 0
	lineSep := []byte{'\n'} // newline as separators

	for {
		c, err := r.Read(buf)
		count += bytes.Count(buf[:c], lineSep)

		switch {
		case err == io.EOF:
			lineCounted <- count

		case err != nil:
			fmt.Println("[!] Error occured: ", err)
		}
	}
}

// concurrent http requests
func MakeRequests(url string, bodyResp chan<- string, statusResp chan<- int) error {

	resp, err := client.Get(url)
	if err != nil {
		fmt.Println("[!]", err)
		return err
	}
	defer resp.Body.Close()

	// body parsing
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("[!]", err)
	}
	bodyResp <- string(bodyBytes)
	statusResp <- int(resp.StatusCode)

	//wg.Done()
	return nil
}

func main() {

	utils.Banner()

	// no verify
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	hostFile := flag.String("i", "", ">> Hosts, input file")
	outFile := flag.String("o", "", ">> Output file")
	flag.Parse()

	if *hostFile == "" {
		fmt.Println(">> Usage: ./subrecon -i <hosts.txt> -o <results.txt>")
		os.Exit(1)
	}

	if *outFile == "" {
		fmt.Println(">> Please specify the output file.")
		os.Exit(1)
	}

	var url string

	// declare unbuffered channels
	done := make(chan bool)
	lineCounted := make(chan int)
	bodyResp := make(chan string)
	statusResp := make(chan int)

	file, err := os.Open(*hostFile)
	if err != nil {
		log.Fatal("[!] Unable to read file", err)
	}
	defer file.Close()

	// create a io.Reader from the returned *os.File instance 'file'
	var reader io.Reader
	reader = file
	go lineCounter(reader, lineCounted)
	count := <-lineCounted
	running := 0
	fmt.Println("[+] Total Hosts:", count)

	// declaring file open again for Scanner
	file, err = os.Open(*hostFile)
	if err != nil {
		log.Fatal("[!] Unable to read file", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	fmt.Println("[+] Please wait..")

	// on each hosts..
	for scanner.Scan() {
		url = scanner.Text()
		if url != "" {
			// url format handling
			if !strings.Contains(url, "https://") && !strings.Contains(url, "http://") {
				url = "http://" + url
			}
			// recurent calling of gouroutines here!
			//wg.Add(1)
			go MakeRequests(url, bodyResp, statusResp)
		}
	}

	//wg.Wait()
	// close(bodyResp)
	// close(statusResp)

	// output time.
	outputFile, err := os.Create(*outFile)
	if err != nil {
		fmt.Println("[!] Error while creating output file", err)
	}
	defer outputFile.Close()

	// check for return channels.
	for i := 0; i < count; i++ {
		bodyString := <-bodyResp
		statusCode := <-statusResp

		fmt.Printf("\n[*] (%d/%d) Hosts Completed", running, count)

		// deploy goroutine for checking each services concurrently
		go checkAws(done, bodyString, url, statusCode)
		go checkGpages(done, bodyString, url, statusCode)
		go checkReadmeio(done, bodyString, url, statusCode)

		// wait for goroutines to finish
		<-done
		<-done
		<-done

		// writing
		for i := 0; i < len(vulnHosts); i++ {
			if vulnHosts[i] != "" {
				fmt.Println("Writing")
				if i == 0 {
					str := "[+] AWS: " + vulnHosts[i]
					outputFile.WriteString(str)
				}
				if i == 1 {
					str := "[+] GitHub Pages: " + vulnHosts[i]
					outputFile.WriteString(str)
				}
				if i == 2 {
					str := "[+] Readme.io: " + vulnHosts[i]
					outputFile.WriteString(str)
				}
				fmt.Println("[*] Output written to", *outFile)
			}
		}
		// GC
		for i := 0; i < len(vulnHosts); i++ {
			vulnHosts[i] = ""
		}
		running++
	}

	// we done.
	fmt.Println("\n[*] Takeover check completed.")

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}
