# SubRecon
Fast Subdomain Takeover Enumeration tool written in Go. It uses Golang concurrency and hence is very fast. It can easily detect potential subdomain takeovers that exist. 

## Installing

You need to have Golang installed on your machine. There are no additional requirements for this tool.

```sh
go get github.com/Asjidkalam/SubRecon
```

## Usage

` ./SubRecon -i hosts.txt -o results.txt`
- `-i` List of Subdomains
- `-o` Output/Result file
