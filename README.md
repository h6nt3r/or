## This tool is make for Open Redirect checking

## Options:
```
or -h  
Open Redirect Checker. Current version 0.0.2
Developed by github.com/h6nt3r

Usage: open-redirect-checker [options]

Options:
  -u string       Single URL to test (can contain placeholder)
  -f string       File with URLs (one per line)
  -p string       Payloads file (one per line) (default "payloads.txt")
  -pl string      Placeholder text in URL (default "OREDIR")
  -t int          Per-request timeout in seconds (default 10)
  -c int          Thread concurrency number of workers (default 5)
  -d              Enable debug logging (default: false)
  -o string       Output file (plain text)
```
## Installations
```
go install -v github.com/h6nt3r/or@latest
```
## Build binary
```
git clone https://github.com/h6nt3r/or.git
cd or
go mod init main.go
go mod tidy
go build -o or main.go
sudo mv or /usr/local/bin/
cd
or -h
```