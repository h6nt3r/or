## This tool is make for Open Redirect checking

## Options:
```
or -h  
Open Redirect Checker. Current version 0.0.1
Developed by github.com/h6nt3r

Usage of or:
  -c int
    	concurrency (number of workers) (default 5)
  -d	enable debug logging (default: false)
  -f string
    	file with URLs (one per line)
  -o string
    	output file (plain text). if empty prints to stdout
  -p string
    	payloads file (one per line) (default "payloads.txt")
  -pl string
    	placeholder text in URL (default: OREDIR) (default "OREDIR")
  -t int
    	per-request timeout in seconds (default 10)
  -u string
    	single URL to test (can contain placeholder)
```