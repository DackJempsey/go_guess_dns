# Go Guess DNS
Simple DNS subdomain enumeration.

## Usage
### docker
`docker build -t go_gues_dns` \
`docker run -it --rm --name go_guess_dns go_guess_dns`
### bare metal
`go build .` \
`go run . -wordlist 100names.txt -domain <domain.A>`
### Good word lists
https://github.com/danielmiessler/SecLists

## Example output
```
ns3.google.com        216.239.36.10
mail.google.com       142.251.40.165
```


Built from the book: [Black Hat Go](https://nostarch.com/blackhatgo)
