package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/miekg/dns"
)

type result struct {
	IPAddress string
	Hostname  string
}

func main() {

	var (
		flDomain      = flag.String("domain", "", "the domain to perform guessing arguments against.")
		flWordList    = flag.String("wordlist", "", "Wordlist to use for guessing")
		flWorkerCount = flag.Int("c", 100, "Amount of workers to user")
		flServerAddr  = flag.String("server", "1.1.1.1:53", "DNS server to use")
	)
	flag.Parse()
	if *flDomain == "" || *flWordList == "" {
		fmt.Println("-domain and -wordlist are required")
		os.Exit(1)
	}
	fmt.Println(*flWorkerCount, *flServerAddr)
	var results []result
	fqdns := make(chan string, *flWorkerCount)
	gather := make(chan []result)
	tracker := make(chan empty)

	fh, err := os.Open(*flWordList)
	if err != nil {
		panic(err)
	}
	defer fh.Close()
	scanner := bufio.NewScanner(fh)
	for i := 0; i < *flWorkerCount; i++ {
		go worker(tracker, fqdns, gather, *flServerAddr) // this is where all the lookup is done
	}
	go func() {
		for r := range gather {
			results = append(results, r...)
		}
		var e empty
		tracker <- e
	}()
	for scanner.Scan() {
		fqdns <- fmt.Sprintf("%s.%s", scanner.Text(), *flDomain)
	}
	close(fqdns)
	for i := 0; i < *flWorkerCount; i++ {
		<-tracker
	}
	close(gather)
	<-tracker
	w := tabwriter.NewWriter(os.Stdout, 0, 8, 4, ' ', 0)
	for _, r := range results {
		fmt.Fprintf(w, "%s\t%s\n", r.Hostname, r.IPAddress)
	}
	w.Flush()
}

func lookupA(fqdn, serverAddr string) ([]string, error) {
	var m dns.Msg
	var ips []string
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeA)
	in, err := dns.Exchange(&m, serverAddr)
	if err != nil {
		return ips, err
	}
	for _, answer := range in.Answer {
		if a, ok := answer.(*dns.A); ok {
			ips = append(ips, a.A.String())
		}
	}
	return ips, nil
}

func lookupCNAME(fqdn, serverAddr string) ([]string, error) {
	var m dns.Msg
	var fqdns []string
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeCNAME)
	in, err := dns.Exchange(&m, serverAddr)
	if err != nil {
		return fqdns, err
	}
	if len(in.Answer) < 1 {
		return fqdns, errors.New("no answer")
	}
	for _, answer := range in.Answer {
		if c, ok := answer.(*dns.CNAME); ok {
			fqdns = append(fqdns, c.Target)
		}
	}
	return fqdns, nil
}

func lookup(fqdn, serverAddr string) []result {
	var results []result
	var cfqdn = fqdn // not modifying original
	for {
		cnames, err := lookupCNAME(cfqdn, serverAddr)
		if err == nil && len(cnames) > 0 {
			cfqdn = cnames[0]
			continue // process next cname
		}
		ips, err := lookupA(cfqdn, serverAddr)
		if err != nil {
			break // no A records for this hostname
		}
		for _, ip := range ips {
			results = append(results, result{IPAddress: ip, Hostname: fqdn})
		}
		break
	}
	return results
}

type empty struct{}

func worker(tracker chan empty, fqdns chan string, gather chan []result, serverAddr string) {
	for fqdn := range fqdns {
		results := lookup(fqdn, serverAddr)
		if len(results) > 0 {
			gather <- results
		}
	}
	var e empty
	tracker <- e
}
