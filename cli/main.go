package main

import (
	"fmt"
	"os"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/pflag"
)

const ErrNoCAA = `Sorry, we couldn't detect any CAA records for your domain! Are you sure they were configured correctly?
If no CAA records are defined, any Certificate Authority can provide SSL/TLS certificates for your domain, without restrictions.`
const defaultNS = "114.114.114.114:53"
const defaultTimeout = "500ms"

var ns *string
var timeout time.Duration

func init() {
	pflag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n\tcaa-validator [domain]\n", os.Args[0])
		pflag.PrintDefaults()
	}
	ns = pflag.StringP("server", "s", defaultNS, "name server")
	tmp := pflag.StringP("timeout", "t", defaultTimeout, "timeout for dial, write and read")
	pflag.Parse()

	var err error
	timeout, err = time.ParseDuration(*tmp)
	if err != nil {
		fmt.Println("parse timeout error:", err)
		os.Exit(0)
	}
	if timeout > 1e10 {
		timeout = 5e8
	}
}

func main() {
	domain := dns.Fqdn(pflag.Arg(0))
	if domain == "." {
		fmt.Println("give a domain please.")
		os.Exit(0)
	}
	detect(domain)
}

func detect(name string) {
	conn, err := dns.DialTimeout("tcp", *ns, timeout)
	if err != nil {
		fmt.Println(err)
		return
	}

	// write msg
	req := new(dns.Msg)
	req.SetQuestion(name, dns.TypeCAA)
	err = conn.WriteMsg(req)
	if err != nil {
		fmt.Println(err)
		return
	}

	// read msg
	resp, err2 := conn.ReadMsg()
	if err2 != nil {
		fmt.Println(err2)
		return
	}
	conn.Close()

	var nocaa bool
	var records string
	for k := range resp.Answer {
		rr := resp.Answer[k]
		switch rr.(type) {
		case *dns.CAA:
			caa := rr.(*dns.CAA)
			records += fmt.Sprintf("%s\t%d\tIN\t%d\t %s %s\n",
				caa.Header().Name, caa.Header().Ttl, caa.Flag, caa.Tag, caa.Value)

		default:
			nocaa = true
			break
		}
	}

	if nocaa || records == "" {
		fmt.Println(ErrNoCAA)
	} else {
		fmt.Println("CAA Raw Records:")
		fmt.Print(records)
	}

}
