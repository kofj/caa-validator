package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/miekg/dns"
)

const ErrNoCAA = `Sorry, we couldn't detect any CAA records for your domain! Are you sure they were configured correctly?
If no CAA records are defined, any Certificate Authority can provide SSL/TLS certificates for your domain, without restrictions.`

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n\tcaa-validator [domain]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
}

func main() {
	detect(dns.Fqdn(flag.Arg(0)))
}

func detect(name string) {
	conn, err := dns.DialTimeout("tcp", "114.114.114.114:53", 1e8)
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
