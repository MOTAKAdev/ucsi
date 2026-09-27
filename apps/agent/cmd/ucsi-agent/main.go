package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

func main() {
	server := flag.String("server", "", "approved target hostname")
	port := flag.Int("port", 443, "approved port")
	timeout := flag.Duration("timeout", 5*time.Second, "connect timeout")
	flag.Parse()
	if *server == "" {
		log.Fatal("-server is required")
	}
	ips, e := net.LookupIP(*server)
	if e != nil {
		log.Fatal(e)
	}
	for _, ip := range ips {
		c, e := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, *port), *timeout)
		if e != nil {
			fmt.Printf("%s FAILED %v\n", ip, e)
			continue
		}
		fmt.Printf("%s CONNECTED\n", ip)
		_ = c.Close()
	}
	_ = os.Stdout
}
