package main

// Basic radius testing of the golang radius library.
// https://github.com/tomarus/radius originally https://github.com/go-av/radius
// Sends an Accept-Request packet followed by an Accounting-Stop record.
// Tommy van Leeuwen <tommy@chiparus.org>

import (
	"flag"
	"fmt"
	"github.com/tomarus/radius"
	"log"
	"math/rand"
	"net"
	"os"
	"time"
)

var host = flag.String("host", "localhost", "Hostname of radius server.")
var port = flag.Int("port", 1812, "Portnr of radius server.")
var secret = flag.String("secret", "testing123", "Radius secret.")
var user = flag.String("user", "", "Username to test.")
var pass = flag.String("pass", "", "Password to test.")
var ip = flag.String("ip", "10.0.0.1", "Client IP to use.")

func main() {
	flag.Parse()

	if *host == "" || *user == "" || *pass == "" || *secret == "" {
		flag.Usage()
		os.Exit(0)
	}

	auth := RadiusConnect(*port)
	RadiusAuth(auth)

	acct := RadiusConnect(*port + 1)
	RadiusAcct(acct)
}

func RadiusConnect(port int) *net.UDPConn {
	udpAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", *host, port))
	if err != nil {
		log.Fatal(err)
	}

	rc, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		log.Fatal(err)
	}
	return rc
}

func RadiusAuth(rc *net.UDPConn) {
	p := new(radius.Packet)
	p.Code = radius.AccessRequest
	p.Id = byte(rand.Int() & 0xff)
	p.Secret = *secret
	p.Pairs = append(p.Pairs, radius.Pair{Type: radius.FramedIP, Str: *ip})
	p.Pairs = append(p.Pairs, radius.Pair{Type: radius.UserName, Str: *user})
	p.Pairs = append(p.Pairs, radius.Pair{Type: radius.UserPass, Str: *pass})

	RadiusSendPacket(rc, p)
}

func RadiusAcct(rc *net.UDPConn) {
	p := new(radius.Packet)
	p.Code = radius.AcctRequest
	p.Id = byte(rand.Int() & 0xff)
	p.Secret = *secret

	p.Pairs = append(p.Pairs, radius.Pair{Type: radius.FramedIP, Str: *ip})
	p.Pairs = append(p.Pairs, radius.Pair{Type: radius.UserName, Str: *user})

	p.Pairs = append(p.Pairs, radius.Pair{Type: radius.AcctStatusType, Uint32: radius.AcctStop})
	p.Pairs = append(p.Pairs, radius.Pair{Type: radius.AcctSessionTime, Uint32: 30})

	p.Pairs = append(p.Pairs, radius.Pair{Type: radius.AcctInputOctets, Uint32: 1234567})
	p.Pairs = append(p.Pairs, radius.Pair{Type: radius.AcctInputGigawords, Uint32: 2})
	p.Pairs = append(p.Pairs, radius.Pair{Type: radius.AcctInputPackets, Uint32: 12345})

	p.Pairs = append(p.Pairs, radius.Pair{Type: radius.AcctOutputOctets, Uint32: 7654321})
	p.Pairs = append(p.Pairs, radius.Pair{Type: radius.AcctOutputGigawords, Uint32: 1})
	p.Pairs = append(p.Pairs, radius.Pair{Type: radius.AcctOutputPackets, Uint32: 54321})

	RadiusSendPacket(rc, p)
}

func RadiusSendPacket(rc *net.UDPConn, p *radius.Packet) {
	pkt, err := p.Encode()
	if err != nil {
		log.Fatal(err)
	}

	_, err = rc.Write(pkt)
	if err != nil {
		log.Fatal(err)
	}

	var buf [2048]byte
	var rcv = make(chan int)
	go func(out chan int) {
		n, _ := rc.Read(buf[0:])
		out <- n
	}(rcv)
	select {
	case <-rcv:
	case <-time.After(time.Second * 5):
		log.Fatal("Radius server timeout after 5 seconds.")
	}

	response := new(radius.Packet)
	err = response.Decode(buf[:])
	if err != nil {
		log.Fatal(err)
	}
	//log.Printf("Received Radius Packet: %#v", response)

	if response.Code == radius.AccessAccept {
		log.Printf("Received Access-Accept")
		for _, p := range response.Pairs {
			if p.Type == 78 {
				log.Printf("Received Access-Accept Configuration-Token %s", p.Bytes)
			}
			if p.Type == radius.ReplyMessage {
				log.Printf("Received Access-Accept Reply-Message %s", p.Str)
			}
		}
	} else if response.Code == radius.AccessReject {
		log.Printf("Received Access-Reject")
	} else if response.Code == radius.AcctResponse {
		log.Printf("Received Acct-Response")
	}
}
