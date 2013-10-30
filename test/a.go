
package main

import (
	"github.com/go-av/radius"
	"net"
	"log"
)

func test_listen() {
	l := &radius.Listener{
		CbConn: func (addr *net.UDPAddr) (secret string, err error) {
			secret = "123456"
			return
		},
		CbPass: func (user string, checkPass func (string)bool) (pairs []radius.Pair, err error) {
			pass = "aaa"
			pairs = append(pairs, radius.Pair{
				Type: radius.FramedIP,
				Str: "1.2.2.3",
			})
			pairs = append(pairs, radius.Pair{
				Type: radius.VendorSpecific,
				Vendor: radius.VendorMikrotik,
				VendorType: radius.MikrotikRateLimit,
				Str: "200k/200k",
			})
			pairs = append(pairs, radius.Pair{
				Type: radius.SessionTimeout,
				Uint32: 23222,
			})
			return
		},
		CbAcct: func (a radius.AcctInfo) {
			return
		},
	}
	l.Listen()
}

func main() {
	err := radius.Disconnect("2013050511771", "192.168.1.90")
	log.Println(err)
}

