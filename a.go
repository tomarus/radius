
package main

import (
	"crypto/md5"
	"os"
	"time"
	"net"
	"fmt"
	"log"
	"io"
	"encoding/binary"
	"bytes"
)

const (
	UserName = PairType(1)
	UserPass = PairType(2)
	NasIpAddr = PairType(4)
	NasPort = PairType(5)
	ServiceType = PairType(6)
	FramedProtocol = PairType(7)
	FramedIP = PairType(8)
	NasPortTYpe = PairType(61)
	NasPortId = PairType(87)
	VendorSpecific = PairType(26)
	NasIdentifier = PairType(32)

	ReplyMessage = PairType(18)

	AcctStart = uint32(1)
	AcctStop = uint32(2)
	AcctInterim = uint32(3)

	AcctSessionId = PairType(44)
	AcctStatusType = PairType(40)
	AcctSessionTime = PairType(46)
	AcctInputOctets = PairType(42)
	AcctInputGigawords = PairType(52)
	AcctInputPackets = PairType(47)
	AcctOutputOctets = PairType(43)
	AcctOutputGigawords = PairType(53)
	AcctOutputPackets = PairType(48)
	AcctTerminateCause = PairType(40)

	CallingStationId = PairType(31)
	CalledStationId = PairType(30)

	MikrotikRateLimit = PairType(8)

	AccessRequest = PacketCode(1)
	AccessAccept = PacketCode(2)
	AccessReject = PacketCode(3)
	AcctRequest = PacketCode(4)
	AcctResponse = PacketCode(5)
)

const (
	Mikrotik = VendorCode(14988)
)

type VendorCode uint32
type PacketCode byte
type PairType byte

type Pair struct {
	Type PairType
	Bytes []byte
	Str string
	Uint32 uint32
}

type Packet struct {
	Code PacketCode
	Id byte
	Auth []byte
	Pairs []Pair
	debug bool
	secret string
	inauth []byte
}

func (m *Packet) fillPass(pass string) (buf []byte){
	maxPassLen := 48
	authLen := 16

	passLen := len(pass)
	if passLen > maxPassLen {
		passLen = maxPassLen
	}

	padLen := (passLen + (authLen-1)) & (^(authLen-1))
	passBuf := make([]byte, maxPassLen)
	copy(passBuf, []byte(pass))

	vec := m.Auth
	for i := 0; i < padLen; i += authLen {
		h := md5.New()
		io.WriteString(h, m.secret)
		h.Write(vec)
		buf = append(buf, h.Sum(nil)...)
		for j := i; j < i+authLen; j++ {
			buf[j] ^= passBuf[j]
		}
		vec = buf[i:i+authLen]
	}

	return
}

func (m *Packet) Encode() (ret []byte, err error) {

	data := new(bytes.Buffer)
	for _, p := range m.Pairs {
		switch p.Type {
		case ServiceType, FramedProtocol,
				 NasPort, NasPortTYpe, NasPortId,
				 NasIpAddr:
			b := new(bytes.Buffer)
			binary.Write(b, binary.BigEndian, p.Uint32)
			p.Bytes = b.Bytes()

		case UserName, CalledStationId, ReplyMessage:
			p.Bytes = []byte(p.Str)

		default:
			err = fmt.Errorf("unknown pair type 0x%x", p.Type)
			return
		}

		data.WriteByte(byte(p.Type))
		data.WriteByte(byte(len(p.Bytes)+2))
		data.Write(p.Bytes)
	}

	w := new(bytes.Buffer)
	w.WriteByte(byte(m.Code))
	w.WriteByte(byte(m.Id))
	binary.Write(w, binary.BigEndian, uint16(data.Len()+20))
	w.Write(m.inauth)
	w.Write(data.Bytes())
	w.Write([]byte(m.secret))

	h := md5.New()
	h.Write(w.Bytes())
	m.Auth = h.Sum(nil)

	ret = w.Bytes()
	ret = ret[:len(ret)-len(m.secret)]
	copy(ret[4:20], m.Auth)

	return
}

func (m *Packet) Decode(r io.Reader) (err error) {
	err = binary.Read(r, binary.BigEndian, &m.Code)
	if err != nil {
		return
	}

	err = binary.Read(r, binary.BigEndian, &m.Id)
	if err != nil {
		return
	}

	var l16 uint16
	err = binary.Read(r, binary.BigEndian, &l16)
	l16 -= 4
	r = io.LimitReader(r, int64(l16))

	if m.debug { log.Println("len", l16) }

	m.Auth = make([]byte, 16)
	_, err = r.Read(m.Auth)
	if err != nil {
		return
	}

	m.Pairs = []Pair{}
	for i := 0; i < 1024; i++ {
		p := Pair{}

		err = binary.Read(r, binary.BigEndian, &p.Type)
		if err != nil {
			break
		}

		var l8 byte
		err = binary.Read(r, binary.BigEndian, &l8)
		if err != nil {
			break
		}

		if m.debug { log.Printf("pair %x %d\n", p.Type, l8) }

		plen := int(l8)-2
		if plen <= 0 {
			err = fmt.Errorf("pair len < 0")
			return
		}

		p.Bytes = make([]byte, plen)
		_, err = r.Read(p.Bytes)
		if err != nil {
			break
		}

		br := bytes.NewReader(p.Bytes)

		switch p.Type {

		case ServiceType, FramedProtocol,
				 NasPort, NasPortTYpe,
				 AcctStatusType,
				 AcctSessionTime,
				 AcctInputPackets, AcctOutputPackets,
				 AcctInputOctets, AcctOutputOctets,
				 AcctInputGigawords, AcctOutputGigawords:
			err = binary.Read(br, binary.BigEndian, &p.Uint32)
			if err != nil {
				return
			}

		case NasIpAddr, FramedIP:
			if len(p.Bytes) != 4 {
				err = fmt.Errorf("ip addr not 4 bytes")
				return
			}
			p.Str = fmt.Sprintf("%d.%d.%d.%d", p.Bytes[0], p.Bytes[1], p.Bytes[2], p.Bytes[3])

		case UserName, NasPortId,
				 CalledStationId, CallingStationId,
				 ReplyMessage:
			p.Str = string(p.Bytes)

		}

		m.Pairs = append(m.Pairs, p)
	}

	if err == io.EOF {
		err = nil
	}

	return
}

func (m *Listener) handle(in *Packet, secret string) (out *Packet) {
	out = new(Packet)
	out.Id = in.Id
	out.inauth = in.Auth
	out.secret = secret
	out.Pairs = []Pair{}

	in.secret = secret

	switch in.Code {
	case AccessRequest:
		out.Code = AccessReject
		name := ""
		passBuf := []byte{}

		for _, p := range in.Pairs {
			if p.Type == UserName { name = p.Str }
			if p.Type == UserPass { passBuf = p.Bytes }
		}
		if name == "" {
			out.Pairs = append(out.Pairs, Pair{
				Type: ReplyMessage, Str: "missing username",
			})
			return
		}
		if len(passBuf) == 0 {
			out.Pairs = append(out.Pairs, Pair{
				Type: ReplyMessage, Str: "missing password",
			})
			return
		}
		pass, err := m.cbPass(name)
		if err != nil {
			out.Pairs = append(out.Pairs, Pair{
				Type: ReplyMessage, Str: fmt.Sprint(err),
			})
			return
		}
		calcPass:= in.fillPass(pass)
		if bytes.Compare(calcPass, passBuf) != 0 {
			out.Pairs = append(out.Pairs, Pair{
				Type: ReplyMessage, Str: "password invalid",
			})
			return
		}
		out.Code = AccessAccept
		return

	case AcctRequest:
		out.Code = AcctResponse
		info := AcctInfo{}
		for _, p := range in.Pairs {
			switch p.Type {
			case AcctStatusType:
				info.Op = p.Uint32
			case UserName:
					info.User = p.Str
			case FramedIP:
				info.Ip = p.Str
			case CallingStationId:
				info.Mac = p.Str
			case AcctInputPackets:
				info.InPkts += uint64(p.Uint32)
			case AcctOutputPackets:
				info.OutPkts += uint64(p.Uint32)
			case AcctInputOctets:
				info.InBytes += uint64(p.Uint32)
			case AcctOutputOctets:
				info.OutBytes += uint64(p.Uint32)
			case AcctInputGigawords:
				info.InBytes += uint64(p.Uint32)<<30
			case AcctOutputGigawords:
				info.OutBytes += uint64(p.Uint32)<<30
			case AcctSessionTime:
				info.Dur = time.Second*time.Duration(p.Uint32)
			}
		}
		m.cbAcct(info)
		return
	}

	out = nil
	return
}

type AcctInfo struct {
	Op uint32
	InBytes,OutBytes uint64
	InPkts,OutPkts uint64
	User string
	Dur time.Duration
	Ip, Mac string
	Cause uint32
}

type cbConn func (addr *net.UDPAddr) (string, error)
type cbPass func (user string) (string, error)
type cbAcct func (info AcctInfo)

type Listener struct {
	cbConn
	cbPass
	cbAcct
}

func (m *Listener) listen(port int) {

	log.Printf("listen :%d\n", port)

	socket, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP:   net.IPv4(0, 0, 0, 0),
		Port: port,
	})
	if err != nil {
		log.Println(err)
		return
	}
	defer socket.Close()


	for {
		data := make([]byte, 4096)
		read, addr, err := socket.ReadFromUDP(data)
		if err != nil {
			log.Println("readudp:", err)
			continue
		}
		log.Printf("<< %v %d\n", addr, read)

		var secret string
		secret, err = m.cbConn(addr)
		if err != nil {
			log.Println("  reject conn:", err)
			continue
		}

		data = data[:read]
		//ioutil.WriteFile("out", data, 0777)

		pkt := new(Packet)
		br := bytes.NewReader(data)
		err = pkt.Decode(br)
		if err != nil {
			log.Println("  decode err:", err)
			continue
		}

		out := m.handle(pkt, secret)
		if out != nil {
			if ret, err := out.Encode(); err != nil {
				log.Println("  outpkt encode err:", err)
			} else {
				log.Printf(">> %v %v\n", addr, len(ret))
				socket.WriteToUDP(ret, addr)
			}
		}
	}
}

func (m *Listener) Listen() {
	go m.listen(1812)
	go m.listen(1813)
}

func debug_access_req() {
	f, _ := os.Open("pkt_access_req")
	pkt := new(Packet)
	pkt.debug = true
	pkt.Decode(f)

	for _, p := range pkt.Pairs {
		if p.Type == UserName {
			log.Println("username", p.Str)
		}
		if p.Type == UserPass {
			log.Println("userpass", p.Bytes)
		}
	}
}

func test_password() {
	f, _ := os.Open("pkt_access_req")
	pkt := new(Packet)
	pkt.debug = true
	pkt.Decode(f)

	maxPassLen := 48
	authLen := 16

	secret := "123456"
	pkt.secret = secret
	pass := "aaa"

	passLen := len(pass)
	if passLen > maxPassLen {
		passLen = maxPassLen
	}

	padLen := (passLen + (authLen-1)) & (^(authLen-1))
	passBuf := make([]byte, maxPassLen)
	copy(passBuf, []byte(pass))

	log.Println(padLen)

	buf := []byte{}
	vec := pkt.Auth
	for i := 0; i < padLen; i += authLen {
		h := md5.New()
		io.WriteString(h, secret)
		h.Write(vec)
		buf = append(buf, h.Sum(nil)...)
		for j := i; j < i+authLen; j++ {
			buf[j] ^= passBuf[j]
		}
		vec = buf[i:i+authLen]
	}

	for _, p := range pkt.Pairs {
		if p.Type == UserPass {
			log.Printf("hispass %x\n", p.Bytes)
		}
	}
	log.Printf("mypass  %x\n", buf)
	log.Printf("mypas2  %x\n", pkt.fillPass(pass))
}

func main() {
	lis := &Listener{
		cbConn: func (addr *net.UDPAddr) (secret string, err error) {
			return "123456", nil
		},
		cbPass: func (user string) (pass string, err error) {
			return "aaa", nil
		},
		cbAcct: func (info AcctInfo) {
			log.Println("acct", info)
		},
	}

	lis.Listen()

	for {
		time.Sleep(time.Second)
	}

	//test_password()
}

