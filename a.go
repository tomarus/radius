
package radius

import (
	"crypto/md5"
	"time"
	"net"
	"fmt"
	"log"
	"io"
	"os"
	"io/ioutil"
	"encoding/binary"
	"bytes"
)

const (
	UserName = PairType(1)
	UserPass = PairType(2)
	ChapPass = PairType(3)
	ChapChallenge = PairType(60)
	NasIpAddr = PairType(4)
	NasPort = PairType(5)
	ServiceType = PairType(6)
	FramedProtocol = PairType(7)
	FramedIP = PairType(8)
	NasPortTYpe = PairType(61)
	NasPortId = PairType(87)
	VendorSpecific = PairType(26)
	SessionTimeout = PairType(27)
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

	VendorMikrotik = uint32(14988)
	MikrotikRateLimit = PairType(8)

	CallingStationId = PairType(31)
	CalledStationId = PairType(30)

	AccessRequest = PacketCode(1)
	AccessAccept = PacketCode(2)
	AccessReject = PacketCode(3)
	AcctRequest = PacketCode(4)
	AcctResponse = PacketCode(5)
	DisconnectRequest = PacketCode(40)
)

type VendorCode uint32
type PacketCode byte
type PairType byte

type Pair struct {
	Type PairType
	Vendor uint32
	VendorType PairType
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
	Secret string
	inauth []byte
}

func (m *Packet) fillPassChap(id byte, pass string, random []byte) (buf []byte) {
	h := md5.New()
	h.Write([]byte{id})
	io.WriteString(h, pass)
	h.Write(random)
	return h.Sum(nil)
}

func (m *Packet) fillPass(pass string) (buf []byte) {
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
		io.WriteString(h, m.Secret)
		h.Write(vec)
		buf = append(buf, h.Sum(nil)...)
		for j := i; j < i+authLen; j++ {
			buf[j] ^= passBuf[j]
		}
		vec = buf[i:i+authLen]
	}

	return
}

func (m *Packet) encodeVendor(w io.Writer, p Pair) {
	switch p.VendorType {
	case MikrotikRateLimit:
		p.Bytes = []byte(p.Str)
	}
	w.Write([]byte{byte(p.VendorType), byte(len(p.Bytes)+2)})
	w.Write(p.Bytes)
}

func (m *Packet) Encode() (ret []byte, err error) {

	data := new(bytes.Buffer)
	var passwd string
	var padPos int // position of password blob in packet
	var padLen int // length of password blob rounded to 16 bytes
	for _, p := range m.Pairs {
		switch p.Type {
		case ServiceType, FramedProtocol,
				 SessionTimeout,
				 NasPort, NasPortTYpe, NasPortId,
				 NasIpAddr,
				 AcctStatusType, AcctSessionTime,
				 AcctInputPackets, AcctOutputPackets,
				 AcctInputOctets, AcctOutputOctets,
				 AcctInputGigawords, AcctOutputGigawords:
			b := new(bytes.Buffer)
			binary.Write(b, binary.BigEndian, p.Uint32)
			p.Bytes = b.Bytes()

		case UserName, CalledStationId, ReplyMessage, NasIdentifier:
			p.Bytes = []byte(p.Str)

		case UserPass:
			passwd = p.Str // keep for later
			padLen = (len(passwd) + 15) & (^15)
			padPos = data.Len()
			b := make([]byte, padLen)
			p.Bytes = b

		case FramedIP:
			b := make([]byte, 4)
			fmt.Sscanf(p.Str, "%d.%d.%d.%d", &b[3], &b[2], &b[1], &b[0])
			p.Bytes = b

		case VendorSpecific:
			b := new(bytes.Buffer)
			binary.Write(b, binary.BigEndian, p.Vendor)
			m.encodeVendor(b, p)
			p.Bytes = b.Bytes()

		default:
			err = fmt.Errorf("unknown pair type 0x%x", p.Type)
			return
		}

		data.WriteByte(byte(p.Type))
		data.WriteByte(byte(len(p.Bytes)+2))
		data.Write(p.Bytes)
	}

	if len(m.inauth) == 0 {
		m.inauth = make([]byte, 16)
	}

	w := new(bytes.Buffer)
	w.WriteByte(byte(m.Code))
	w.WriteByte(byte(m.Id))
	binary.Write(w, binary.BigEndian, uint16(data.Len()+20))
	w.Write(m.inauth)
	padPos += w.Len()
	w.Write(data.Bytes())
	w.Write([]byte(m.Secret))

	h := md5.New()
	h.Write(w.Bytes())
	m.Auth = h.Sum(nil)

	ret = w.Bytes()
	ret = ret[:len(ret)-len(m.Secret)]
	copy(ret[4:20], m.Auth)

	padPos +=2 // 2 for Type
	copy(ret[padPos:padPos+padLen], m.fillPass(passwd))
	return
}

func (m *Packet) Decode(in []byte) (err error) {
	var r io.Reader
	r = bytes.NewReader(in)

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
			if f, err2 := os.Create("/tmp/radius-err-pkt"); err2 != nil {
				f.Write(in)
				f.Close()
			}
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

		case UserName, NasPortId, NasIdentifier,
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

func (m *Packet) AddInt(p PairType, i uint32) {
}

func (m *Listener) handle(in *Packet, secret string, addr *net.UDPAddr) (out *Packet) {
	out = new(Packet)
	out.Id = in.Id
	out.inauth = in.Auth
	out.Secret = secret
	out.Pairs = []Pair{}

	in.Secret = secret

	userip := ""
	usermac := ""
	nasip := addr.IP.String()

	for _, p := range in.Pairs {
		switch p.Type {
		case FramedIP:
			userip = p.Str
		case CallingStationId:
			usermac = p.Str
		}
	}

	switch in.Code {
	case AccessRequest:
		out.Code = AccessReject
		name := ""
		passBuf := []byte{}
		chapPass := []byte{}
		chapChal := []byte{}

		for _, p := range in.Pairs {
			if p.Type == UserName { name = p.Str }
			if p.Type == UserPass { passBuf = p.Bytes }
			if p.Type == ChapPass { chapPass = p.Bytes }
			if p.Type == ChapChallenge { chapChal = p.Bytes }
		}

		if name == "" {
			out.Pairs = append(out.Pairs, Pair{
				Type: ReplyMessage, Str: "missing username",
			})
			return
		}

		checkPassNormal := func (pass string) bool {
			b := in.fillPass(pass)
			return bytes.Compare(b, passBuf) == 0
		}
		checkPassChap := func (pass string) bool {
			a := in.fillPassChap(chapPass[0], pass, chapChal)
			b := chapPass[1:17]
			return bytes.Compare(a, b) == 0
		}
		var checkPass func (pass string) bool
		var method string

		switch {
		case len(passBuf) != 0:
			checkPass = checkPassNormal
			method = "pap"
		case len(chapPass) == 17 && len(chapChal) > 0:
			checkPass = checkPassChap
			method = "chap"
		}

		if checkPass == nil {
			out.Pairs = append(out.Pairs, Pair{
				Type: ReplyMessage, Str: "missing password or chap password",
			})
			return
		}

		pairs, err := m.CbPass(name, checkPass, nasip, userip, usermac, method)
		if err != nil {
			out.Pairs = append(out.Pairs, Pair{
				Type: ReplyMessage, Str: fmt.Sprint(err),
			})
			return
		}
		out.Pairs = append(out.Pairs, pairs...)
		out.Code = AccessAccept
		return

	case AcctRequest:
		out.Code = AcctResponse
		info := AcctInfo{}
		info.NasIp = nasip
		info.Ip = userip
		info.Mac = usermac
		for _, p := range in.Pairs {
			switch p.Type {
			case AcctStatusType:
				info.Op = p.Uint32
			case UserName:
					info.User = p.Str
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
		m.CbAcct(info)
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
	Ip, NasIp, Mac string
	Cause uint32
}

type cbConn func (addr *net.UDPAddr) (string, error)
type cbPass func (user string, checkPass func(string)bool, nasip,userip,usermac,method string) ([]Pair, error)
type cbAcct func (info AcctInfo)

type Listener struct {
	CbConn cbConn
	CbPass cbPass
	CbAcct cbAcct
}

func Disconnect(user, nasip string) (err error) {

	var socket *net.UDPConn
	raddr := &net.UDPAddr{
		IP: net.ParseIP(nasip), Port: 3799,
	}
	log.Println("disconnect", nasip, user, raddr)

	socket, err = net.DialUDP("udp4", nil, raddr)
	if err != nil {
		return
	}

	pkt := &Packet{
		Code: DisconnectRequest,
	}
	pkt.Pairs = []Pair{
		{Type: UserName, Str: user},
	}
	var b []byte
	b, err = pkt.Encode()
	if err != nil {
		return
	}

	//log.Printf("%x\n", b)

	_, err = socket.Write(b)
	if err != nil {
		return
	}

	socket.SetReadDeadline(time.Now().Add(time.Second*5))
	rb := make([]byte, 4096)
	var read int
	read, err = socket.Read(rb)
	if err != nil {
		return
	}
	rb = rb[:read]

	pkt2 := &Packet{}
	err = pkt2.Decode(rb)
	if err != nil {
		return
	}

	return
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
		secret, err = m.CbConn(addr)
		if err != nil {
			log.Println("  reject conn:", err)
			continue
		}

		data = data[:read]
		//ioutil.WriteFile("out", data, 0777)

		pkt := new(Packet)
		err = pkt.Decode(data)
		if err != nil {
			log.Println("  decode err:", err)
			continue
		}

		out := m.handle(pkt, secret, addr)
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
	b, _ := ioutil.ReadFile("pkt_access_req")

	pkt := new(Packet)
	pkt.debug = true
	pkt.Decode(b)

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
	b, _ := ioutil.ReadFile("pkt_access_req")

	pkt := new(Packet)
	pkt.debug = true
	pkt.Decode(b)

	maxPassLen := 48
	authLen := 16

	secret := "123456"
	pkt.Secret = secret
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

