package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
)

type Params struct {
	port int
	account string
}

type requestSelectAuth struct {
	Ver      int
	NMethods int
	Methods  []int
}

type responseSelectAuth struct {
	Ver      int
	Method   int
}

type reqAuth struct {
	Ver      int
	ULen     int
	UName    string
	PLen     int
	Passwd   string
}

type respAuth struct {
	Ver      int
	status   int
}

type clientRequest struct {
	Ver      int
	Cmd      byte
	Rsv      byte
	Atyp     byte
	addr     string
	port     int
}

type serverResponse struct{
	Ver int
	Rep int

}

const (
	running = "port: [%s], Socks5 proxy running... "
	newClient = "new client: [%s]"

	socks5Ver                        = 0x05
	methodNoAuthenticationRequired   = 0x00
	usernamePassword                 = 0x02
	cmdConnect                       = 0x01
	cmdBind                          = 0x02
	cmdUdpAssociate                  = 0x03
	rsv                              = 0x00
	atypIPV4                         = 0x01
	atypDomain                       = 0x03
	atypIPV6                         = 0x04
	repSuccessed                     = 0x00
	repGeneralSOCKSServerFailure     = 0x01
	repConnectionNotAllowedByRuleset = 0x02
	repNetworkUnreachable            = 0x03
	repHostUnreachable               = 0x04
	repConnectionRefused             = 0x05
	repTTLExpired                    = 0x06
	repCommandNotSupported           = 0x07
	repAddressTypeNotSupported       = 0x08
	repUnassigned                    = 0x09
	serverResponseStatusOk           = 0x00
	serverResponseStatusFalse        = 0x01
	respAuthFail                     = 0x01
	respAuthSuccess                  = 0x00
)

func main() {
	params := getParams()
	dispatch(params)
}

func getParams() Params {

	fp  := flag.Int("p", 0, "port [默认端口:9999]")
	fup := flag.String("a", "", "a [username:password]")
	flag.Parse()

	var port = 9999
	if *fp != 0 {
		port = *fp
	}

	return Params{
		port:port,
		account:*fup,
	}
}

func dispatch(params Params) {

	//listen
	l, err := net.Listen("tcp", ":"+strconv.Itoa(params.port))
	if err != nil {
		log.Panic(err)
	}

	msg := fmt.Sprintf(running, strconv.Itoa(params.port))
	fmt.Println(msg)

	//new client
	for {
		client, err := l.Accept()
		if err != nil {
			log.Panic(err)
		}

		msg := fmt.Sprintf(newClient, client.RemoteAddr())
		fmt.Println(msg)

		go handleClientRequest(client, params)
	}
}

func handleClientRequest(client net.Conn, params Params) {

	if client == nil {
		return
	}
	defer client.Close()

	//read fist byte
	first, _ := ReadOneByte(client)
	if first == 0x00 {
		return
	}

	//socks5-proxy protocol
	//first byte is 0x05 fixed
	if first == socks5Ver {

		//coordination
		selectAuth := requestSelectAuthMethod(client)
		responseSelectAuthMethod(client, selectAuth, params)

		//auth
		if len(params.account) != 0 {
			request := requestAuth(client)
			if !responseAuth(client, request, params) {
				return
			}
		}

		//data transfer
		clientRequest := requestData(client)
		responseData(client, clientRequest)

		//server request
		server, err := net.Dial("tcp", net.JoinHostPort(clientRequest.addr, strconv.Itoa(clientRequest.port)))
		if err != nil {
			log.Println(err)
			return
		}
		defer server.Close()

		//proxy data
		go io.Copy(server, client)
		io.Copy(client, server)
	}
}

func requestAuth(client net.Conn) reqAuth {
	ver   := ReadMustByte(client)
	_ = ver
	ulen  := int(ReadMustInt8(client))
	uname := ReadStringByLen(client, ulen)
	plen  := int(ReadMustInt8(client))
	passwd:= ReadStringByLen(client, plen)

	request  := reqAuth {
		Ver: socks5Ver,
		ULen:ulen,
		UName:uname,
		PLen:plen,
		Passwd:passwd,
	}

	return request
}

func responseAuth(client net.Conn, auth reqAuth, params Params) bool {
	account := auth.UName+":"+auth.Passwd
	resp := respAuth{
		Ver:socks5Ver,
		status:respAuthSuccess,
	}
	if strings.Compare(account, params.account) != 0 {
		resp.status = respAuthFail
		client.Write([]byte{
			byte(resp.Ver),
			byte(resp.status),
		})
		return false
	}

	client.Write([]byte{
		byte(resp.Ver),
		byte(resp.status),
	})
	return true
}

func requestSelectAuthMethod(client net.Conn) requestSelectAuth {
	ver      := socks5Ver
	nMethods := int(ReadMustInt8(client))
	for i:=0; i < nMethods; i++ {
		ReadMustInt8(client)
	}

	//EOF
	ReadOneByte(client)

	request  := requestSelectAuth {
		Ver     :ver,
		NMethods:nMethods,
	}

	return request
}

func responseSelectAuthMethod(client net.Conn, requset requestSelectAuth, params Params) {

	//need username and password
	auth := methodNoAuthenticationRequired
	if len(params.account) != 0 {
		auth = usernamePassword
	}
	client.Write([]byte{
		byte(requset.Ver),
		byte(auth),
	})
}

func requestData(client net.Conn) clientRequest {

	ver := int(ReadMustInt8(client))
	cmd := ReadMustByte(client)
	rsv := ReadMustByte(client)
	atyp:= ReadMustByte(client)
	addr:= ReadMustAddr(client, atyp)
	port:= ReadMustPort(client)

	//EOF
	ReadOneByte(client)

	request := clientRequest {
		Ver:ver,
		Cmd:cmd,
		Atyp:atyp,
		Rsv:rsv,
		addr:addr,
		port:port,
	}

	return request
}

func responseData(client net.Conn, request clientRequest) {
	client.Write([]byte{
		socks5Ver,
		repSuccessed,
		rsv,
		atypIPV4,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
	})
}

func ReadMustAddr(r io.Reader, atyp byte) string {
	addr := ""
	switch atyp {
		case atypIPV4:
			addr = ReadMustIPv4(r)
		case atypDomain:
			addr = ReadString(r)
		case atypIPV6:
			addr = ReadMustIPv6(r)
	}
	return addr
}

func ReadMustIPv4(r io.Reader) string {
	var byt [4]byte
	n, err := r.Read(byt[:])
	if n != 4 || err != nil {
		panic("ReadMustIPv4 error")
	}
	return net.IPv4(byt[0], byt[1], byt[2], byt[3]).String()
}

func ReadMustIPv6(r io.Reader) string {
	var byt [16]byte
	n, err := r.Read(byt[:])
	if n != 16 || err != nil {
		panic("ReadMustIPv6 error")
	}

	return net.IP{
		byt[0], byt[1], byt[2],  byt[3],
		byt[4], byt[5], byt[6],  byt[7],
		byt[8], byt[9], byt[10], byt[11],
		byt[12],byt[13],byt[14], byt[15],
	}.String()
}

func ReadMustPort(r io.Reader) int {
	return int(ReadInt16(r))
}

func ReadString(r io.Reader) string {
	var result []byte
	var b = make([]byte, 1)
	l := int(ReadMustInt8(r))
	for i := 0; i < l; i++ {
		_, err := r.Read(b)
		if err != nil {
			panic(err)
		}
		result = append(result, b[0])
	}
	return string(result)
}

func ReadStringByLen(r io.Reader, l int) string {
	var result []byte
	var b = make([]byte, 1)
	for i := 0; i < l; i++ {
		_, err := r.Read(b)
		if err != nil {
			panic(err)
		}
		result = append(result, b[0])
	}
	return string(result)
}


func ReadInt16(r io.Reader) (n int16) {
	binary.Read(r, binary.BigEndian, &n)
	return
}

func ReadOneByte(r io.Reader) (byte, error) {
	var one [1]byte
	_, err := r.Read(one[:])

	if len(one) == 0 {
		return 0x00, nil
	}

	if err != nil || err == io.EOF || len(one) == 0 {
		return 0x00, err
	}

	return one[0], err
}

func ReadMustByte(r io.Reader) byte {
	var one [1]byte
	_, err := r.Read(one[:])
	if err != nil {
		panic("ReadMustByte error")
	}

	return one[0]
}

func ReadMustInt8(r io.Reader) (n int8) {
	err := binary.Read(r, binary.LittleEndian, &n)
	if err != nil {
		panic(err)
	}

	return n
}
