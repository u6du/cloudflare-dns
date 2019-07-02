//usr/bin/env go run "$0" "$@"; exit

package main

import (
	"encoding/binary"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/cloudflare/cloudflare-go"
	"github.com/pkg/errors"
	"github.com/u6du/config"
	"github.com/u6du/ex"
	"github.com/u6du/go-rfc1924/base85"
	"github.com/u6du/zerolog/info"
	"github.com/u6du/zerolog/log"
	"golang.org/x/crypto/ed25519"
)

const TimeBit = 4

// 建议放22个ipv4，加上80个字节的签名，base85编码之后正好是250字节，不超过dns txt记录的限制
func ipLiSign(bit int) func([]*net.UDPAddr, *ed25519.PrivateKey) string {

	var dump func(addr *net.UDPAddr) net.IP
	if bit == 4 {
		dump = func(addr *net.UDPAddr) net.IP {
			return addr.IP.To4()
		}
	} else {
		dump = func(addr *net.UDPAddr) net.IP {
			return addr.IP
		}
	}

	return func(li []*net.UDPAddr, private *ed25519.PrivateKey) string {
		buf := make([]byte, ed25519.SignatureSize+TimeBit+len(li)*(bit+2))
		n := ed25519.SignatureSize
		next := n + TimeBit

		binary.LittleEndian.PutUint32(buf[n:next], uint32(time.Now().Unix()/3600))

		n = next

		for i := range li {
			addr := li[i]
			next = n + bit
			copy(buf[n:next], dump(addr))
			n = next
			next = n + 2
			binary.LittleEndian.PutUint16(buf[n:next], uint16(addr.Port))
			n = next
		}

		copy(buf[0:ed25519.SignatureSize], ed25519.Sign(*private, buf[ed25519.SignatureSize:]))
		info.Msgf("%x", buf)

		return base85.EncodeToString(buf)
	}
}

var IpLiSign = map[uint8]func([]*net.UDPAddr, *ed25519.PrivateKey) string{
	4: ipLiSign(4),
	6: ipLiSign(16),
}

func main() {
	filename := Root+"/6du.sign.private"
	privateByte := config.File.Byte(filename, func() []byte {
		panic(errors.New(config.File.Path(filename) + " no exist"))
		return nil
	})
	private := ed25519.NewKeyFromSeed(privateByte)

	TxtSet(&private, 6, []string{
		"[2600:1f1c:626:9201:2ecb:6a9b:60b:a31b]:8321",
		"[ab1d:1f1c:626:9201:2ecb:1111:2222:3333]:39999",
		"[2600:1f1c:626:9201:2ecb:6a9b:60b:a31b]:8321",
		"[ab1d:1f1c:626:9201:2ecb:1111:2222:3333]:39999",
		"[2600:1f1c:626:9201:2ecb:6a9b:60b:a31b]:8321",
		"[2600:1f1c:626:9201:2ecb:6a9b:60b:a31b]:8321",
		"[ab1d:1f1c:626:9201:2ecb:1111:2222:3333]:39999",
	})

	TxtSet(&private, 4, []string{
		"178.128.56.161:80",
		"217.150.84.113:8080",
		"217.112.174.24:8080",
		"112.133.225.56:8888",
		"216.126.82.39:8080",
		"178.135.10.50:8080",
		"213.33.248.60:8080",
		"103.234.254.163:80",
		"213.163.122.196:8080",
		"178.128.21.67:8080",
		"110.44.122.85:8080",
		"121.54.164.139:8080",
		"178.128.223.158:3128",
		"212.237.5.164:8080",
		"177.85.79.216:8080",
		"103.225.228.105:58732",
		"168.0.9.108:8080",
		"212.24.47.93:8080",
		"101.78.209.62:808",
		"212.237.30.203:3128",
		"177.91.223.46:8080",
		"177.74.159.124:8080",
	})
}

var Root = "cloudflare"

func TxtSet(private *ed25519.PrivateKey, network uint8, li []string) {
	filename := Root
	emailKey := config.File.Li(filename, []string{})

	if len(emailKey) != 2 {
		panic(errors.New(config.File.Path(filename+".li") + " is empty , please write email and key one a line"))
	}

	email := emailKey[0]
	key := emailKey[1]
	info.Msg(email)
	info.Msg(key)

	sort.Strings(li)
	log.Info().Msgf("%s", li)
	info.Uint8("network", network).End()
	println("txt set len(li)", len(li))

	addrLi := make([]*net.UDPAddr, len(li))
	var err error
	for i := range li {
		addr := li[i]
		addrLi[i], err = net.ResolveUDPAddr("udp", addr)
		ex.Panic(err)
	}

	ipv4Sign := IpLiSign[network](addrLi, private)

	log.Print(ipv4Sign)
	log.Printf("sign len %d", len(ipv4Sign))

	api, err := cloudflare.New(key, email)
	ex.Panic(err)
	host := "6du.host"
	id, err := api.ZoneIDByName(host)
	ex.Panic(err)
	log.Print("id ", id)

	txtHost := string([]byte{network + 48}) + ".ip." + host

	rr := cloudflare.DNSRecord{
		Name: txtHost,
		Type: "TXT",
	}
	recLi, err := api.DNSRecords(id, rr)
	ex.Panic(err)
	rr.Content = ipv4Sign
	rr.TTL = 3600

	recLiLen := len(recLi)

	if recLiLen == 0 {
		api.CreateDNSRecord(id, rr)
	} else {
		for i := 0; i < recLiLen; i++ {
			rec := &recLi[i]
			//		api.DeleteDNSRecord(id,rec.ID)
			println(recLi[i].Name)
			println(len(rec.Content), rec.Content)
			if strings.Compare(rec.Content, rr.Content) == 0 {
				print("the same, not update")
			} else {
				api.UpdateDNSRecord(id, rec.ID, rr)
			}
		}
	}
}

/*
	var out bytes.Buffer
	w, err := lzma.Writer2Config{DictCap:64 * 1024 * 1024}.NewWriter2(&out)
	// compress text
	if err != nil {
		fmt.Printf("xz.NewWriter error %s", err)
	}
	if _, err := io.Copy(w, bytes.NewReader(buf)); err != nil {
		fmt.Printf("WriteString error %s", err)
	}
	if err := w.Close(); err != nil {
		fmt.Printf("w.Close error %s", err)
	}

	log.Printf("%x", out.Bytes())

	log.Printf("buf len %d",len(buf))

	log.Printf("out.Bytes() len %d",len(out.Bytes()))
*/
