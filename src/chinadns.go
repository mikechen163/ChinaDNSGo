package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/miekg/dns"
	"io"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"encoding/base64"
	"io/ioutil"
	"net/http"
	
	"sync"
	"bytes"

	"my_aes"
)

type routeIp struct {
	Ip    string
	IpInt uint32
	mask  uint32
}

type RouteList struct {
	r []routeIp
}

type ByIp []routeIp

func (ip ByIp) Len() int      { return len(ip) }
func (ip ByIp) Swap(i, j int) { ip[i], ip[j] = ip[j], ip[i] }

// big ... small
func (ip ByIp) Less(i, j int) bool { return ip[i].IpInt > ip[j].IpInt }

func strIp2Int(ipstr string) (uint32, error) {

	l := 0
	ip := uint32(0)
	for {
		pos := strings.Index(ipstr, ".")
		if pos == -1 {
			pos = len(ipstr)
		}
		b, _ := strconv.Atoi(string([]byte(ipstr[:pos])))
		ip <<= 8
		ip |= uint32(b)
		l++
		if len(ipstr) == pos {
			break
		}
		ipstr = string([]byte(ipstr[pos+1:]))
	}

	if l != 4 {
		return 0, fmt.Errorf("ip format must is xxx.xxx.xxx.xxx")
	}

	return ip, nil
}

func format_domain_name(s string) string{
	str := strings.Trim(s, " ")
	//str := strings.Trim(s2, ".lan")

    
   
	count2 := strings.Count(str,".")

	 if count2 == 0 {
   	return ""
   }

   if count2 == 1 {
   	return str
   }
   
     if count2 == 2 {
     	if strings.HasPrefix(str,"www") || strings.HasPrefix(str,"blog") || strings.HasSuffix(str,"com") || strings.HasSuffix(str,"net")  {
            nstr := strings.Split(str,".")
            return nstr[1]+"."+nstr[2]
     	}
     }

     if strings.HasSuffix(str,"com") || strings.HasSuffix(str,"net")   {
             nstr := strings.Split(str,".")
             len2 := len(nstr) 
             return nstr[len2-3]+"."+nstr[len2-2]+"."+nstr[len2-1]

      }





         //if count2 > 1 {
        //fmt.Println(str)
        //}
        return str
}

func read_china_domain() map[string]int{
	f, err := os.Open("cn.txt")
	if err != nil {
		log.Printf("ERROR: open %s fail:%v\n", "cn.txt")
		return nil
	}
	defer f.Close()

	r := bufio.NewReader(f)

	var m map[string]int
	m = make(map[string]int)

	//var buffer bytes.Buffer

	for {
		 str , e := r.ReadString(' ')
		if e == io.EOF {
			break
		}

		if e != nil {
			log.Printf("ERROR: read  fail:%v\n", e)
			return nil
		}
         

         //buffer.WriteString(c)]
         ns := format_domain_name(str)     
        
         m[ns] = 1
		//log.Printf("%s\n", domain)
	} //end for

	 // for key, value := range m {
  //    //fmt.Println("Key:", key, "Value:", value)
  //    fmt.Printf("%v %v %v\n",key, m[key], value)
  //    }
	

     //fmt.Println( []byte("xueqiu.com"))

	// v1 := m["xueqiu.com"]
	// fmt.Printf("%v\n",m["xueqiu.com"])
 //    if 1 == v1 {
 //    	fmt.Printf("success1\n")
 //    }

 //     v2 := m["google.com"]
 //     fmt.Printf("%v\n",v2)
 //    if 1 != v2 {
 //    	fmt.Printf("success2\n")
 //    }
   

    return m

}

func newRouteList(fname string) *RouteList {
	f, err := os.Open(fname)
	if err != nil {
		log.Printf("ERROR: open %s fail:%v\n", fname)
		return nil
	}
	defer f.Close()
	r := bufio.NewReader(f)

	list := &RouteList{}
	lineno := 0
	for {
		line, e := r.ReadString('\n')
		if e == io.EOF {
			break
		}

		if e != nil {
			log.Printf("ERROR: read line fail:%v\n", e)
			return nil
		}

		lineno++
		ls := strings.Split(line, "/")
		if len(ls) != 2 {
			log.Printf("WARN: line format is ip/mask")
			continue
		}
		//log.Printf("line is (%s):first(%s) second(%s)\n", line, ls[0], ls[1])

		ipint, err := strIp2Int(ls[0])
		if err != nil {
			log.Printf("WARN: invalid addr %s in %s:%d:%v\n", ls[0], lineno, ipint)
			continue
		}

		maskBytes := []byte(ls[1])
		if maskBytes[len(maskBytes)-1] == '\n' {
			maskBytes = maskBytes[:len(maskBytes)-1]
		}
		if maskBytes[len(maskBytes)-1] == '\r' {
			maskBytes = maskBytes[:len(maskBytes)-1]
		}
		m, err := strconv.Atoi(string(maskBytes))
		if err != nil {
			log.Printf("WARN: invalid mask %s in %s:%d\n", m, ls[1], err)
			continue
		}

		mask := ^(^(uint32(0)) >> uint32(m))

		//log.Printf("line:%v  %v:%v %x %x %x  \n",lineno, ls[0],m, ipint,mask, ipint&mask)

		list.r = append(list.r, routeIp{
			Ip:    string(ls[0]),
			IpInt: ipint,
			mask:  mask})
	}

	sort.Sort(ByIp(list.r))

	return list
}

func (r *RouteList) testIpInList(ip uint32) bool {
	//  data := []int{60, 58, 52, 50, 48, 40, 30, 20, 10}
	//  n := sort.Search(len(data), func(i int) bool {
	//      return data[i] < 51
	//  })
	// out 3

	n := sort.Search(len(r.r), func(i int) bool {
		return r.r[i].IpInt < ip
	})

	//fmt.Println(r.r[n])
	//log.Printf("ip = %x, item = %v %x %x \n", ip,r.r[n].Ip,r.r[n].IpInt,r.r[n].mask )

	if n < len(r.r) {
		route := r.r[n]
		if (route.mask & ip) == route.IpInt {
			return true
		}
	}
	return false
}

func TestnewRouteList() {
	chnroute_file := flag.String("c", "/etc/chinadns/chnroute.txt", "china route list")

	r := newRouteList(*chnroute_file)

	n, _ := strIp2Int("1.0.1.1")
	log.Printf("%v\n", r.testIpInList(n))

	n, _ = strIp2Int("1.0.1.3")
	log.Printf("%v\n", r.testIpInList(n))

	n, _ = strIp2Int("118.27.3.4")
	log.Printf("%v\n", r.testIpInList(n))

	n, _ = strIp2Int("93.46.8.89")
	log.Printf("%v\n", r.testIpInList(n))
}


const MAX_BUFF int = 100
const BUFF_SIZE int = 512
type chinaDNS struct {
	route *RouteList
	sa    string
}

type SafeInt struct {
	sync.Mutex
	Num int
}

var g_pos SafeInt
var gbuffer [MAX_BUFF][]byte
var gmap map[string]int
var gkeyword [2]string

func newChinaDNS(fname string, sa string) *chinaDNS {
	c := new(chinaDNS)
      
    g_pos.Num = 0 
    
    for i := 0; i < MAX_BUFF; i++ {
    	gbuffer[i] = make([]byte, BUFF_SIZE)

    	for j := 0; j< 100; j++ {
        memsetRepeat(gbuffer[i], 0)
        }
    }

    gkeyword[0] ="googleads.g.doubleclick.net" 
    gkeyword[1] = "adservice.google.com"
    

    gmap = read_china_domain()

	c.route = newRouteList(fname)
	if c.route == nil {
		return nil
	}

	c.sa = sa
	return c
}

func get_next_buff(url string) []byte {

    g_pos.Lock()
    log.Printf("url = %s, buffer pos = %d\n", url,g_pos.Num)
    old_pos := g_pos.Num
			g_pos.Num += 1 
            if g_pos.Num == MAX_BUFF {
               g_pos.Num = 0

            }

       g_pos.Unlock()
     return gbuffer[old_pos]
}

var dnsAddr []string
var in_key string
var out_key string
var out_ip string
var dohserver string

func init() {
	//dnsAddr = strings.Split("180.76.76.76,182.254.116.116,208.67.222.222:443,192.168.8.1", ",")
	dnsAddr = strings.Split("180.76.76.76,119.29.29.29,208.67.222.222:443,192.168.8.1", ",")
	in_key = ""
	out_key = ""
	out_ip = ""
}

type dnsPacket struct {
	dnsType     string
	packet      []byte
	debugString string
}

func getIp(s string) (uint32, error) {
	a := strings.Split(s, "\t")
	ipStr := a[len(a)-1]
	ip, err := strIp2Int(ipStr)
	if err != nil {
		return 0, fmt.Errorf("ip is %s:%s", ipStr, err)
	}
	return ip, nil
}

func getName(s string) string {
	a := strings.Split(s, "\t")
	ipStr := a[0]
	return ipStr
}

func getIpString(s string) string {
	a := strings.Split(s, "\t")
	ipStr := a[len(a)-1]
	return ipStr
}

func getParameter(localBuf []byte) string {

    //return string(localBuf)
	//var buffer bytes.Buffer
	//
	//
	len2 := len(localBuf)
	if len2 == 0 {
		return ""
	}


	var s bytes.Buffer
	//s := ""
	i := 0

    //len2 = len(localBuf)
	//log.Printf(" %v", localBuf[0..len-1])

	//len := len(localBuf)
	for {

		

		if  (i > (len2 -1)) {
			return s.String()
		}

		c := localBuf[i]


		if  (c == 0) {
			return s.String()
		}

		printable := false
		if (c >= 'a') && (c <= 'z') {
			printable = true
		}
		if (c >= 'A') && (c <= 'Z') {
			printable = true
		}
		if (c >= '1') && (c <= '9') {
			printable = true
		}

		if (c == '-') || (c == '_') || (c == '.') {
			printable = true
		}

		tc := string(c)
		if printable == false {
			tc = "."
			//if c != "." { //other char is invalid
				//return s.String()
			//}
		}

		//s = s + tc
		s.WriteString(tc)
		i = i + 1

	}

	return s.String()

}

func proxy(dohserver string, conn *net.UDPConn, addr *net.UDPAddr, raw []byte) {
	enc := base64.RawURLEncoding.EncodeToString(raw)
	//log.Printf("dohserver: %s %v", dohserver,getParameter(raw[13:]))
	url := fmt.Sprintf("%s?dns=%s", dohserver, enc)
	r, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		log.Printf("could not create request: %s", err)
		return
	}
	r.Header.Set("Content-Type", "application/dns-message")
	r.Header.Set("Accept", "application/dns-message")

    //log.Printf("starting...")
    //now := time.Now()
    //sec := now.Unix()
	c := http.Client{}
	resp, err := c.Do(r)
	if err != nil {
		log.Printf("could not perform request: %s", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("wrong response from DOH server got %s", http.StatusText(resp.StatusCode))
		return
	}

	msg, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("could not read message from response: %s", err)
		return
	}

    //nnow := time.Now()
    //log.Printf("Take %d seconds" ,nnow.Unix() - sec)
	if _, err := conn.WriteToUDP(msg, addr); err != nil {
		log.Printf("could not write to udp connection: %s", err)
		return
	}

	
}

func (c chinaDNS) selectPacket(conn *net.UDPConn, remoteAddr *net.UDPAddr, localBuf []byte, size int) {

	inputPara := getParameter(localBuf[13:])
	//log.Printf("query site : %v", inputPara)

	//packet := make(chan dnsPacket, len(dnsAddr))
	//timeout := make(chan bool, 1)

     var send_ok int
     send_ok = 0

     len2 := len(localBuf)
     if len2 == 0 {
     	return
     }

     //for _, dnsA := range dnsAddr {
     //	log.Printf("dns server address: %v", dnsA)
     //}

	for _, dnsA := range dnsAddr {

		go func(dnsA string) {
			pos := strings.Index(dnsA, ":")
			dnsB := dnsA
			if pos == -1 {
				dnsA += ":53"
			} else {
				dnsB = dnsA[:pos]
			}

			// if (dnsB == "127.0.0.1") {
			// 	if c.sa == ":5300" {
			// 		return
			// 	}
			// }

			//ti, err := strIp2Int(dnsB)
			//is_chn_dns_server := c.route.testIpInList(ti)

			is_chn_dns_server := true

			addr, err := net.ResolveUDPAddr("udp", dnsA)
			if err != nil {
				log.Printf("Can't resolve address: %v", err)
				return
			}

			cliConn, err := net.DialUDP("udp", nil, addr)
			if err != nil {
				log.Printf("Can't dial: ", err)
				return
			}
			defer cliConn.Close()

			if dnsB == out_ip {
				if out_key != "" {
					key := []byte(out_key)
					//log.Printf("size before ciph %d\n", len(localBuf))
					//encrypt will add 16 byte padding byte
					localBuf, err = my_aes.AesEncrypt(localBuf[:1008], key)
					//log.Printf("size after ciph %d\n", len(localBuf))
					if err != nil {
						panic(err)
					}
				}
			}

			// todo set timeout
			_, err = cliConn.Write(localBuf[:size])
			remoteBuf := get_next_buff(inputPara)
            
			cliConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err = cliConn.Read(remoteBuf)
			if err != nil {
				//log.Printf("read udp fail: %s %v\n",inputPara, err)
				return
			}

            //just return
			conn.WriteToUDP(remoteBuf,remoteAddr)
			return 

            //do not any work 
			m := new(dns.Msg)
			err = m.Unpack(remoteBuf)
			if err != nil {
				log.Printf("ERROR: dns server addr is (%s) errmsg is (%s)\n", dnsA, err)
				return
			}

			if len(m.Answer) == 0 {
				//log.Printf("WARN: answer size is 0 from %s for %s \n",dnsA,inputPara)
				return
			}

			flag := false
			debugString := ""
			isCname := true
			for i, v := range m.Answer {

				debugString = "Server:" + dnsA + " | " + inputPara + "->" + getIpString(v.String())

				ip, err := getIp(v.String())
				if err != nil {

					//log.Printf("ERROR: get ip error:%s:String(%s)\n", err, v.String())

					continue
				}

				isCname = false

				//debugString = "Server:" + dnsA + " | "+inputPara +  "->" + getIpString(v.String())
				//log.Printf("##%d##(server :%#v) (result :%#v %#v)\n", i, dnsA, getName(v.String()),getIpString(v.String()) )
				if flag == false {
					if flag = c.route.testIpInList(ip); flag == true {

						break
					}
				}

				if i > 2 {

				}
			}


			if isCname == true {
						//packet <- dnsPacket{"cname", remoteBuf, debugString}

						conn.WriteToUDP(remoteBuf,remoteAddr)
			} else {

			if flag {
				// this is a china ip

				// if (dnsAddr[0] == dnsB) || (dnsAddr[1] == dnsB) {
				//   packet <- dnsPacket{"chinese", remoteBuf, debugString}
				//    }

				//    if ((dnsAddr[2] == dnsB) || (dnsAddr[3] == dnsB)){
				//   packet <- dnsPacket{"chinese", remoteBuf, debugString}
				//    }
				//if is_chn_dns_server {
				//	packet <- dnsPacket{"chinese", remoteBuf, debugString}
				//} else {
					//log.Printf("ignore chn ip %v\n", debugString)

				//	packet <- dnsPacket{"chinese", remoteBuf, debugString}
				//}

				//packet <- dnsPacket{"chinese", remoteBuf, debugString}
				conn.WriteToUDP(remoteBuf,remoteAddr)

			} else {

				// this is not a china ip

				if is_chn_dns_server == true {
					// only process domestic dns return CNAME case. ignore Class A case
					//if isCname == true {
					//	packet <- dnsPacket{"cname", remoteBuf, debugString}
					//} else {
					//
					
					if strings.Contains(debugString, "apple.com") {
						//packet <- dnsPacket{"apple", remoteBuf, debugString}
						conn.WriteToUDP(remoteBuf,remoteAddr)
					} else {
						//log.Printf("ignore oversea ip %v\n", debugString)
						//
						if (0 == send_ok) {
						   // proxy(dohserver, conn, remoteAddr, localBuf[:size])
						   send_ok += 1
					    }
					}
					

				    
					//}

				} else {

					//if isCname == true {
					//	packet <- dnsPacket{"cname", remoteBuf, debugString}
					//} else {
						//packet <- dnsPacket{"oversea", remoteBuf, debugString}
						conn.WriteToUDP(remoteBuf,remoteAddr)
					//}
				}
			}

		    }
		}(dnsA)
	}

	//go func() {
	// 	time.Sleep(time.Second * 5)
		
	//}()

	// 	p := dnsPacket{}
	// 	select {

	// 	case p = <-packet:

	// 		log.Printf("[%s] %s\n", p.dnsType, p.debugString)

	// 		conn.WriteToUDP(p.packet, remoteAddr)

	// 		return

	// 	case <-timeout:
	// 		log.Printf("Query %s timeout!\n", inputPara)
	// 		return
	// 	}

}

//gkeyword :=["googleads.g.doubleclick.net","adservice.google.com"]

func deal_tail_lan(b []byte,n int) bool {
	//fmt.Println("size = %d, %v %d ", n,localBuf,localBuf[n-4])
    //str := string(localBuf[13:])
     //fmt.Println("DEAL:   localbuf ", str)
     // if strings.HasSuffix(str,"lan"){
     // 	fmt.Println("size = %d, %v  ", n,localBuf)
     // 	localBuf[n-4] = 0
     // }
    //fmt.Println("size = %d, | %d %d %d %d | %v", n,localbuf[n-4],localbuf[n-3],localbuf[n-2],localbuf[n-1],localbuf[:n]) 
    
    if (b[n-9] == 3) && (b[n-8] == 108) && (b[n-7] == 97) && (b[n-6] == 110) {
        
        b[n-9] = 0
        b[n-8] = 0
        b[n-7] = b[n-3]
        b[n-6] = 0
        b[n-5] = 1


        return true
    }else{
     return false
    }
    //return false  
}


func (c chinaDNS) handleClient(conn *net.UDPConn,localBuf []byte) {

	//localBuf := make([]byte, 1024)
	n, remoteAddr, err := conn.ReadFromUDP(localBuf)
	if err != nil {
		fmt.Println("ERROR: failed to read UDP msg because of ", err.Error())
		return
	}

	if in_key != "" {
		key := []byte(in_key)
		localBuf, err = my_aes.AesDecrypt(localBuf, key)
		if err != nil {
			panic(err)
		}
	}

	//log.Printf("DEBUG: read local udp data %d\n", n)
	if n > 2 {
	}

    //if localBuf[n-3] == 28 {
    	//do not support ipv6 request
    //	return 
    //}

    

    flag := deal_tail_lan(localBuf,n)
    //flag := false
   

	//go func() {
	 url := getParameter(localBuf[13:])
	 //log.Printf("query %s",url)
	 //
	 if len(url) == 0 {
	 	return
	 }

	 for _, v := range gkeyword {

			 if strings.Contains(url,v) {
			 	// ad block 
			 	log.Printf("block %s",url)
			 	//c.selectPacket(conn, remoteAddr, []byte("www.baidu.com"),12)
			 	return 
			 }

		}
	 
	
       
     if (0 != gmap[format_domain_name(url)]) || (strings.HasSuffix(url,".cn")) {
     	log.Printf("query domestic %s",url)

     	if flag{
     		c.selectPacket(conn, remoteAddr, localBuf,n-4)
     	}else{
     		c.selectPacket(conn, remoteAddr, localBuf,n)
     	}


		//c.selectPacket(conn, remoteAddr, localBuf,n)
		//time.Sleep(time.Second * 3)
	}else{
		log.Printf("query oversea %s",url)
       
       if flag{
     		go proxy(dohserver, conn, remoteAddr, localBuf[:(n-4)])
     	}else{
     		go proxy(dohserver, conn, remoteAddr, localBuf[:n])
     	}

      
	}



	//}()
}

func memsetRepeat(a []byte, v byte) {
    if len(a) == 0 {
        return
    }
    a[0] = v
    for bp := 1; bp < len(a); bp *= 2 {
        copy(a[bp:], a[:bp])
    }
}

func (c chinaDNS) updServe() {
	addr, err := net.ResolveUDPAddr("udp", c.sa)
	if err != nil {
		log.Printf("ERROR: Cant't resolve address:%v\n", err)
		return
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Printf("ERROR: listeing fail:%v\n", err)
		return
	}

	defer conn.Close()

    //localBuf := make([]byte, 512)

	for {
			 // for i := 0; i < 100; i++ {
	   //      memsetRepeat(localBuf, 0)
	   //      }

        //localBuf := make([]byte, 512)
        localBuf := get_next_buff("localbuff")
        
		c.handleClient(conn,localBuf)
	}
}

func main() {

	//  port := ":53"
	//  for i, v := range os.Args {
	//     if i> 0 {
	//       //fmt.Printf("%d %#v\n",i,v)
	//       if v == "-s" {
	//         fmt.Printf("%d %#v\n",i,os.Args[i+1])
	//       }

	//       if v == "-p" {
	//         fmt.Printf("Listen on port %#v\n",os.Args[i+1])
	//         port = ":" + os.Args[i+1]
	//       }
	//   }
	// }

	sa := flag.String("sa", ":53", "dns addr:port")
	fname := flag.String("fn", "/etc/chinadns/chnroute.txt", "china route list")
	ds := flag.String("ds", "223.5.5.5,118.126.68.223,119.29.29.29", "dns server address")
	ine := flag.String("ie", "", "ciph incoming traffic")
	oue := flag.String("oe", "", "ciph outgoing traffic")
	ouip := flag.String("ip", "", "outgoing traffic ip")
	//dohserver_r := flag.String("dohserver", "https://mozilla.cloudflare-dns.com/dns-query", "DNS Over HTTPS server address")
    dohserver_r := flag.String("dohserver", "https://8.8.8.8/dns-query", "DNS Over HTTPS server address")
	
	flag.Parse()

	if *ds != "" {
		dnsAddr = strings.Split(*ds, ",")
		for _, v := range dnsAddr {

			fmt.Printf("dns server = [%#v]\n", v)
		}
	}

	if *sa != "" {
		fmt.Printf("Listen on port  [%#v]\n", *sa)
	}

	if *ine != "" {
		in_key = *ine
		fmt.Printf("Incoming Ciph Enabled key = [%#v]\n", in_key)
	}

	if *oue != "" {
		out_key = *oue
		fmt.Printf("outgoing Ciph Enabled key = [%#v]\n", out_key)
	}

	if *ouip != "" {
		out_ip = *ouip
		fmt.Printf("outgoing Ciph Enabled ip = [%#v]\n", out_ip)
	}

	if *dohserver_r != "" {
		//puts dohserver 
		dohserver = *dohserver_r
		fmt.Printf("doh server = [%#v]\n", dohserver)
	}

	c := newChinaDNS(*fname, *sa)
	if c == nil {
		return
	}
	c.updServe()

	//TestnewRouteList()
}
