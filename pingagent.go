package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

var (
	info   *log.Logger
	warn   *log.Logger
	debug  *log.Logger
	global *Agent
)

type Config struct {
	lastModityTime time.Time
	ctx            context.Context
	cancel         context.CancelFunc
	file           string
	ProbeInterval  int                 `json:"probe_period"`
	ReportInterval int                 `json:"report_period"`
	ServerIP       string              `json:"server_ip"`
	PingList       map[string][]string `json:"pingList"`
}

type Agent struct {
	sync.Mutex
	wg      sync.WaitGroup
	Config  *Config
	IPInfos []*IPInfo
}

type IPInfo struct {
	sync.Mutex
	Src     string `json:"src"`
	Dst     string `json:"dst"`
	Time    string `json:"time"`
	Total   int64  `json:"total"`
	Success int64  `json:"success"`
	Fail    int64  `json:"fail"`
	Min     int64  `json:"min"`
	Max     int64  `json:"max"`
	Avg     int64  `json:"avg"`
}

func (ip *IPInfo) updateinfo(result bool, rtt int64) {
	ip.Lock()
	defer ip.Unlock()
	if result == true {
		if rtt < ip.Min || ip.Min == 0 {
			ip.Min = rtt
		}
		if rtt > ip.Max {
			ip.Max = rtt
		}
		ip.Avg = (ip.Avg*ip.Success + rtt) / (ip.Success + 1)
		ip.Total++
		ip.Success++
	} else {
		ip.Total++
		ip.Fail++
	}
	ip.Time = time.Now().Format("2006-01-02 15:04:05")
}

func (ip *IPInfo) resetinfo() {
	// caller shoud guarantee lock
	ip.Total = 0
	ip.Success = 0
	ip.Fail = 0
	ip.Min = 0
	ip.Max = 0
	ip.Avg = 0
}

func (ip *IPInfo) copy() *IPInfo {
	return &IPInfo{
		Src:     ip.Src,
		Dst:     ip.Dst,
		Total:   ip.Total,
		Success: ip.Success,
		Fail:    ip.Fail,
		Min:     ip.Min,
		Max:     ip.Max,
		Avg:     ip.Avg,
		Time:    ip.Time,
	}

}

func pingloop(ctx context.Context, global *Agent, s, d string) {
	cfg := global.Config
	src, _ := net.ResolveIPAddr("ip4", s)
	dst, _ := net.ResolveIPAddr("ip4", d)
	conn, _ := net.DialIP("ip4:icmp", src, dst)
	echomsg := &icmp.Echo{
		ID: os.Getpid() & 0xffff, Seq: 1,
		Data: []byte("pingagent"),
	}
	wm := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: echomsg,
	}
	ipinfo := &IPInfo{
		Src: s,
		Dst: d,
	}
	global.Lock()
	global.IPInfos = append(global.IPInfos, ipinfo)
	global.Unlock()
	tk := time.NewTicker(time.Duration(cfg.ProbeInterval) * time.Second)
	info.Printf("start ping from %s to %s\n", s, d)
	for {
		select {
		case <-tk.C:
			wb, _ := wm.Marshal(nil)
			begin := time.Now()
			conn.SetWriteDeadline(time.Now().Add(time.Duration(3 * time.Second)))
			if _, err := conn.Write(wb); err != nil {
				warn.Printf("%s > %s seq %d ping error: %s\n",
					s, d, echomsg.Seq, err)
				ipinfo.updateinfo(false, 0)
				echomsg.Seq++
				continue
			}
			rb := make([]byte, 1500)
			conn.SetReadDeadline(time.Now().Add(time.Duration(3 * time.Second)))
			n, _, err := conn.ReadFrom(rb)
			if err != nil {
				warn.Printf("%s > %s seq %d ping error: %s\n",
					s, d, echomsg.Seq, err)
				ipinfo.updateinfo(false, 0)
				echomsg.Seq++
				continue
			}
			rtt := time.Now().Sub(begin).Nanoseconds() / 1000
			rm, err := icmp.ParseMessage(1, rb[:n])
			if err != nil {
				warn.Printf("%s > %s seq %d ping error: %s\n",
					s, d, echomsg.Seq, err)
				ipinfo.updateinfo(false, 0)
				echomsg.Seq++
				continue
			}
			switch rm.Type {
			case ipv4.ICMPTypeEchoReply:
				b, _ := rm.Body.Marshal(1)
				bodyLen := len(b)
				p := &icmp.Echo{
					ID:  int(binary.BigEndian.Uint16(b[:2])),
					Seq: int(binary.BigEndian.Uint16(b[2:4])),
				}
				if bodyLen > 4 {
					p.Data = make([]byte, bodyLen-4)
					copy(p.Data, b[4:])
				}
				info.Printf("%s > %s seq %d: get normal reply\n",
					s, d, p.Seq)
				ipinfo.updateinfo(true, rtt)
				echomsg.Seq++
			default:
				warn.Printf("%s > %s seq %d ping error: got %+v; want echo reply\n",
					s, d, echomsg.Seq, rm.Type)
				ipinfo.updateinfo(false, 0)
				echomsg.Seq++
			}
		case <-ctx.Done():
			conn.Close()
			tk.Stop()
			info.Printf("end ping from %s to %s\n", s, d)
			global.wg.Done()
			return
		}
	}
}

func startPingList(ctx context.Context) {
	ips, _ := net.InterfaceAddrs()
	for _, ip := range ips {
		s := strings.FieldsFunc(ip.String(), func(r rune) bool {
			if r == '/' {
				return true
			}
			return false
		})[0]
		if strings.HasPrefix(s, "127.0.0.1") {
			continue
		}
		for src, dsts := range global.Config.PingList {
			if s == src {
				for _, dst := range dsts {
					info.Printf("add new ping instance %s\n",
						src+"->"+dst)
					global.wg.Add(1)
					go pingloop(ctx, global, src, dst)
				}
			}
		}
	}
	global.wg.Add(1)
	go reportloop(ctx, global)
}

type ReportInfo struct {
	Flows []Flow `json:"flow"`
}

type Flow struct {
	Src        string `json:"sip"`
	Dst        string `json:"dip"`
	Time       string `json:"time"`
	Statistics struct {
		PacketSent   int64 `json:"packet-sent,string"`
		PacketSucess int64 `json:"packet-sucess,string"`
		PacketDrop   int64 `json:"packet-drop,string"`
		Min          int64 `json:"min,string"`
		Max          int64 `json:"max,string"`
		Avg          int64 `json:"avg,string"`
	} `json:"statistics"`
}

type RespStat struct {
	Code int `json:"code"`
}

func reportloop(ctx context.Context, global *Agent) {
	rep := &ReportInfo{}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{Transport: tr}
	tk := time.NewTicker(time.Duration(global.Config.ReportInterval) * time.Second)
	for {
		select {
		case <-tk.C:
			for _, ip := range global.IPInfos {
				ip.Lock()
				flow := Flow{
					Src:  ip.Src,
					Dst:  ip.Dst,
					Time: ip.Time,
				}
				flow.Statistics.PacketSent = ip.Total
				flow.Statistics.PacketSucess = ip.Success
				flow.Statistics.PacketDrop = ip.Fail
				flow.Statistics.Min = ip.Min
				flow.Statistics.Max = ip.Max
				flow.Statistics.Avg = ip.Avg
				rep.Flows = append(rep.Flows, flow)
				ip.resetinfo()
				ip.Unlock()
			}
			b, _ := json.Marshal(rep)
			debug.Println("sent:", string(b))
			req, _ := http.NewRequest("POST", "https://"+global.Config.ServerIP+"/msg/", bytes.NewReader(b))
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(req)
			var respstat RespStat
			if err != nil {
				warn.Printf("face error when report data: %s", err)
				continue
			}
			body, _ := ioutil.ReadAll(resp.Body)
			json.Unmarshal(body, &respstat)
			if respstat.Code == 200 {
				info.Printf("success to report info: %s\n", b)
			} else {
				warn.Printf("fail to report info: %s, error code:%d\n", b, respstat.Code)
			}
			rep.Flows = rep.Flows[:0]
		case <-ctx.Done():
			tk.Stop()
			info.Printf("end report\n")
			global.wg.Done()
			return
		}
	}
}
func loadConfigFile(file string) (*Config, error) {
	var config Config
	configdata, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(configdata, &config)
	if err != nil {
		return nil, err
	}
	finfo, _ := os.Stat(file)
	config.lastModityTime = finfo.ModTime()
	return &config, nil
}

func periodupdateconfig() {
	c := time.Tick(2 * time.Second)
	for {
		<-c
		finfo, err := os.Stat("config.json")
		if err != nil {
			continue
		}
		if !global.Config.lastModityTime.Equal(finfo.ModTime()) {
			info.Printf("found new config file\n")
			config, err := loadConfigFile("config.json")
			if err != nil {
				warn.Printf("read new file failed\n")
				continue
			}
			global.Config.cancel()
			global.wg.Wait()
			global.Config = config
			global.IPInfos = global.IPInfos[:0]
			config.ctx, config.cancel = context.WithCancel(context.Background())
			info.Printf("read config file\n")
			info.Printf("config info: %#v\n", config)
			go startPingList(config.ctx)
		}
	}
}

func main() {
	fileName := "pingagent.log"
	logFile, err := os.Create(fileName)
	if err != nil {
		log.Fatalln("open file error !")
	}
	defer logFile.Close()
	global = &Agent{}
	info = log.New(logFile, "INFO:", log.Ldate|log.Ltime)
	warn = log.New(logFile, "WARN:", log.Ldate|log.Ltime)
	debug = log.New(logFile, "DEBUG:", log.Ldate|log.Ltime)
	config, err := loadConfigFile("config.json")
	if err != nil {
		info.Fatalf("fail to read %s:%s\n", "config.json", err)
	}
	global.Config = config
	info.Printf("read config file\n")
	info.Printf("config info: %#v\n", config)
	go periodupdateconfig()
	config.ctx, config.cancel = context.WithCancel(context.Background())
	go startPingList(config.ctx)
	for {
		time.Sleep(10 * time.Minute)
	}
}
