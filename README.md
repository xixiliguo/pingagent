# pingagent
利用icmp消息探测主机间网络质量的客户端

# 介绍
1. 使用 raw socket
2. 支持动态更新配置文件
3. 收集信息后,定期向服务器上报

# 配置文件
probe_period:     每次发icmp消息的间隔. 单位:秒  
report_period:    向服务端上报网络状态的间隔. 单位:秒  
server_ip:        服务器地址  
pingList:         具体的源和目的地址  

```json
{
    "probe_period": 1,     
    "report_period": 5,    
    "server_ip": "10.211.55.7:8243",    
    "pingList": {                  
        "110.211.55.9": [
            "10.211.55.1"
        ],
        "172.16.0.188": [
            "172.16.0.111",
            "172.16.0.15"
        ]
    }
}
```

# Example
```
INFO:2018/01/05 23:42:18 read config file
INFO:2018/01/05 23:42:18 config info: &main.Config{lastModityTime:time.Time{sec:63650763730, nsec:799835413, loc:(*time.Location)(0x7c03e0)}, ctx:context.Context(nil), cancel:(context.CancelFunc)(nil), file:"", ProbeInterval:1, ReportInterval:5, ServerIP:"10.211.55.7:8243", PingList:map[string][]string{"10.211.55.9":[]string{"10.211.55.1"}, "172.16.0.188":[]string{"172.16.0.111", "172.16.0.15"}}}
INFO:2018/01/05 23:42:18 add new ping instance 10.211.55.9->10.211.55.1
INFO:2018/01/05 23:42:18 start ping from 10.211.55.9 to 10.211.55.1
INFO:2018/01/05 23:42:19 10.211.55.9 > 10.211.55.1 seq 1: get normal reply
INFO:2018/01/05 23:42:20 10.211.55.9 > 10.211.55.1 seq 2: get normal reply
INFO:2018/01/05 23:42:21 10.211.55.9 > 10.211.55.1 seq 3: get normal reply
INFO:2018/01/05 23:42:22 10.211.55.9 > 10.211.55.1 seq 4: get normal reply
INFO:2018/01/05 23:42:23 10.211.55.9 > 10.211.55.1 seq 5: get normal reply
DEBUG:2018/01/05 23:42:23 sent: {"flow":[{"sip":"10.211.55.9","dip":"10.211.55.1","time":"2018-01-05 23:42:22","statistics":{"packet-sent":"4","packet-sucess":"4","packet-drop":"0","min":"374","max":"611","avg":"466"}}]}
INFO:2018/01/05 23:42:24 10.211.55.9 > 10.211.55.1 seq 6: get normal reply
INFO:2018/01/05 23:42:25 10.211.55.9 > 10.211.55.1 seq 7: get normal reply
```
