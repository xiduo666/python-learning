#Day 2.1 基础转换
numbers = [1, 2, 3, 4, 5, 6]
print([number**2 for number in numbers])



#Day 2.2 筛选合法端口
ports_1 = [22, 80, -1, 443, 65536, 8080, 0, 3306]
print('合法端口:',[port for port in ports_1 if 1<=port<=65535])
print('知名端口:',[port for port in ports_1 if 1<=port<=1023])



#Day 2.3 条件表达式
ports_2 = [22, 80, 443, 3306, 8080]
print([f"{port}:well-konwn" if 1<=port<=1023 else f"{port}:other" for port in ports_2])



#Day 2.4 筛选字典
port_status = {
    21: "closed",
    22: "open",
    23: "filtered",
    80: "open",
    443: "open",
    445: "filtered",
    3306: "closed",
}
print({port:status for port,status in port_status.items() if status=="open"})



#Day 2.5 enumerate()
targets = [
    "192.168.1.10",
    "192.168.1.20",
    "10.0.0.5",
]
print([f"目标{index}:{ip}" for index,ip in enumerate(targets,start=1)])



#Day 2.6 zip()
ips = [
    "10.0.0.1",
    "10.0.0.2",
    "192.168.1.5",
]

failed_counts = [2, 6, 4]
print({ip:count for ip,count in zip(ips,failed_counts) if count>=4})



#综合题:生成安全告警
login_counts = {
    "10.0.0.1": 2,
    "10.0.0.2": 7,
    "192.168.1.5": 4,
    "172.16.0.8": 1,
}

def build_login_alerts(
    counts: dict[str, int],
    threshold: int,
) -> list[str]:
    return [f"警告：{ip}登陆失败{count}次" for ip,count in counts.items() if count>=threshold]

alerts = build_login_alerts(login_counts, 4)

for alert in alerts:
    print(alert)



#挑战题：集合推导式
access_logs = [
    "10.0.0.1",
    "10.0.0.2",
    "10.0.0.1",
    "192.168.1.5",
    "10.0.0.2",
]


unique_ips={ip for ip in access_logs}
#print({ip for ip in access_logs})
print(sorted(unique_ips))
