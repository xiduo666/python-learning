#Day 1.1 端口分类
def classify_port(port: int) -> str:
    if port<=1023 and port>=1:
        return "well known"
    elif port<=49151 and port>=1024:
        return "registered"
    elif port>=49152 and port<=65535:
        return "dynamic"
    return "invalid"

print(classify_port(22))
print(classify_port(8080))
print(classify_port(60000))
print(classify_port(70000))



#Day 1.2 and 1.3   统计失败登录和筛选可疑IP
login_events = [
    "10.0.0.1",
    "10.0.0.2",
    "10.0.0.1",
    "192.168.1.5",
    "10.0.0.1",
    "10.0.0.2"
]

login_events_dict={}
for ip in login_events:
    login_events_dict[ip]=login_events_dict.get(ip,0)+1

print(login_events_dict)

for ip,value in login_events_dict.items():
    if value>=2:
        print(f"可疑IP:{ip},失败次数:{value}")



#挑战题
def analyze_failed_logins(events: list[str], threshold: int) -> dict[str, int]:
    dict_count={}
    dict_count_filter={}

    for ip in events:
        dict_count[ip]=dict_count.get(ip,0)+1

    for ip,value in dict_count.items():
        if value>=threshold:
            dict_count_filter[ip]=dict_count_filter.get(ip,0)+value

    return dict_count_filter

result = analyze_failed_logins(login_events,2)
print(result)


#推导式练习
ports = [22, 80, 443, 8080, 3306, 65536, -1]

right_ports=[port for port in ports if 65535>=port>=1]
print(right_ports)
