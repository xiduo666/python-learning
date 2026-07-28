'''
掌握：
strip()
split()
join()
replace()
removeprefix()
startswith()
endswith()
lower()
in
字符串切片
字符串不可变性
'''

#Day 3.1 清理并统一格式
raw_events = [
    "  LOGIN_FAILED\n",
    "\tlogin_success ",
    " Login_Failed ",
    "\nWARNING\t",
]

normalized_events=[event.strip().upper() for event in raw_events]
print(normalized_events)



#Day 3.2 拆分和连接IP
ip = "192.168.10.25"
ip_split=ip.split(".")
ip_recover=".".join(ip_split)
ip_join="-".join(ip_split)
print("拆分结果：",ip_split)
print("第一段：",ip_split[0])
print("最后一段：",ip_split[-1])
print("恢复结果：",ip_recover)
print("连接结果：",ip_join)



#Day 3.3 解析键值对
fields = [
    "user=admin",
    "password=a=b=c",
    "ip=10.0.0.1",
]

dict_fields={key:value for key,value in (field.split("=",1) for field in fields)}
#刚刚看完你写的教程，我回忆起了一点生成器的知识，我觉得这里用生成器好像更简单
print(dict_fields)



#Day 3.4 筛选日志
logs = [
    "INFO: service started",
    "WARNING: high memory usage",
    "ERROR: connection refused",
    "INFO: user login",
    "CRITICAL: database unavailable",
    "DEBUG: checking configuration",
]

valid_logs=[line for line in logs if line.startswith(("WARNING", "ERROR", "CRITICAL"))]
print(valid_logs)



#Day 3.5 处理文件名
filenames = [
    "access.log",
    "error.LOG",
    "users.txt",
    "config.json",
    "system.log",
    "photo.png",
]
file_log=[file for file in filenames if file.lower().endswith(".log")]
remove_file_log=[file.split(".")[0] for file in file_log]
print(remove_file_log)



#Day 3.6 单行日志解析函数
def parse_login_log(line: str) -> dict[str, str] | None:

    line=line.strip()
    if line=='':
        return None

    list_log=line.split()
    if len(list_log)!=4:
        return None
    time,event,ip,user=list_log

    if not ip.startswith("ip="):
        return None
    ip=ip.removeprefix("ip=")

    if not user.startswith("user="):
        return None
    user=user.removeprefix("user=")

    if  user=='' or  ip=='':
        return None

    return {
        "time": time,
        "event": event,
        "ip": ip,
        "user": user,
    }

test_logs = [
    "2026-07-28T20:15:03 LOGIN_FAILED ip=192.168.1.10 user=admin",
    "  2026-07-28T20:16:21 LOGIN_SUCCESS ip=10.0.0.2 user=alice  ",
    "",
    "LOGIN_FAILED ip=10.0.0.1",
    "2026-07-28T20:17:30 LOGIN_FAILED address=10.0.0.3 user=root",
    "2026-07-28T20:18:45 LOGIN_FAILED ip=10.0.0.4 user=",
]
for log in test_logs:
    result = parse_login_log(log)
    print(result)



#综合题：分析登陆失败事件
security_logs = [
    "2026-07-28T20:15:03 LOGIN_FAILED ip=10.0.0.1 user=admin",
    "2026-07-28T20:15:20 LOGIN_SUCCESS ip=10.0.0.2 user=alice",
    "2026-07-28T20:16:11 LOGIN_FAILED ip=10.0.0.1 user=root",
    "bad log",
    "2026-07-28T20:17:42 LOGIN_FAILED ip=192.168.1.5 user=admin",
    "2026-07-28T20:18:03 LOGIN_FAILED ip=10.0.0.1 user=test",
    "",
    "2026-07-28T20:19:27 LOGIN_FAILED ip=192.168.1.5 user=root",
]

def count_failed_logins(logs: list[str]) -> dict[str, int]:
    sum_dict={}
    for log in logs:
        login_logs=parse_login_log(log)
        if login_logs is None:
            continue
        if login_logs["event"]=="LOGIN_FAILED":
            ip=login_logs["ip"]
            sum_dict[ip]=sum_dict.get(ip,0)+1

    return sum_dict

failed_logins = count_failed_logins(security_logs)
print({ip:count for ip,count in failed_logins.items() if count>=2})



#挑战题：手动验证IPv4地址
def is_valid_ipv4(ip: str) -> bool:
    ip=ip.strip()
    if ip=='':
        return False

    ip_split=ip.split(".")
    if len(ip_split)!=4:
        return False
    for segment in ip_split:
        if segment=='':
            return False
        if not segment.isdigit():
            return False
        if not 0<=int(segment)<=255:
            return False
    return True

test_ips = [
    "192.168.1.1",
    " 10.0.0.1 ",
    "256.1.1.1",
    "192.168.1",
    "192.168.1.abc",
    "192..1.1",
    "-1.0.0.1",
]


for ip in test_ips:
    print(f"{ip}: {is_valid_ipv4(ip)}")
