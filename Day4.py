# 工程建议：逐步按 PEP 8 调整格式，例如在 # 后、赋值/比较运算符两侧及逗号后留空格。
#Day 4.1 参数设计与格式化
def build_alert(
    source_ip: str,
    event: str,
    level: str = "MEDIUM",
    *,
    uppercase_event: bool = True,
) -> str:
    source_ip=source_ip.strip()
    level=level.strip().upper()
    event=event.strip()

    if uppercase_event:
        event = event.upper()

    return f'[{level}] {source_ip} - {event}'

print(build_alert(" 10.0.0.8 ", "port scan"))
print(
    build_alert(
        event="login failed",
        source_ip="192.168.1.5",
        level="high",
        uppercase_event=False,
    )
)
# 工程建议：uppercase_event 适合设为仅限关键字参数，因为 True/False 单独出现在
# 调用位置时含义不直观；写成 uppercase_event=False 能直接说明这个开关控制什么。



#Day 4.2 正确处理可变默认参数
def add_event_tag(
    tag: str,
    tags: list[str] | None = None,
) -> list[str]:
    if tags is None:
        tags=[]

    tag=tag.strip().lower()
    if not tag:
        return tags
    
    if tag in tags:
        return tags
    
    tags.append(tag)
    return tags

first_tags = add_event_tag(" SSH ")
second_tags = add_event_tag("Brute-Force")

print(first_tags)
print(second_tags)

shared_tags = ["login"]
returned_tags = add_event_tag(" SSH ", shared_tags)
add_event_tag("ssh", shared_tags)
add_event_tag("   ", shared_tags)

print(shared_tags)
print(returned_tags is shared_tags)



#Day 4.3 *args 和 **kwargs
def create_security_event(
    event_type: str,
    *tags: str,
    **details: object,
) -> dict[str, object]:
    event_type=event_type.strip().upper()
    tags=[tag.strip().lower() for tag in tags if tag.strip()]

    return {
        "event_type": event_type,
        "tags": tags,
        "details": details
    }

event = create_security_event(
    " login_failed ",
    " SSH ",
    "External",
    " ",
    ip="10.0.0.8",
    user="admin",
    port=22,
)

print(event)



#Day 4.4 多返回值与None
def parse_security_log(
    line: str,
) -> tuple[dict[str, str] | None, str | None]:
    if not line.strip():
        return None, "empty line"

    if len(line.strip().split())!=4:
        return None, "invalid field count"
    
    time,event,ip,user=line.strip().split()

    if not ip.startswith("ip="):
        return None,"invalid ip field"
    
    ip=ip.removeprefix("ip=")
    if not ip:
        return None,"missing value"
    
    ip_parts = ip.split(".")
    if len(ip_parts) != 4:
        return None, "invalid ip field"

    if not all(
        part.isascii()
        and part.isdigit()
        and 0 <= int(part) <= 255
        for part in ip_parts
    ):
        return None,"invalid ip field"

    if not user.startswith("user="):
        return None,"invalid user field"
    
    user=user.removeprefix("user=")

    if not user:
        return None,"missing value"

    event=event.strip().upper()
    user=user.strip().lower()

    return {
        "time": time,
        "event": event,
        "ip": ip,
        "user": user
    },None


test_logs = [
    "2026-07-29T09:00:00 LOGIN_FAILED ip=10.0.0.1 user=Admin",
    "",
    "bad log",
    "2026-07-29T09:01:00 LOGIN_FAILED address=10.0.0.1 user=root",
    "2026-07-29T09:02:00 LOGIN_FAILED ip=10.0.0.1 account=root",
    "2026-07-29T09:03:00 LOGIN_FAILED ip= user=root",
]

for log in test_logs:
    event, error = parse_security_log(log)
    print("event:", event, "error:", error)



#Day 4.5 修改原对象与返回新对象
def record_failure(
    failure_counts: dict[str, int],
    ip: str,
) -> None:
    ip=ip.strip()
    if not ip:
        return

    failure_counts[ip] = failure_counts.get(ip, 0) + 1


def record_failure_copy(
    failure_counts: dict[str, int],
    ip: str,
) -> dict[str, int]:
    new_counts = failure_counts.copy()
    ip = ip.strip()

    if not ip:
        return new_counts
    
    new_counts[ip] = new_counts.get(ip, 0) + 1
    return new_counts


original_counts = {"10.0.0.1": 2}

result = record_failure(original_counts, "10.0.0.1")
print(original_counts)
print(result)

new_counts = record_failure_copy(original_counts, "192.168.1.5")
print(original_counts)
print(new_counts)
print(original_counts is new_counts)



#综合题：可配置登录日志分析器
def analyze_security_logs(
    lines: list[str],
    *,
    threshold: int = 2,
    ignored_users: set[str] | None = None,
) -> dict[str, object]:
    normalized_ignored_users = set()
    if ignored_users is not None:
        normalized_ignored_users = {
            user.strip().lower()
            for user in ignored_users
            if user.strip()
        }

    total_line_count = len(lines)
    valid_event_count = 0
    invalid_line_count = 0
    ignored_event_count = 0
    failure_counts: dict[str, int] = {}

    for line in lines:
        event, _error = parse_security_log(line)

        if event is None:
            invalid_line_count += 1
            continue

        valid_event_count += 1

        if event["user"] in normalized_ignored_users:
            ignored_event_count += 1
            continue

        if event["event"] != "LOGIN_FAILED":
            continue

        record_failure(failure_counts, event["ip"])

    suspicious_ips = sorted(
        ip
        for ip, count in failure_counts.items()
        if count >= threshold
    )

    return {
        "total_line_count": total_line_count,
        "valid_event_count": valid_event_count,
        "invalid_line_count": invalid_line_count,
        "ignored_event_count": ignored_event_count,
        "failure_counts": failure_counts,
        "suspicious_ips": suspicious_ips
    }


security_logs = [
    "2026-07-29T10:00:00 LOGIN_FAILED ip=10.0.0.1 user=admin",
    "2026-07-29T10:00:10 LOGIN_SUCCESS ip=10.0.0.2 user=alice",
    "2026-07-29T10:00:20 LOGIN_FAILED ip=10.0.0.1 user=root",
    "bad log",
    "2026-07-29T10:00:30 LOGIN_FAILED ip=192.168.1.5 user=admin",
    "2026-07-29T10:00:40 LOGIN_FAILED ip=10.0.0.1 user=test",
    "",
    "2026-07-29T10:00:50 LOGIN_FAILED ip=192.168.1.5 user=root",
]

ignored_users = {"TEST"}

report = analyze_security_logs(
    security_logs,
    threshold=2,
    ignored_users=ignored_users,
)

print(report)
print(ignored_users)



#可选挑战：闭包
def make_event_filter(*allowed_events: str):
    allowed_events_set={event.strip().upper() for event in allowed_events if event.strip()}

    def filter_event(events: dict[str,str]) -> bool:
        return events.get('event', '').strip().upper() in allowed_events_set

    return filter_event


login_filter = make_event_filter(
    "login_failed",
    "login_success",
)

events = [
    {"event": "LOGIN_FAILED", "ip": "10.0.0.1"},
    {"event": "PORT_SCAN", "ip": "10.0.0.2"},
    {"ip": "10.0.0.3"},
]

for event in events:
    print(login_filter(event))
