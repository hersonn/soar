import re

f = open("/var/log/psad/status.out", "r")

# Extract Top 25 attackers
content = f.read()
top_attackers = (content.split('[+]'))[3]
#print(top_attackers)


# Extract IPs
filtred_info = top_attackers.\
    replace(' ','').\
    replace('DL', '').\
    replace(',Packets', '')
ips = re.findall( r'[0-9]+(?:\.[0-9]+){3}', filtred_info)
#print(ips)


# Extract Danger Levels
filtred_info = filtred_info.\
    replace(':',' ').\
    replace('\n',' ').\
    split()
danger_lvls = []
for ip in ips:
    if ip in filtred_info:
        danger_lvls.append(filtred_info[filtred_info.index(ip)+1])
#print(danger_lvls)


# Extract IPs to Block (Danger Level > 5)
for ip, danger_lvl in zip(ips, danger_lvls):
    if int(danger_lvl) == 5:
        print(ip)

f.close()

