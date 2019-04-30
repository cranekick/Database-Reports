#!/usr/bin/env python3


import re
from subprocess import call, Popen, PIPE


masscan = 'cat swt.txt | xargs masscan --rate 100000 -oL /var/log/masscan-output.log \
                --append-output --ping'

p = Popen(masscan, stdout=PIPE, shell=True)
(output, err) = p.communicate()
p_status = p.wait()
print("Masscan Output: " + str(output))


masscan_results = open('/var/log/masscan-output.log', "r")
ping_systems = open('/var/log/live_systems.txt', 'w')
ip_regex = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
ip_array = []

for line in enumerate(masscan_results):
    match = ip_regex.findall(str(line))
    for ip in match:
        # print(ip)
        ip_array.append(ip) # YAY!
        ping_systems.write("%s\n" % ip)
ping_systems.close()

nmap = call("nmap -iL /var/log/live_systems.log -A -oN /var/log/nmap_results.log", shell=True)
masscan_results.close()


