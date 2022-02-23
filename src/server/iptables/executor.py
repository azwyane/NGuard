import os
import subprocess
import json

try:
    with open('ips_config.json','r') as f:
        config = json.load(f)
except Exception as e:
    import sys
    print(e,"didn\'t found config for the executor")
    sys.exit()

AVOID = list()
IFACE = config.get("interface",None)
NETWORK = config.get("network",None)
MODE = NETWORK.get("NETWORK_MODE",None)
if MODE == 'HOST':
    HOST_NETWORK  = NETWORK.get('HOST',None)
    AVOID.append(HOST_NETWORK)
else:
    HOST_NETWORK = NETWORK.get('NETWORK',None)
  

CHAINS = ['INPUT','OUTPUT','FORWARD']
#os.popen("iptables -A OUTPUT -d 192.168.1.3 -j DROP")


#if #match in src output chain is blocked;
#else in dst block input chain

def blocker(sip, sport, dip, dport,proto,iface=IFACE):
    if os.getuid() == 0:
        if sip == HOST_NETWORK:
            os.popen(f"iptables -A {CHAINS[1]} -d {dip} -j DROP")
        else:
            os.popen(f"iptables -A {CHAINS[0]} -d {sip} -j DROP")
    else:
        print("NEED ROOT PRIVILEGES")

def unblocker(sip, sport, dip, dport,proto,iface=IFACE):
    if os.getuid() == 0:
        if sip == HOST_NETWORK:
            os.popen(f"iptables -D {CHAINS[1]} -d {dip} -j DROP")
        else:
                os.popen(f"iptables -D {CHAINS[0]} -d {sip} -j DROP")
    else:
        print("NEED ROOT PRIVILEGES")

def get_applied_rules():
    if os.getuid() == 0:
        output,err = subprocess.Popen(["iptables","-S"],stdout=subprocess.PIPE).communicate()
        if not err:
            return output

    else:
        print("NEED ROOT PRIVILEGES")

