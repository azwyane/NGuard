import os


INTERNAL_NETWORK = "192.168.1"
AVOID = "192.168.1.1" #gateway
CHAINS = ['INPUT','OUTPUT','FORWARD']
#os.popen("iptables -A OUTPUT -d 192.168.1.3 -j DROP")


#if #match in src output chain is blocked;
#else in dst block input chain

def blocker(sip, sport, dip, dport,proto,iface=DEFAULT_IFACE):
    if os.getuid() == 0:
        if sip == INTERNAL_NETWORK:
            os.popen(f"iptables -A {CHAINS[1]} -d {dip} -j DROP")
        else:
            os.popen(f"iptables -A {CHAINS[0]} -d {sip} -j DROP")
    else:
        print("NEED ROOT PRIVILEGES")

def unblocker(sip, sport, dip, dport,proto,iface=DEFAULT_IFACE):
    if os.getuid() == 0:
        if sip == INTERNAL_NETWORK:
            os.popen(f"iptables -D {CHAINS[1]} -d {dip} -j DROP")
        else:
                os.popen(f"iptables -D {CHAINS[0]} -d {sip} -j DROP")
    else:
        print("NEED ROOT PRIVILEGES")

