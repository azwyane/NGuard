import nftables
import json

nft = nftables.Nftables()
nft.set_json_output(True)

#check for IPS host or network mode
#if hostmode then forward all INPUT and OUTPUT traffic to NGUARD chain
def setup_hostmode_target():
    rc,output,err = nft.cmd("insert rule ip filter INPUT counter jump NGUARD")
    rc,output,err = nft.cmd("insert rule ip filter OUTPUT counter jump NGUARD")
    return

def setup_networkmode_target():
    rc,output,err = nft.cmd("insert rule ip filter FORWARD counter jump NGUARD")
    return


def block(sip, sport, dip, dport,proto,iface,block_port_ip_network:str):
    if block_port_ip_network == 'port':
        rc,output,err = nft.cmd(f"add rule ip filter NGUARD tcp dport {dport} counter drop")
        return err
        
    elif block_port_ip_network == 'ip-port':
        rc,output,err = nft.cmd(f"add rule ip filter NGUARD ip saddr {sip} tcp dport {dport} counter drop")
        return err

    elif block_port_ip_network == 'ip':
        rc,output,err = nft.cmd(f"add rule ip filter NGUARD ip saddr {sip} tcp counter drop")
        return err  

    
def unblock(sip, sport, dip, dport,proto,iface,config:dict):
    #run nft cmf to remove entry from the NGUARD chain
    pass



def list_rules():
    rc,output,err = nft.cmd("list ruleset")
    table_chain_rule = json.loads(output)['nftables']
    nguard_rules= []
    for tcr in table_chain_rule:
        if tcr.get('rule',None):
            if tcr['rule']['chain'] == 'NGUARD':
                nguard_rules.append(rule)
    return {'nguard_rules':nguard_rules}


def flush_NGUARD_chain():
    rc,output,err = nft.cmd("flush chain ip filter NGUARD")
    return rc,err #if rc!= means error running json load error







