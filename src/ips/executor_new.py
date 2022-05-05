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
        rc,output,err = nft.cmd(f"add rule ip filter NGUARD ip saddr {sip} counter drop")
        return err
    return ""  

    
def unblock(sip, sport, dip, dport,proto,iface,config:dict):
    #run nft cmf to remove entry from the NGUARD chain
    handles=get_handle(sip,sport,dip,dport,proto,iface)
    if len(handles)>=0:
        for handle in handles:
            rc,output,err=nft.cmd(f"delete rule ip filter NGUARD handle {handle}")
    return rc,err


def get_handle(sip,dport,sip_dport_both):
    handles=[]
    rules=list_rules()
    rules=rules['nguard_rules']
    for rule in rules:
        attribute={}
        for expr in rule['expr']:
            try:
                if(expr['match']):
                    field=expr['match']['left']['payload']['field']
                    value=expr['match']['right']
                    if field=="saddr" and value==sip:
                        attribute[field]=value
                    elif field=="dport" and str(value)==str(dport):
                        attribute[field]=value
            except:
                pass
        try:
            if sip_dport_both=="dport":
                if attribute["dport"]==dport:
                    handles.append(rule['handle'])
            elif sip_dport_both=="sip":
                if attribute["saddr"]==sip:
                    handles.append(rule['handle'])
            elif sip_dport_both=="ip-port":
                if attribute["saddr"]==sip and attribute['dport']==dport:
                    handles.append(rule['handle'])
                    break
        except:
            pass
    return handles


def list_rules():
    rc,output,err = nft.cmd("list ruleset")

    table_chain_rule = json.loads(output)['nftables']
    nguard_rules= []
    for tcr in table_chain_rule:
        if tcr.get('rule',None):
            if tcr['rule']['chain'] == 'NGUARD':
                nguard_rules.append(tcr['rule'])
    return {'nguard_rules':nguard_rules}


def flush_NGUARD_chain():
    rc,output,err = nft.cmd("flush chain ip filter NGUARD")
    try:
        with open('rules.json') as f:
            config = json.load(f) 
        warning.warning("NGuard rules flushed")
        config["blocked"]=[]
        config["suspicious"]=[]
        with open('rules.json','w') as f:
                json.dump(config, f)
        return rc,err         
    except:
        return ""
        
   #if rc!= means error running json load error

