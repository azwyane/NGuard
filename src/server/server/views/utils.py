import json
import os
def get_rules(rule_id):
    try:
        print(str(os.getcwd())+"/../rules.py")
        with open(os.getcwd()+'/../rules.json') as f:
            config = json.load(f)
        with open(os.getcwd()+'/../server/requests.json') as f:
            manual = json.load(f)    
    except:
        return "error"
    if rule_id=="exclude": return config["exclude"]
    if rule_id=="blocked": return config["blocked"]
    if rule_id=="suspicious": return config["suspicious"]
    if rule_id=="manual": return manual["manual"]
    return ""
def get_action(rule_id):
    if rule_id=="exclude": return "ALLOW"
    if rule_id=="blocked": return "DROP"
    if rule_id=="suspicious": return "ALLOW"
    if rule_id=="manual": return "DROP"





def check_rule(sip,sport,dip,dport):
    dport=str(dport)
    sport=str(sport)
    try:
        with open('rules.json') as f:
            config = json.load(f)  
    except:
        warning.warning("rules.json file not found")
        return "failed"

    mamnual_rule=config["manual"]
    for manual in manual_rule:
        if exclude['sip']==sip or str(exclude['dport']) ==dport:
            return "in_exclude"
    FILE_PATH = f"{os.getcwd().replace('/server','')}/{config['request_path']}"
    blocked_rule=config["blocked"]
    for blocked in blocked_rule:
        if blocked['sip']==sip and str(blocked["dport"])==dport:
            return "both_blocked"
        elif blocked['sip']==sip:
            return "sip_blocked"
        elif str(blocked['dport'])==dport:
            return "dport_blocked"
    suspicious_rule=config["suspicious"]
    for rule in suspicious_rule:
        if rule['sip']==sip and str(rule["dport"])==dport:
            return "in_suspicious"
    return ""








def handle_manual_rule(data):
    if "policy" in data and data["policy"] == "allow":
        policy="ALLOW"
    else:
        policy="DROP"
    if "sip" in data:
        sip=data["sip"]
    else:
        sip=""
    if "sport" in data:
        sport=data["sport"]
    else:
        sport=""
    if "dip" in data:
        dip=data["dip"]
    else:
        dip=""
    if "dport" in data:
        dport=data["dport"]
    else:
        dport=""
    if "protocol" in data:
        protocol=data["protocol"]
    else:
        protocol=""
    if "ipv" in data:
        ipv=data["ipv"]
    else:
        ipv=""
    if "iface" in data:
        iface=data["iface"]
    else :
        iface=""
    try:
        if(sip!="" and sport!="" and dport!="" ):
            with open(os.getcwd().replace('/server','') + '/server_config.json') as f:
                config = json.load(f)
                FILE_PATH = f"{os.getcwd().replace('/server','')}/{config['request_path']}"
                with open(FILE_PATH) as f:
                    config=json.load(f)
                manual_rule=config["manual"]
                manual_rule.append({"sip":str(sip),"sport":str(sport),"dip":str(dip),"dport":str(dport),"action":policy,"protocol":protocol,"ipv":ipv})
                config["manual"]=manual_rule
                config["req"]=True
                print("or here") 
                try:
                    with open(FILE_PATH,'w') as f:
                        json.dump(config, f)
                    return "success"
                except:
                    pass
        else:
            return "failed"
    except Exception as e:
        print(e)
        return "failed"


def handle_update_request(data):
    if "id" in data:
        if data["id"]=='system':
            mode=data['update']['mode']
            FILE_PATH = f"{os.getcwd().replace('/server','')}/ips_config.json"
            with open(FILE_PATH) as f:
                    config=json.load(f)
            if(mode=="ips"):
                config["mode"]="IPS"
            if(mode=="ids"):
                config["mode"]="IDS"
            try:
                with open(FILE_PATH,'w') as f:
                    json.dump(config, f)
                return "success"
            except:
                return "failed"
        elif data["id"]=='notification_email':
            return "success"
            pass
    return "failed"
    


