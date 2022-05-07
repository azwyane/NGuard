import json
import os
def get_rules(rule_id):
    try:
        print(str(os.getcwd())+"/../rules.py")
        with open(os.getcwd()+'/../rules.json') as f:
            config = json.load(f)  
    except:
        return "error"
    if rule_id=="exclude": return config["exclude"]
    if rule_id=="blocked": return config["blocked"]
    if rule_id=="suspicious": return config["suspicious"]
    if rule_id=="manual": return ""
    return ""
def get_action(rule_id):
    if rule_id=="exclude": return "ALLOW"
    if rule_id=="blocked": return "DROP"
    if rule_id=="suspicious": return "ALLOW"
    if rule_id=="manual": return "DROP"
