import nftables
import json
import pprint
nft = nftables.Nftables()
nft.set_json_output(True)

rc,output,err = nft.cmd("add chain ip filter NGUARD")

#check for IPS host or network mode
#if hostmode then forward all INPUT and OUTPUT traffic to NGUARD chain
def setup_hostmode_target():
    rc,output,err = nft.cmd("insert rule ip filter INPUT counter jump NGUARD")
    rc,output,err = nft.cmd("insert rule ip filter OUTPUT counter jump NGUARD")
    return

def setup_networkmode_target():
    rc,output,err = nft.cmd("insert rule ip filter FORWARD counter jump NGUARD")
    return


def block(sip, sport, dip, dport,proto,iface,config:dict):
    #read config for calling setup mode 
    #read config and use policies to block port ip and network mentioned in config 
    #run nft block cmd
    pass

def unblock(sip, sport, dip, dport,proto,iface,config:dict):
    #run nft cmf to remove entry from the NGUARD chain
    pass



def list_rules():
    rc,output,err = nft.cmd("list ruleset")
    return json.loads(output)
    # rules = output['nft']['rule']
    # nguard_rules = [k,v if  ]








