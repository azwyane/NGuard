from . import iptb
import nftables
import json

nft = nftables.Nftables()
nft.set_json_output(True)
rc,output,err = nft.cmd("add chain ip filter NGUARD")