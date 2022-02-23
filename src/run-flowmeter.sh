#!/bin/bash
java -Djava.library.path="./cicflowmeter/jarfile/jnetpcap/linux/jnetpcap" -jar ./cicflowmeter/jarfile/CICFlowMeterV3.jar -i wlan0 tcpdump
