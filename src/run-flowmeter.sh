#!/bin/bash
java -Djava.library.path="./cicflowmeter/jarfile/jnetpcap/linux/jnetpcap" -jar ./cicflowmeter/jarfile/CICFlowMeterV3.jar -i wlp2s0 -d predictions/flow/ tcpdump
