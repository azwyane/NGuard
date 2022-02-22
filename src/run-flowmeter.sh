#!/bin/bash
java -Djava.library.path="jnetpcap/linux/jnetpcap" -jar ./cicflowmeter/'jar file'/CICFlowMeterV3.jar -i wlp2s0 tcpdump
