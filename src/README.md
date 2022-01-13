# To run cicflowmeter
- step 1 : cd cicflowmeter
- step 2: list interfaces
       &nbsp; &nbsp; &nbsp;  &nbsp;  &nbsp;	java -Djava.library.path=jnetpcap -jar CICFlowMeter.jar --list</li>

- step 3: run cicflowmeter on any interfaces
	&nbsp; &nbsp; &nbsp;  &nbsp; java -Djava.library.path=jnetpcap -jar CICFlowMeter.jar -i [interface] start
	&nbsp; &nbsp; &nbsp;  &nbsp;  eg:java -Djava.library.path=jnetpcap -jar CICFlowMeter.jar -i wlp2s0 start </li>


