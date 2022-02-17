# To run cicflowmeter .jar
- step 1 : cd cicflowmeter
- step 2: list interfaces
       &nbsp; &nbsp; &nbsp;  &nbsp;  &nbsp;	java -Djava.library.path=jnetpcap -jar CICFlowMeter.jar --list</li>

- step 3: run cicflowmeter on any interfaces
	&nbsp; &nbsp; &nbsp;  &nbsp; java -Djava.library.path=jnetpcap -jar CICFlowMeter.jar -i [interface] start
	&nbsp; &nbsp; &nbsp;  &nbsp;  eg:java -Djava.library.path=jnetpcap -jar CICFlowMeter.jar -i wlp2s0 start </li>


# To run cicflowmeter through gradle

- sudo bash
- chmod +x ./gradlew
- ./grdlew shell -PappArgs='["[options]"]' 
- for eg: to list interfaces
     ./gradlew shell -PappArgs=''["--list"]' 
-for eg: to start capturing
    ./gradlew shell -PappArgs='["-i","wlp2s0","start"]'
- for eg : to lauch graphical userinterface
     ./gradlew shell -PappArgs='["--gui"]'
- for eg: to capture using tcpdump
     ./gradlew shell -PappArgs='["-i","wlp2s0","tcpdump"]'


