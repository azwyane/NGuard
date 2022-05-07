# To run cicflowmeter .jar
note:run cicflowmeter as root

- step 1 : cd cicflowmeter
- step 2: list interfaces
       &nbsp; &nbsp; &nbsp;  &nbsp;  &nbsp;	java -Djava.library.path=jnetpcap -jar CICFlowMeter.jar --list</li>

- step 3: run cicflowmeter on any interfaces
	&nbsp; &nbsp; &nbsp;  &nbsp; java -Djava.library.path=[jnetpcap path] -jar CICFlowMeter.jar -i [interface] start
	&nbsp; &nbsp; &nbsp;  &nbsp;  eg:java -Djava.library.path=jnetpcap/linux/jnetpcap -jar CICFlowMeter.jar -i wlp2s0 start </li>


# To run cicflowmeter through gradle

- sudo bash
- chmod +x ./gradlew
- ./grdlew shell -PappArgs='["[options]"]' 
- for eg: to list interfaces
     ./gradlew shell -PappArgs=''["--list"]' 
- for eg: to start capturing
    ./gradlew shell -PappArgs='["-i","wlp2s0","start"]'
- for eg : to lauch graphical userinterface
     ./gradlew shell -PappArgs='["--gui"]'
- for eg: to capture using tcpdump
     ./gradlew shell -PappArgs='["-i","wlp2s0","tcpdump"]'


# Procedure to run NGuard

- step 1: goto folder NGuard/src

### Run sensor
> requirements include libpcap installed
- step 2: execute the below as:
```
$ sudo ./run-flowmeter.sh
``` 
### Run brain
> pip install -r requirements.txt
- step 3: execute as:
```
$ ./run-brain.sh
```

### Run ips
> need to install nftables and python3-nftables
- step 4: execute as:
```
$ ./run-ips.sh
```

### Finally run the web server
- step 5: execute as:
```
$ ./run-server.sh
```


### Some configs that needs edit as per the requirements
- brain_config.json
- server_config.json
- ips_config.json


### Logs
- logs (flowmeter logs)
- brain_logs(default logs for brain)
- ips_logs(default logs for ips)





