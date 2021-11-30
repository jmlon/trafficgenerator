# A simple traffic generator using scapy

## Installation
```
source .venv/bin/activate           # If using virtual environments
pip3 install -r requirements.txt
```

## Running the program
```
source .venv/bin/activate           # If using virtual environments
python3 trafficgen.py sample_scenary
```

Capturing traffic with tcpdump
```
tcpdump -n port 1234
tcpdump -i lo -n port 1234     # When sending to same host
```



## References
[Scapy documentation](https://scapy.readthedocs.io/en/latest/introduction.html)  
[The Art of Packet Creafting](https://0xbharath.github.io/art-of-packet-crafting-with-scapy/scapy/sending_recieving/index.html)  
[Scapy examples](https://www.programcreek.com/python/example/81628/scapy.all.UDP)  
[tcpdump Tutorial](https://danielmiessler.com/study/tcpdump/)  

