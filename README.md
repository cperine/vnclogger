# VNC logger

This is primarily the work of [Jon Oberheide](https://jon.oberheide.org/). I have done a bit of modification to capture the RFB client cut command and the data in there. I have also made a quick and dirty version that accepts pcaps instead of listening to an interface.

When working on some honeypots, we wanted to invisibly log keys on the VNC systems we put online. We noticed attackers using copy/paste which meant digging through the pcaps for vnc.client_cut_text. I figured it would be nice to have the keylogging and the copy/paste logging all in one location. We did all of our processing with pcaps so being able to pull directly from a file is easier than using tcpreplay.

## Requirements

### Python 2.7.18
Yes, it's out of date. I'm looking at making a Python 3 version.


### [libevent 1.4.x](https://libevent.org/)
You will likely have to compile the 1.4.x code from scratch as most linux distro's push the 2.x version.
I the have forked the source code for libevent in case they ever pull their code down.


### [libpcap](https://www.tcpdump.org/)
You can probably use your linux distro's version of libpcap.
I the have forked the source code for libpcap in case they ever pull their code down.


### Python libraries

```
pip install dpkt
pip install pypcap
pip install event
```


## Use

### vnclogger.py
```
sudo python2 vnclogger.py -i eth0
```
You can alter the interface and filter via command arguments or in the code.


### vnclogger_pcap.py
```
sudo python2 vnclogger_pcap.py -f input.pcap
```
You can alter the filter via command arguments or in the code. You can alter the pcap file in the command argument.


### vnclogger_orig.py
Jon's original work for reference
