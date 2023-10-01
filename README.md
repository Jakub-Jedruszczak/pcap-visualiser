# pcap-visualiser

This is a project I completed for an Incident Response unit as part of my degree. This project is a visualiser for .pcap files using Python to show statistics about packets to potentially help Security Analysts with identifying malicious packets.

# How to use

``` Python
pip install dpkt
python3 visualiser.py
```

After running the Python file, enter the name of the pcap file to be analysed. Make sure to include the file extension when passing the name of the file.

### Required packages
  * matplotlib
  * dpkt
  * numpy
  * socket
