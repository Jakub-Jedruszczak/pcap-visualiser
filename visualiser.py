import matplotlib.pyplot as plt 

from matplotlib.widgets import Slider 

import numpy as np # for maths and stuff 

import dpkt 

import socket 

from random import choice # for picking random colours for the graph plots 



l_ts = [] # list of all timestamps 

l_prt = [] # list of all ports 

ip_dic = {} # keeps track of all IP addresses already in the megalist 

megalist =[] # stores IP as well as all source packets related to that IP in a 2D list 

eth = None 

ip = None 

tcp = None 



def index_2D (item, l): 

	for i in l: 

		if item in i: 

			return i, l.index(i) 

	return 0 



def load_data(pcap): 

	f = open(pcap, 'rb') # rb = read but binary - pcaps are not written in plaintext 

	pcap = dpkt.pcap.Reader(f) 

	for ts, buf in pcap: 

		final_timestamp = ts 

		eth = dpkt.ethernet.Ethernet(buf) 

		if type(eth.data) != dpkt.ip.IP: 

			continue # not an IP packet! we want to ignore those 

		ip = eth.data      

		#print(ip.get_proto(ip.p)) # shows protocol of the packet 

		if type(ip.data) != dpkt.tcp.TCP: 

			continue # not a TCP packet! we want to ignore these too       

		tcp = ip.data 

		#print(tcp.__class__.__name__) 

		#print(tcp.data) 

		l_ts.append(ts) 

		l_prt.append(tcp.dport) 

		if str(socket.inet_ntoa(ip.src)) not in ip_dic: 

			ip_dic[str(socket.inet_ntoa(ip.src))] = 0 

			#print(ip_dic) 

			megalist.append([str(socket.inet_ntoa(ip.src))]) 

			megalist[index_2D(str(socket.inet_ntoa(ip.src)), megalist)[1]].append(ts) 

			megalist[index_2D(str(socket.inet_ntoa(ip.src)), megalist)[1]].append(tcp.dport) 

		else: 

			#print(index_2D(str(socket.inet_ntoa(ip.src)), megalist)) 

			megalist[index_2D(str(socket.inet_ntoa(ip.src)), megalist)[1]].append(ts) 

			megalist[index_2D(str(socket.inet_ntoa(ip.src)), megalist)[1]].append(tcp.dport)	 

	f.close() 



plt.style.use('ggplot') 



fig, ax = plt.subplots(figsize=(9,6)) 

plt.subplots_adjust(bottom = 0.25) 

ax_slider = plt.axes([0.1,0.1,0.8,0.05]) # makes a 'frame' for the slider 



load_data(input("Enter filename:\n")) 



y = np.arange(len([1,2,0.5,4,5])) # for the bar chart 



def change_graph(i): # an event that triggers every time the slider is moved 

	ax.clear() 

	if i == 0: # bar chart 

		b = ax.barh(y, [1,2,0.5,4,5], height = .8, color=['C0','C1','C2','C3','C4','C5','C6','C7','C8','C9','C10'], align = 'center') 

		ax.set_title('Most Common Protocols') 

		ax.set_yticks(y, labels=['p1','p2','p3','p4','p5']) 

		ax.bar_label(b) 

		ax.set_xlabel('Frequency') 



	if i == 1: # line graph 

		for i in megalist: 

			ax.plot(i[1:len(i):2], i[2:len(i):2], choice(['C0','C1','C2','C3','C4','C5','C6','C7','C8','C9']) + '.', label = i[0]) 

			ax.set_title('Requests Over Time') 

			ax.set_xlabel('Time, seconds') 

			ax.set_ylabel('Source Port Number') 

			ax.legend() # shows which colour corresponds to which IP address 

	if i == 2: # pie chart 

		print('pie') # work in progress 



plt.draw() 



graph_slider = Slider(ax_slider, "Graph", valmin = 0, valmax = 2, valinit = 0, valstep = 1)  

graph_slider.on_changed(change_graph) 



plt.show() 


