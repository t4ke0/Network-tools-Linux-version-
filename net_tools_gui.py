#!/usr/bin/python3

#Author TAKEO 
#Description : Simple GUI pogram scan for online host and do other simple network stuff 
#				And it dont let you to be ARP spoofed 
# this program can only be runed in Linux Devices 

from PyQt5.QtGui import QPixmap ,QIcon
from PyQt5.QtWidgets import * 
from PyQt5.QtWidgets import QTableWidget
from PyQt5 import QtWidgets
from PyQt5.QtCore import *
from PyQt5 import QtCore
from PyQt5.uic import loadUi	
from sys import platform 
import sys, subprocess, time, os, socket ,urllib.request , json, re , logging
os.environ['PYGAME_HIDE_SUPPORT_PROMPT'] = 'hide'
import pygame
from scapy.all import *

if os.getuid() != 0 : 
	print('You are not Root')
	pritn('Please run as root')
	sys.exit()
else : 
	pass




class App(QWidget):
	def __init__(self):
		super().__init__()
		
		self.title = "Network TOOLS"
		self.left = 100
		self.top = 200
		self.width = 720
		self.height = 600
		self.initUI()

		


	def initUI(self):
		self.setWindowTitle(self.title)
		self.setFixedSize(self.width, self.height)#self.width, self.height)
		l = QLabel(self)
		l.move(160,20)
		l.setText('Network TOOLs')
		l.setStyleSheet("font:34pt;color:gray")

		

		b = QPushButton("Net Scan tools ",self)
		b.setGeometry(250,280,150,50)
		b.clicked.connect(self.buttonNetscan_clicked)
		

		b1 = QPushButton('Anti Arp Spoofing ', self)
		b1.setGeometry(250,350,150,50)
		b1.clicked.connect(self.buttonArp_clicked)


		self.show()

	@pyqtSlot()
	def buttonNetscan_clicked(self):
		self.cams = netscanW()
		self.cams.show()
		self.close()

	#@pyqtSlot() #Single window pop up  instead of switching to another window 
	def buttonArp_clicked(self):
		self.arp_window = arpW()
		self.arp_window.show()
		#self.cams = arpW()
		#self.cams.show()
		#self.close()

#add arp spoof window 
class arpW(QWidget):

	def __init__(self,parent=None):
		super().__init__(parent)
		self.setWindowTitle("WIFI GUARD ARP")
		self.setGeometry(100,200,740,600)
		self.retB = QPushButton("Return Main",self)
		self.retB.setGeometry(10,20,200,50)
		self.retB.clicked.connect(self.return_main)
		self.layout = QGridLayout()
		self.setLayout(self.layout)
#creating the radio button to start and stop the ARP GUARD 
		self.rb = QRadioButton("START")
		self.rb.setChecked(False)
		self.layout.addWidget(self.rb,0,0)
		self.rb.toggled.connect(self.guard_s)  

# Radio button for stopping 
		self.rb1 = QRadioButton("Stop")
		self.rb1.setChecked(False)
		self.layout.addWidget(self.rb1,0,1)
		self.rb1.toggled.connect(self.guard_stop)

# Label for When the thread is stopped 

		self.l1 = QtWidgets.QLabel(self)
		self.l1.setGeometry(60,350,600,70)
		self.l1.setStyleSheet("font:10pt;color:orange")

#Thread class 
		self.get_thr = Arp_thread()



# Label for the Warning 
		self.l = QtWidgets.QLabel(self)
		self.l.setGeometry(60,210,600,70)
		self.l.setStyleSheet("font:10pt;color:red")

	def guard_s(self):
		self.get_thr.started.connect(self.st_s)
		self.get_thr.warning.connect(self.warning)
		self.get_thr.srt()
		self.get_thr.start()



	def guard_stop(self):
		self.get_thr.finished.connect(self.thread_stop)
		self.get_thr.stop()
		

		

	def thread_stop(self,s):
		self.l1.setText(s)
		#self.get_thr.stop()
		self.get_thr.quit()
		self.get_thr.wait()

#Start string function connecting started signal with guard_s func
	def st_s(self,x):
		self.l1.setText(x)



	def warning(self,w):
		self.l.setText(w)


 						

	@pyqtSlot()
	def return_main(self):
		self.cams = App()
		self.cams.show()
		self.close()



class Arp_thread(QThread,QObject):
	#Signals here : 
	#warning signal 
	warning = pyqtSignal(str)
	started = pyqtSignal(str)
	finished = pyqtSignal(str)
	
	def __init__(self):
		QThread.__init__(self)
		
		



	def run(self):
		#get the gateway and the interface 
		cmd = subprocess.check_output(['ip','route'])
		g = cmd.translate(None, b'\r\n').decode().split()
		global gateway_ip
		gateway_ip = g[2]

		cmd2 = subprocess.check_output(['arp','-vn',gateway_ip])
		m = cmd2.translate(None,b'\r\n').decode().split()
		global gateway_mac
		gateway_mac = m[7]
		m1 = m[9]
		e = re.findall('[A-Z][^A-Z]*',m1) #Finding out What interface is up 
		s= ("").join(e)	
		global interface	
		interface = m1.split(s)
		#log file setup 
		logging.basicConfig(filename="arp_log.txt",
                            filemode='a',
                            format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
                            datefmt='%H:%M:%S',
                            level=logging.DEBUG)

		now = datetime.now()
		
		while self.is_running :
			self.started.emit('ARP Guard Started correctely!')
			c = subprocess.check_output(['arp','-vn',gateway_ip])
			c1 = c.translate(None,b'\r\n').decode().split()
			global c2
			c2 = c1[7]

			if c2 == gateway_mac :
				pass 
			else :
				self.warning.emit(f'{now} ARP SPOOFED BY {c2} Check the ARP log file')
				pygame.mixer.init()
				pygame.mixer.music.load('warning.wav')
				pygame.mixer.music.play()
				logging.info(f"Warning arp spoof by {c2}") 
				time.sleep(6)
				pygame.mixer.music.stop()
				break
	
	def srt(self): #start function adding True bool value to run function to start the infinit loop 
		self.is_running = True

	def stop(self): # stop infinit loop by replacing is_runnining value with False  
		self.is_running = False
		self.finished.emit("ARP GUARD has been stoped !")

	
		
	

class netscanW(QDialog):
	def __init__(self,parent=None):
		super().__init__(parent)
		self.setWindowTitle('Network scan')
		self.setGeometry(100,200,740,600)

		self.mainbutton = QPushButton('Go main Page !',self)
		self.mainbutton.setGeometry(10,10,200,50)
		self.mainbutton.clicked.connect(self.go_main)

		self.StartB = QPushButton('Start Scan',self)
		self.StartB.setGeometry(10,170,200,50)
		self.StartB.clicked.connect(self.StartB_clicked)

		self.ent1 = QLineEdit('Put the IP address Here',self)
		self.ent1.setGeometry(220,350,350,50)

		self.GatwB = QPushButton('Gateway address',self)
		self.GatwB.setGeometry(10,230,200,50)
		self.GatwB.clicked.connect(self.gateway)

		self.ipB = QPushButton('External IP',self)
		self.ipB.setGeometry(10,290,200,50)
		self.ipB.clicked.connect(self.IP_founder)

		self.iplB = QPushButton('IP Lookup',self)
		self.iplB.setGeometry(10,350,200,50)
		self.iplB.clicked.connect(self.ip_lookup)


		self.gate = QLabel(self)
		self.gate.setGeometry(220,230,200,50)

		self.ipX = QLabel(self)
		self.ipX.setGeometry(220,290,200,50)

		self.ipL = QLabel(self)
		self.ipL.setGeometry(150,430,250,75)

	def gateway(self):
		g = subprocess.check_output(['ip','route'])
		g0 = g.translate(None, b'\r\n').decode().split()
		gate = g0[2]
		self.gate.setText(f'Your gateway is : {gate}')

	def IP_founder(self):
		external_ip = urllib.request.urlopen('https://ident.me').read().decode('utf8')
		self.ipX.setText(f"IP :{external_ip}")

	def go_main(self):
		self.cams = App()
		self.cams.show()
		self.close()

	def ip_lookup(self): 
			
		ip = str(self.ent1.text())
		with urllib.request.urlopen(f'http://api.ipapi.com/api/{ip}?access_key=d6f48245085fb05889adab7397a5c34e&output=json') as url : 
			p = json.loads(url.read().decode())
			city = p['city']
			location = p['latitude'] , p['longitude']
			country = p['country_name']
			region = p['region_name']
			i = p['type']
			self.ipL.setText(f"City : {city}" +"\n"+ f"Country : {country}" +"\n"+ f"Region : {region}" +"\n"+ f"location : {location}" +"\n"+ f"IP type:  {i}") 
				 
	

	@pyqtSlot()
	def StartB_clicked(self):
		self.cams = show_scan()
		self.cams.show()
		self.close()

#Class for showing ONLINE HOST SCANNING 
class show_scan(QDialog,QObject):
	
	def __init__(self,parent=None):
		super().__init__(parent)
		self.setWindowTitle('Network scan')
		self.setGeometry(100,200,740,510)
		
		#
		self.l = QtWidgets.QLabel(self)
		self.l.setGeometry(10,90,250,50)
		self.l.setStyleSheet("font:11pt;color:red")


#Progress BAR
		
		self.progress = QProgressBar(self)
		self.progress.setGeometry(260,100,250,50)


		self.return_b = QPushButton("Return",self)
		self.return_b.setGeometry(10,20,200,50)
		self.return_b.clicked.connect(self.return_net)
		
		self.ss = QPushButton("Start Scanning",self)
		self.ss.setGeometry(390,20,200,50)
		self.ss.clicked.connect(self.Scan) 	
		#self.ent = QLineEdit("Put Here your Gateway_address/Number of hosts",self)
		#self.ent.setGeometry(10,80,350,50)

		self.table = QTableWidget(self)
		self.table.setRowCount(15)
		self.table.setColumnCount(3)
		self.table.setItem(0,0, QTableWidgetItem("Mac address"))
		self.table.setItem(0,1,QTableWidgetItem("IP ADDRESS"))
		self.table.setItem(0,2, QTableWidgetItem("Device manifacture/Host name"))
		#self.table.setSizeAdjustPolicy(QtWidgets.QAbstractScrollArea.AdjustToContents)
		#self.table.resizeColumnsToContents()
		header = self.table.horizontalHeader()
		header.setStretchLastSection(True)
		header.setSectionResizeMode(QHeaderView.Stretch)
		self.table.setGeometry(10,210,600,250)

	
	def Scan(self): #Connecting thread class with the GUI  #signals should always be connected with a function
		self.get_thread = Scan_thread()

		self.get_thread.change_value.connect(self.prog_val) #progress bar signal connecting 
		self.get_thread.result.connect(self.get_res)
		self.get_thread.result1.connect(self.get_res1)
		self.get_thread.result2.connect(self.get_res2)
		self.l.setText("Wait a Moment please !")
		self.get_thread.start()
		self.get_thread.finished.connect(self.finished)

	def get_res(self,a):
		j=1
		for i in a :  
			self.table.setItem(j,0, QTableWidgetItem(i))   
			j+=1
		
	def get_res1(self,b):
		o=1
		for i in b:  
			self.table.setItem(o,1, QTableWidgetItem(i))
			o+=1 
	
	def get_res2(self,c):
		t=1
		for i in c: 
			self.table.setItem(t,2, QTableWidgetItem(i))
			t+=1

	def finished(self,t):
		self.l.setText(t)
		self.l.setStyleSheet("font:11pt;color:green") 
	
	def prog_val(self,z):
		self.progress.setValue(z)

	
		
		
		

	@pyqtSlot()				
	def return_net(self):
		self.cams = netscanW()
		self.cams.show()
		self.close()



class Scan_thread(QThread,QObject): # thread class for the scan function
	result 	= pyqtSignal(list) #Creating Signals 
	result1 = pyqtSignal(list)
	result2 = pyqtSignal(list)
	finished = pyqtSignal(str)
	change_value = pyqtSignal(int)
	
	def __init__(self):
		QThread.__init__(self)
		

	def run(self):
		""" get the gateway address """
		a = subprocess.check_output(['ip','route'])
		g0 = a.translate(None, b'\r\n').decode().split()
		gateway = g0[2]
		prefix = '/24'
		l = gateway.split(',')
		l.append(prefix)
		Gate = ('').join(l)


		""" grab the network interface """
		cmd = subprocess.check_output(['arp','-vn',gateway])
		cmd0 = cmd.translate(None, b'\r\n').decode().split()
		m1 = cmd0[9]
		e = re.findall('[A-Z][^A-Z]*',m1) #Finding out What interface is up 
		s = ("").join(e)
		inter = m1.split(s)
		interface = inter[0]

		
		#put all ips addresses in one List 
		hosts = []
		#mac address List 
		MAC = []
		#MAC vendor List 
		V = []

		conf.verb = 0
		 
		ans,unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = Gate), timeout = 2, iface = interface ,inter= 0.1)	
		count = 0 
		
		for snd,rcv in ans : 
			mac = rcv[Ether].src
			with urllib.request.urlopen(f'https://api.macvendors.com/{mac}') as url:		 
				vendor = url.read().decode()
				time.sleep(1)				
				hosts.append(rcv[Ether].src)
				MAC.append(rcv[ARP].psrc)
				V.append(vendor)
				count+=50
				self.change_value.emit(count)		
										
		self.result.emit(hosts)
		self.result1.emit(MAC)
		self.result2.emit(V)
		self.finished.emit('Finished')	



if __name__ == '__main__':
	app = QApplication(sys.argv)
	ex = App()
	sys.exit(app.exec_())



# FIN PROJECT 
# Greeting TAKEO 