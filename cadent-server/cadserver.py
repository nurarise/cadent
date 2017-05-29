#!/usr/bin/python
from BaseHTTPServer import BaseHTTPRequestHandler,HTTPServer
import json

PORT_NUMBER = 8080

#This class will handles any incoming request from
#the browser 
class CadentHandler(BaseHTTPRequestHandler):
	
	#Handler for the GET requests
	def do_GET(self):
		self.send_response(200)
		self.send_header('Content-type','text/html')
		self.end_headers()
		# Send the html message
		self.wfile.write("Cadent Server is running !")
		return

	#Handler for the POST requests
	def do_POST(self):
		# self._set_headers()
		print ("in post method")
		self.data_string = self.rfile.read(int(self.headers['Content-Length']))
		
		self.send_response(200)
		self.end_headers()
		data = json.loads(self.data_string)
		with open("testfile.json", "w") as outfile:
			json.dump(data, outfile)
			return
try:
	#Create a web server and define the handler to manage the
	#incoming request
	server = HTTPServer(('', PORT_NUMBER), CadentHandler)
	print ("Started httpserver on port:" + str(PORT_NUMBER) )
	
	#Wait forever for incoming htto requests
	server.serve_forever()

except KeyboardInterrupt:
	print ("^C received, shutting down the web server")
	server.socket.close()
