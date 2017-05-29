import httplib
import json

connection = httplib.HTTPConnection("localhost", 8080, timeout=10)

headers = {"Content-type": "application/json"}

foo = {"report": {
					"title":"Cadent Wifi performance tool" ,
					"SSID" : "testap" , 
					"Signal Quality" : 90 }
		}
json_foo = json.dumps(foo)

connection.request('POST', 'http://localhost:8080', json_foo, headers)

response = connection.getresponse()
print(response.read().decode())
