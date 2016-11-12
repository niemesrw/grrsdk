import grrsdk

g = grrsdk.GRRClient()
g.print_client_info('10.12.52.32')

#g.iterate_clients()
#g.execute_python_hack('get_mbambr.py', '10.12.52.32')
from flask import Flask, request
import json

app = Flask(__name__)

@app.route('/',methods=['POST'])
def foo():
   data = json.loads(request.data)
   print "New commit by: {}".format(data['commits'][0]['author']['name'])
   return "OK"

if __name__ == '__main__':
   app.run()
