import grrsdk

g = grrsdk.GRRClient()
g.print_client_info('10.12.52.32')
#g.iterate_clients()
#g.execute_python_hack('get_mbambr.py', '10.12.52.32')
