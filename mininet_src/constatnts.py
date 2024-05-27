import os

controller_host = os.getenv('CONTROLLER_HOST', '172.16.145.129')
controller_port = int(os.getenv('CONTROLLER_PORT', '6653'))
