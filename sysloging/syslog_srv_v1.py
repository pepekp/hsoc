import socketserver
import logging

import logging
import logging.handlers
import socketserver
import datetime
import time
import os
import glob
from datetime import datetime, timedelta
from venv import logger
from directory_path import syslog_dir_path

#syslog_dir_name = '/home/pepe/PycharmProjects/siem/sysloging/syslogs/'

# def find_last_created_file():
#     files_path = os.path.join(syslog_dir_name, '*')
#     files = sorted(glob.iglob(files_path), key=os.path.getctime, reverse=True)
#     file_name = files[0].split('/')
#     last_file_in_dir = file_name[-1]
#     file_name_time = os.path.getctime(syslog_dir_name + file_name[-1])
#     # Convert Unix time
#     file_time = datetime.fromtimestamp(file_name_time)
#     last_created_file_time = file_time.strftime("%a_%b_%d_%H_%M_%S_%Y")
#     # Convert str to date.time
#     last_created_file_time_dt = datetime.strptime(last_created_file_time, "%a_%b_%d_%H_%M_%S_%Y")
#     print('file name and file create time ')
#     print(last_created_file_time_dt)
#
#     return last_created_file_time, last_file_in_dir
#     # print(files[0])
#     # print(file_name[-1])
# last_created_file_and_time = find_last_created_file()
# print(f'Function return {last_created_file_and_time[0]} {last_created_file_and_time[1]}')
# # print(type(last_created_file_and_time[0]))
# # print(type(last_created_file_and_time[1]))
# print('==================================================================================')
# def generate_syslog_file():
#     t = time.localtime()
#     current_time = time.strftime("%a_%b_%d_%H_%M_%S_%Y", t)
#     time_now = datetime.now()
#     # Define how old should be the last created file
#     time_delta = timedelta(minutes=5)
#     time_ago = time_now - time_delta
#     create_time_ago = time_ago.strftime("%a_%b_%d_%H_%M_%S_%Y")
#     create_time_ago_datetime = datetime.strptime(create_time_ago, "%a_%b_%d_%H_%M_%S_%Y")
#     last_created_file_datetime = datetime.strptime(last_created_file_and_time[0], "%a_%b_%d_%H_%M_%S_%Y")
#     # Generate datetime var based on file create time
#     if create_time_ago_datetime > last_created_file_datetime:
#         t = time.localtime()
#         current_time = time.strftime("%a_%b_%d_%H_%M_%S_%Y", t)
#         file_name = current_time + '.log'
#         with open(syslog_dir_name + '/' + file_name, 'w') as log_file:
#             log_file.close()
#         print(f'New log file is has been created {file_name}')
#     else:
#         print('use last created file')
#         file_name = last_created_file_and_time[1]
#     return file_name
# log_file_name = generate_syslog_file()
# print(f'generate syslog file {log_file_name}')

# Configuration
HOST, PORT = "0.0.0.0", 1514  # Listen on all interfaces, standard syslog port
LOG_FILE = "syslog.log"

# Set up logging to a file
#rotator = logging.FileHandler(log_file_name, mode='a', encoding=None, errors=None)
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s',
                    filename=f'{syslog_dir_path}/{LOG_FILE}', filemode='a')

def log_rotator():
    logger = logging.getLogger()
    handler = logging.handlers.TimedRotatingFileHandler(f'{syslog_dir_path}/{LOG_FILE}', when='M', interval=5, backupCount=1, utc=False)
    formatter = logging.Formatter('%(asctime)s %(message)s')
    handler.setFormatter(formatter)
      # or pass string to give it a name
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger_adapter = logging.LoggerAdapter(logger, extra={})
    return logger_adapter

logger = log_rotator()

class SyslogUDPHandler(socketserver.BaseRequestHandler):
    """Handles incoming UDP syslog messages."""
    print('server start')
    def handle(self) -> None:
        data = bytes.decode(self.request[0].strip())  # Decode the received bytes
        #print(type(data))
        socket = self.request[1]  # The socket, not used here but can be useful
        print(f"{self.client_address[0]}: {data}")  # Print to console
        #logging.info(data)  # Log to file
        logger.info(data)
        print('log rotator')

def main():
    """Sets up and runs the UDP syslog server."""
    print('main function')
    try:
        server = socketserver.UDPServer((HOST, PORT), SyslogUDPHandler)
        print(f"Syslog server listening on {HOST}:{PORT} (UDP)")
        server.serve_forever(poll_interval=0.5)  # Keep the server running
    except (IOError, SystemExit) as e:
        print(f"Error starting syslog server: {e}")
    except KeyboardInterrupt:
        print("Shutting down syslog server")
        server.shutdown()  #added server shutdown


if __name__ == "__main__":
    #find_last_created_file()
    #generate_syslog_file()
    #log_file_name = generate_syslog_file()
    #print(f'generate syslog file {log_file_name}')
    main()

