"""
Syslog server
"""
import logging
import logging.handlers
import socketserver
from venv import logger
from directory_path import syslog_dir_path


# Configuration
HOST, PORT = "0.0.0.0", 1514  # Listen on all interfaces, standard syslog port
LOG_FILE = "syslog.log"

# Set up logging to a file

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

        socket = self.request[1]  # The socket, not used here but can be useful
        print(f"{self.client_address[0]}: {data}")  # Print to console
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
    main()

