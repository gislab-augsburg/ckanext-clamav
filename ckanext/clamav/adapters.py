import socket
import sys
import struct
import random
import string
import os

from clamd import ClamdNetworkSocket, ConnectionError, BufferTooLongError

import ckanext.clamav.config as c


class CustomClamdNetworkSocket(ClamdNetworkSocket):
    """Patches the default ClamdNetworkSocket adapter
    with changed _init_socket method. The default implementation doesn't
    respect timeout properly.

    Additionally this class patches the default ClamdNetworkSocket adapter 
    with changed instream method. This prevents the socket from shutting down
    and producing a timeout error before the scan response is received.

    Args:
        ClamdNetworkSocket (ClamdNetworkSocket): original clamd network adapter
    """
    def _init_socket(self):
        """
        internal use only
        """
        try:
            self.clamd_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.clamd_socket.settimeout(self.timeout)
            self.clamd_socket.connect((self.host, self.port))

        except (socket.error, socket.timeout):
            e = sys.exc_info()[1]
            raise ConnectionError(self._error_message(e))
        
    def instream(self, buff):
        """
        Scan a buffer

        buff  filelikeobj: buffer to scan

        return:
          - (dict): {filename1: ("virusname", "status")}

        May raise :
          - BufferTooLongError: if the buffer size exceeds clamd limits
          - ConnectionError: in case of communication problem
        """

        try:
            self._init_socket()
            self._send_command('INSTREAM')

            max_chunk_size = 1024  # MUST be < StreamMaxLength in /etc/clamav/clamd.conf

            chunk = buff.read(max_chunk_size)

            while chunk:
                size = struct.pack(b'!L', len(chunk))
                self.clamd_socket.send(size + chunk)
                chunk = buff.read(max_chunk_size)
                
                # Generate dummy file with random string
                write_dir = c.CLAMAV_CONF_WRITE_DIR
                print('write dir for dummy file:')
                print(write_dir)
                random_str = ''.join(random.choice(string.ascii_letters) for i in range(8))
                dummy_file = f'{write_dir}/{random_str}'
                f = open(dummy_file, 'w')
                f.close()
                os.remove(dummy_file)

            self.clamd_socket.send(struct.pack(b'!L', 0))

            result = self._recv_response()

            if len(result) > 0:
                if result == 'INSTREAM size limit exceeded. ERROR':
                    raise BufferTooLongError(result)           

                filename, reason, status = self._parse_response(result)
                return {filename: (status, reason)}
        
        finally:
            self._close_socket()
            