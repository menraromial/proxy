import socket
import threading
import re
import argparse
import ssl
import logging
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('forward_proxy')

class ForwardProxy:
    def __init__(self, host='0.0.0.0', port=8080, blocked_domains=None, 
                 anonymize=False, use_ssl=False, cert_file=None, key_file=None):
        self.host = host
        self.port = port
        self.blocked_domains = blocked_domains or []
        self.anonymize = anonymize
        self.use_ssl = use_ssl
        self.cert_file = cert_file
        self.key_file = key_file
        
        # Compile regex patterns for blocked domains
        self.blocked_patterns = [re.compile(pattern) for pattern in self.blocked_domains]
        
    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind((self.host, self.port))
            server_socket.listen(100)
            logger.info(f"Proxy server started on {self.host}:{self.port}")
            
            while True:
                client_socket, client_address = server_socket.accept()
                logger.info(f"Connection from {client_address}")
                
                if self.use_ssl:
                    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                    context.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)
                    client_socket = context.wrap_socket(client_socket, server_side=True)
                
                client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
                client_thread.daemon = True
                client_thread.start()
                
        except Exception as e:
            logger.error(f"Error starting proxy server: {e}")
        
        finally:
            server_socket.close()
    
    def handle_client(self, client_socket):
        request_data = b''
        
        try:
            # Receive the request from the client
            while True:
                chunk = client_socket.recv(4096)
                request_data += chunk
                if len(chunk) < 4096 or not chunk:
                    break
            
            if not request_data:
                client_socket.close()
                return
            
            # Parse the request
            request_lines = request_data.split(b'\r\n')
            first_line = request_lines[0].decode('utf-8')
            method, url, protocol = first_line.split()
            
            # Handle CONNECT method differently (for HTTPS)
            if method == 'CONNECT':
                self.handle_connect(client_socket, request_data)
                return
            
            # Extract host and port from request
            host_line = next((line for line in request_lines if line.startswith(b'Host:')), None)
            
            if not host_line:
                client_socket.close()
                return
            
            host_port = host_line.split(b':')[1].strip().decode('utf-8')
            host = host_port.split(':')[0]
            port = 80  # Default HTTP port
            
            if ':' in host_port:
                port = int(host_port.split(':')[1])
            
            # Check if the domain is blocked
            if self.is_blocked(host):
                self.send_blocked_response(client_socket)
                return
            
            # Modify request for anonymity if needed
            if self.anonymize:
                request_data = self.anonymize_request(request_data)
            
            # Connect to the remote server
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.settimeout(10)
            server_socket.connect((host, port))
            
            # Forward the request to the server
            server_socket.sendall(request_data)
            
            # Receive the response from the server
            response_data = b''
            while True:
                chunk = server_socket.recv(4096)
                if not chunk:
                    break
                response_data += chunk
            
            # Forward the response back to the client
            client_socket.sendall(response_data)
            
        except Exception as e:
            logger.error(f"Error handling client: {e}")
        
        finally:
            try:
                client_socket.close()
                if 'server_socket' in locals():
                    server_socket.close()
            except:
                pass
    
    def handle_connect(self, client_socket, request_data):
        try:
            # Extract host and port from CONNECT request
            request_line = request_data.split(b'\r\n')[0].decode('utf-8')
            _, address, _ = request_line.split()
            host, port = address.split(':')
            
            # Check if the domain is blocked
            if self.is_blocked(host):
                self.send_blocked_response(client_socket)
                return
            
            # Connect to the remote server
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.settimeout(10)
            server_socket.connect((host, int(port)))
            
            # Send success response to the client
            success_response = b"HTTP/1.1 200 Connection Established\r\n\r\n"
            client_socket.sendall(success_response)
            
            # Start bidirectional tunneling
            self.tunnel_traffic(client_socket, server_socket)
        
        except Exception as e:
            logger.error(f"Error handling CONNECT: {e}")
            try:
                client_socket.close()
            except:
                pass
    
    def tunnel_traffic(self, client_socket, server_socket):
        # Create threads for bidirectional tunneling
        client_to_server = threading.Thread(target=self.forward_data, 
                                            args=(client_socket, server_socket))
        server_to_client = threading.Thread(target=self.forward_data, 
                                            args=(server_socket, client_socket))
        
        client_to_server.daemon = True
        server_to_client.daemon = True
        
        client_to_server.start()
        server_to_client.start()
        
        # Wait for both threads to complete
        client_to_server.join()
        server_to_client.join()
    
    def forward_data(self, source, destination):
        try:
            while True:
                data = source.recv(4096)
                if not data:
                    break
                destination.sendall(data)
        except:
            pass
        finally:
            try:
                source.close()
                destination.close()
            except:
                pass
    
    def is_blocked(self, domain):
        for pattern in self.blocked_patterns:
            if pattern.search(domain):
                logger.info(f"Blocked access to domain: {domain}")
                return True
        return False
    
    def send_blocked_response(self, client_socket):
        blocked_html = """
        <html>
        <head><title>Access Blocked</title></head>
        <body>
        <h1>Access Blocked</h1>
        <p>The requested domain has been blocked by the proxy administrator.</p>
        </body>
        </html>
        """
        response = f"HTTP/1.1 403 Forbidden\r\n"
        response += f"Content-Type: text/html\r\n"
        response += f"Content-Length: {len(blocked_html)}\r\n"
        response += f"Connection: close\r\n\r\n"
        response += blocked_html
        
        client_socket.sendall(response.encode())
        client_socket.close()
    
    def anonymize_request(self, request_data):
        # Convert to string for easier manipulation
        lines = request_data.split(b'\r\n')
        headers = []
        
        # Extract headers to modify
        for i, line in enumerate(lines):
            if i == 0 or not line:
                headers.append(line)
                continue
                
            # Remove referrer header
            if line.lower().startswith(b'referer:'):
                continue
            
            # Remove cookies
            if line.lower().startswith(b'cookie:'):
                continue
                
            # Remove or modify user agent
            if line.lower().startswith(b'user-agent:'):
                headers.append(b'User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0')
                continue
                
            # Add Do Not Track header
            if line.lower().startswith(b'dnt:'):
                continue
                
            headers.append(line)
        
        # Add privacy headers if not present
        if not any(h.lower().startswith(b'dnt:') for h in headers):
            headers.insert(1, b'DNT: 1')
            
        # Add X-Forwarded-For with anonymized IP
        if not any(h.lower().startswith(b'x-forwarded-for:') for h in headers):
            headers.insert(1, b'X-Forwarded-For: 0.0.0.0')
        
        # Reconstruct the request
        return b'\r\n'.join(headers)

def main():
    parser = argparse.ArgumentParser(description='Simple Forward Proxy Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind the proxy server to')
    parser.add_argument('--port', type=int, default=8080, help='Port to bind the proxy server to')
    parser.add_argument('--block', nargs='+', default=[], help='List of domains to block (regex patterns)')
    parser.add_argument('--anonymize', action='store_true', help='Enable anonymization features')
    parser.add_argument('--ssl', action='store_true', help='Enable SSL for encrypted connections')
    parser.add_argument('--cert', help='Path to SSL certificate file')
    parser.add_argument('--key', help='Path to SSL key file')
    
    args = parser.parse_args()
    
    if args.ssl and (not args.cert or not args.key):
        parser.error("SSL requires both --cert and --key arguments")
    
    proxy = ForwardProxy(
        host=args.host,
        port=args.port,
        blocked_domains=args.block,
        anonymize=args.anonymize,
        use_ssl=args.ssl,
        cert_file=args.cert,
        key_file=args.key
    )
    
    proxy.start()

if __name__ == "__main__":
    main()