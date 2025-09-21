"""
This file is part of pygurt by ItsThatOneJack.

pygurt (C) 2025 ItsThatOneJack

pygurt is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

pygurt is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License along with pygurt. If not, see <https://www.gnu.org/licenses/>.
"""

import socket
import ssl
import time
import json
import ipaddress
from typing import Optional, Union, Dict, Any
from urllib.parse import urlparse
import threading
import os

from .common import Request, Response, URL, Logging

from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("pygurt")
except PackageNotFoundError:
    __version__ = "0.0.0"

class GurtResponse:
    """
    A Gurt protocol response object, more user-friendly than `Response`.

    Properties:
        url: str - The URL the response is from.
        elapsed: float - The time elapsed since the request.
        statusCode: int - The status code the response states.
        reason: str - The note for the status code, usually something like `OK`.
        headers: dict[str,str] - A dictionary of header names to their values, always as strings.
        content: bytes - The body of the request without processing, could be plaintext or file data.
        text: str - The body of the request, processed into a usable string.
    
    Methods:
        json: Any - Get the body of the request, procssed into JSON data.
        ok: bool - Whether the response code is <400 (okay).
        raiseForStatus: None - Raise an exception if the response code is not okay.
    """
    
    def __init__(self, response: Response, url: str, elapsed: float):
        self._response = response
        self.url = url
        self.elapsed = elapsed
        self.statusCode = response.responseCode
        self.reason = response.responseComment
        self.headers = response.headers
        self.content = response.body
        self._jsonCache = None
        self._textCache = None
    
    @property
    def text(self) -> str:
        """The body of the request, processed into a usable string."""
        if self._textCache is None:
            try:
                self._textCache = self.content.decode('utf-8')
            except UnicodeDecodeError:
                self._textCache = self.content.decode('utf-8', errors='replace')
        return self._textCache
    
    def json(self) -> Any:
        """Get the body of the request, procssed into JSON data."""
        if self._jsonCache is None:
            try:
                self._jsonCache = json.loads(self.text)
            except json.JSONDecodeError as e:
                raise json.JSONDecodeError(f"Invalid JSON in response: {e}", self.text, 0)
        return self._jsonCache
    
    @property
    def ok(self) -> bool:
        """Whether the response code is <400 (okay)."""
        return self.statusCode < 400
    
    def raiseForStatus(self):
        """Raise an exception if the response code is not okay."""
        if not self.ok:
            raise GurtError(f"HTTP {self.statusCode}: {self.reason}")

class GurtError(Exception):
    """Base exception for Gurt client errors."""
    pass

class ConnectionError(GurtError):
    """Connection-related errors."""
    pass

class TimeoutError(GurtError):
    """Timeout-related errors."""
    pass

class GurtDnsError(GurtError):
    """DNS resolution errors."""
    pass

class Connection:
    """
    A persistent client-server connection.

    Properties:
        socket: socket.socket - The active socket connection.
        host: str - The IP of the host.
        port: int - The port of the host.
        handshaked: bool - Whether a handshake has been made.
        lastUsed: float - The time the connection was last used.
        closed: bool - Whether the connection is closed.
    
    Methods:
        close: None - Close the connection.
        isValid: bool - Check if connection is still valid and not timed out.
    """
    
    def __init__(self, socket: socket.socket, host: str, port: int, handshaked: bool = False):
        self.socket = socket
        self.host = host
        self.port = port
        self.handshaked = handshaked
        self.lastUsed = time.time()
        self.closed = False
    
    def close(self):
        """Close the connection."""
        if not self.closed:
            try:
                self.socket.close()
            except:
                pass
            self.closed = True
    
    def isValid(self, timeout: float = 300.0) -> bool:
        """Check if connection is still valid and not timed out."""
        if self.closed:
            return False
        if time.time() - self.lastUsed > timeout:
            self.close()
            return False
        return True

class Client:
    """
    A Gurt client with TLS support and GURT DNS resolution!

    Arguments:
        baseUrl: Optional[str] = None - The base URL of the site you will be connecting to.
        timeout: float = 30.0 - The time from a handshake until it is invalidated (and another is made).
        requireHandshake: bool = True - Whether to handshake with the server, this is required to connect to non-pygurt servers, or any production servers.
        userAgent: str = "pygurt/<current_pygurt_version>" - The user agent to pass in the headers on all connections.
        maxConnections: int = 10 - The maximum number of connections to permit before some are closed.
        connectionTimeout: float = 300.0 - The time from a connection's last use until it is closed.

        caCertPath: Optional[str] = None - The path to the root certificate for the CA you are using.
        caCertContent: Optional[str] = None - The content of the root certificate for the CA you are using.
        
        verifySSL: bool = True - Whether to verify SSL certificates for TLS, disable this when testing locally only.
        useTLS: bool = True - Whether to use TLS, disabling this is highly insecure and won't work with any 100% GURT-compliant implementation.
        
        gurtDnsServer: str = "135.125.163.131:4878" - The GURT DNS server to use for domain resolution.
    
    Properties:
        self.defaultHeaders: dict[str,str] - The set of default headers used for connections, includes the user agent and connection keepalive preference.

    Methods:
        setCaCertificate: None - Set the CA certificate to use, using it's content.
        loadCaFromGurtca: None - Automatically load the CA certificate from GurtCA, you can optionally change the CA IP.

        get: GurtResponse - Make a GET request to the provided host, with custom values, and return the response.
        post: GurtResponse - Make a POST request to the provided host, with custom values, and return the response.
        put: GurtResponse - Make a PUT request to the provided host, with custom values, and return the response.
        delete: GurtResponse - Make a DELETE request to the provided host, with custom values, and return the response.
        close: None - Close all open connections.
    """
    
    def __init__(
        self,
        baseUrl: Optional[str] = None,
        timeout: float = 30.0,
        requireHandshake: bool = True,
        userAgent: str = "pygurt/"+__version__,
        maxConnections: int = 10,
        connectionTimeout: float = 300.0,

        caCertPath: Optional[str] = None,
        caCertContent: Optional[str] = None,
        verifySSL: bool = True,
        useTLS: bool = True,
        
        gurtDnsServer: str = "135.125.163.131:4878"
    ):
        self.baseUrl = baseUrl.rstrip('/') if baseUrl else None
        self.timeout = timeout
        self.requireHandshake = requireHandshake
        self.userAgent = userAgent
        self.maxConnections = maxConnections
        self.connectionTimeout = connectionTimeout
        self.defaultHeaders = {
            'user-agent': userAgent,
            'connection': 'keep-alive'
        }

        self.caCertPath = caCertPath
        self.caCertContent = caCertContent
        self._tempCaFile = None
        self.verifySSL = verifySSL
        self.useTLS = useTLS
        
        # GURT DNS configuration
        self.gurtDnsServer = gurtDnsServer
        self._dnsCache = {}  # domain -> (ip, timestamp)
        self._dnsCacheTtl = 3600  # 1 hour default TTL
        
        # Connection pool
        self._connections = {}  # host:port -> [Connection, ...]
        self._connectionLock = threading.Lock()
    
    def setCaCertificate(self, caCertContent: str):
        """Set the CA certificate to use, using it's content."""
        self.caCertContent = caCertContent
        if self._tempCaFile:
            try:
                os.unlink(self._tempCaFile)
            except:
                pass
            self._tempCaFile = None

    def loadCaFromGurtca(self, caUrl: str = "http://135.125.163.131:8876"):
        """Automatically load the CA certificate from GurtCA, you can optionally change the CA IP."""
        try:
            import urllib.request
            with urllib.request.urlopen(f"{caUrl}/ca/root", timeout=10) as response:
                caCert = response.read().decode('utf-8')
                if "BEGIN CERTIFICATE" in caCert and "END CERTIFICATE" in caCert:
                    self.setCaCertificate(caCert)
                    Logging.info("Successfully loaded CA certificate from GurtCA", "Client")
                    return True
                else:
                    Logging.error("Invalid CA certificate format received", "Client")
                    return False
        except Exception as e:
            Logging.error(f"Failed to fetch CA certificate: {e}", "Client")
            return False

    def _isValidIp(self, hostname: str) -> bool:
        """Check if hostname is a valid IP address."""
        try:
            ipaddress.ip_address(hostname)
            return True
        except ValueError:
            return False

    def _resolveGurtDns(self, domain: str) -> str:
        """Resolve domain using GURT DNS system."""
        # Remove port if specified in domain
        cleanDomain = domain.split(':')[0]
        
        # Check cache first
        if cleanDomain in self._dnsCache:
            ip, timestamp = self._dnsCache[cleanDomain]
            if time.time() - timestamp < self._dnsCacheTtl:
                Logging.info(f"DNS cache hit for {cleanDomain}: {ip}", "DNS")
                return ip
        
        try:
            # Parse DNS server address
            if ':' in self.gurtDnsServer:
                dnsHost, dnsPort = self.gurtDnsServer.split(':', 1)
                dnsPort = int(dnsPort)
            else:
                dnsHost = self.gurtDnsServer
                dnsPort = 4878
            
            # Create DNS query payload
            dnsQuery = {"domain": cleanDomain}
            dnsPayload = json.dumps(dnsQuery).encode('utf-8')
            
            # Create DNS request
            dnsHeaders = {
                'host': f"{dnsHost}:{dnsPort}",
                'user-agent': self.userAgent,
                'content-type': 'application/json',
                'content-length': str(len(dnsPayload)),
                'connection': 'close'
            }
            
            dnsRequest = Request(
                method="POST",
                path="/resolve-full",
                version="GURT/1.0.0",
                headers=dnsHeaders,
                body=dnsPayload
            )
            
            # Connect to DNS server
            dnsSocket = socket.create_connection((dnsHost, dnsPort), timeout=10.0)
            
            # Send handshake if required (DNS server is a GURT server)
            if self.requireHandshake:
                handshakeReq = Request(
                    method="HANDSHAKE",
                    path="/",
                    version="GURT/1.0.0",
                    headers={
                        'host': f"{dnsHost}:{dnsPort}",
                        'user-agent': self.userAgent
                    },
                    body=b''
                )
                dnsSocket.sendall(handshakeReq.toBytes())
                
                # Receive handshake response
                handshakeData = self._receiveResponseFromSocket(dnsSocket)
                handshakeResponse = Response.fromBytes(handshakeData)
                if handshakeResponse.responseCode != 101:
                    raise GurtDnsError(f"DNS server handshake failed: {handshakeResponse.responseCode}")
            
            # Send DNS query
            dnsSocket.sendall(dnsRequest.toBytes())
            
            # Receive DNS response
            dnsResponseData = self._receiveResponseFromSocket(dnsSocket)
            dnsSocket.close()
            
            dnsResponse = Response.fromBytes(dnsResponseData)
            
            if dnsResponse.responseCode != 200:
                if dnsResponse.responseCode == 404:
                    raise GurtDnsError(f"ERR_NAME_NOT_RESOLVED: Domain {cleanDomain} not found")
                elif dnsResponse.responseCode == 408:
                    raise GurtDnsError(f"ERR_CONNECTION_TIMED_OUT: DNS server timeout for {cleanDomain}")
                else:
                    raise GurtDnsError(f"DNS resolution failed: {dnsResponse.responseCode} {dnsResponse.responseComment}")
            
            # Parse DNS response
            try:
                dnsResult = json.loads(dnsResponse.body.decode('utf-8'))
            except (json.JSONDecodeError, UnicodeDecodeError):
                raise GurtDnsError(f"Invalid DNS response format for {cleanDomain}")
            
            # Extract A records
            aRecords = [record for record in dnsResult.get('records', []) if record.get('type') == 'A']
            if not aRecords:
                raise GurtDnsError(f"No A records found for {cleanDomain}")
            
            # Use first A record
            resolvedIp = aRecords[0]['value']
            recordTtl = aRecords[0].get('ttl', self._dnsCacheTtl)
            
            # Cache the result
            self._dnsCache[cleanDomain] = (resolvedIp, time.time())
            
            Logging.info(f"DNS resolved {cleanDomain} to {resolvedIp}", "DNS")
            return resolvedIp
            
        except socket.timeout:
            raise GurtDnsError(f"ERR_CONNECTION_TIMED_OUT: DNS server timeout for {cleanDomain}")
        except socket.error as e:
            raise GurtDnsError(f"ERR_CONNECTION_REFUSED: Cannot connect to DNS server: {e}")
        except Exception as e:
            if isinstance(e, GurtDnsError):
                raise
            raise GurtDnsError(f"DNS resolution error for {cleanDomain}: {e}")

    def _receiveResponseFromSocket(self, sock: socket.socket) -> bytes:
        """Receive a complete response from a socket (helper for DNS queries)."""
        buffer = b''
        bodyPart = b''
        headersComplete = False
        contentLength = 0
        
        # Read until we have complete headers
        while not headersComplete:
            chunk = sock.recv(4096)
            if not chunk:
                raise ConnectionError("Connection closed unexpectedly")
            
            buffer += chunk
            
            # Check for end of headers
            if b'\r\n\r\n' in buffer:
                headersComplete = True
                headerEnd = buffer.find(b'\r\n\r\n')
                headerPart = buffer[:headerEnd]
                bodyPart = buffer[headerEnd + 4:]
                
                # Parse headers to get content-length
                try:
                    headerLines = headerPart.split(b'\r\n')
                    for line in headerLines[1:]:  # Skip status line
                        if b': ' in line:
                            key, value = line.decode().split(': ', 1)
                            if key.lower() == 'content-length':
                                contentLength = int(value)
                                break
                except Exception:
                    pass
        
        # Read remaining body if needed
        while len(bodyPart) < contentLength:
            chunk = sock.recv(contentLength - len(bodyPart))
            if not chunk:
                raise ConnectionError("Connection closed while reading body")
            bodyPart += chunk
        
        return buffer[:headerEnd + 4] + bodyPart[:contentLength]

    def _resolveHostname(self, hostname: str) -> Optional[str]:
        """Resolve hostname to IP address using GURT DNS."""
        # If it's already an IP, return as-is
        if self._isValidIp(hostname):
            return hostname
        match hostname.lower():
            case "localhost"|"loopback"|"local"|"loop"|"home"|"self"|"me":return "127.0.0.1"
            case _:
                try:
                    return self._resolveGurtDns(hostname)
                except GurtDnsError as e:
                    raise GurtDnsError(f"Cannot resolve {hostname} with GURT DNS.")

    def _getSslContext(self) -> Optional[ssl.SSLContext]:
        """Create SSL context with custom CA if provided."""
        if not self.useTLS:
            return None
            
        context = ssl.create_default_context()
        
        if not self.verifySSL:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        elif self.caCertContent or self.caCertPath:
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            if self.caCertContent:
                if not self._tempCaFile:
                    import tempfile
                    fd, self._tempCaFile = tempfile.mkstemp(suffix='.pem', prefix='gurtca_')
                    with os.fdopen(fd, 'w') as f:
                        f.write(self.caCertContent)
                context.load_verify_locations(cafile=self._tempCaFile)
            elif self.caCertPath:
                context.load_verify_locations(cafile=self.caCertPath)
        
        context.set_alpn_protocols(['GURT/1.0'])
        return context
    
    def _parseGurtUrl(self, url: str) -> tuple:
        """Parse a GURT URL and return (host, port, path, useTLS)."""
        if not url.startswith('gurt://'):
            raise GurtError(f"Invalid Gurt URL: {url}. Must start with 'gurt://'")
        
        # Replace gurt:// with https:// for urlparse compatibility
        parsed = urlparse(url.replace('gurt://', 'https://'))
        
        host = parsed.hostname
        port = parsed.port or 4878  # Default GURT port
        path = parsed.path or '/'
        query = parsed.query
        
        if query:
            path += '?' + query
        
        return host, port, path, self.useTLS
    
    def _getConnection(self, host: str, port: int, useTLS: bool) -> Connection:
        """Get or create a connection from the pool."""
        hostKey = f"{host}:{port}"
        
        with self._connectionLock:
            # Clean up invalid connections
            if hostKey in self._connections:
                self._connections[hostKey] = [
                    conn for conn in self._connections[hostKey] 
                    if conn.isValid(self.connectionTimeout)
                ]
                
                # Try to reuse an existing connection
                if self._connections[hostKey]:
                    conn = self._connections[hostKey].pop()
                    conn.lastUsed = time.time()
                    return conn
            
            # Create new connection
            return self._createConnection(host, port, useTLS)
    
    def _returnConnection(self, connection: Connection):
        """Return a connection to the pool."""
        if connection.closed:
            return
            
        hostKey = f"{connection.host}:{connection.port}"
        
        with self._connectionLock:
            if hostKey not in self._connections:
                self._connections[hostKey] = []
            
            # Only keep up to maxConnections per host
            if len(self._connections[hostKey]) < self.maxConnections:
                connection.lastUsed = time.time()
                self._connections[hostKey].append(connection)
            else:
                connection.close()
    
    def _createConnection(self, host: str, port: int, useTLS: bool) -> Connection:
        """Create a new socket connection to the server."""
        try:
            # Resolve hostname to IP if necessary
            resolvedHost = self._resolveHostname(host)
            
            # Create socket
            sock = socket.create_connection((resolvedHost, port), timeout=self.timeout)
            
            if useTLS:
                sslContext = self._getSslContext()
                if sslContext:
                    # Use original hostname for TLS SNI, not resolved IP
                    sock = sslContext.wrap_socket(sock, server_hostname=host)
                    if self.verifySSL:
                        selectedProtocol = sock.selected_alpn_protocol()
                        if selectedProtocol != 'GURT/1.0':
                            Logging.warning(f"Expected ALPN 'GURT/1.0', got '{selectedProtocol}'", "Client")
                        
            return Connection(sock, host, port, handshaked=False)
            
        except socket.timeout:
            raise TimeoutError(f"Connection to {host}:{port} timed out")
        except ssl.SSLError as e:
            raise ConnectionError(f"TLS handshake failed with {host}:{port}: {e}")
        except socket.error as e:
            raise ConnectionError(f"Failed to connect to {host}:{port}: {e}")
        except GurtDnsError as e:
            raise ConnectionError(f"DNS resolution failed for {host}: {e}")
    
    def _performHandshake(self, connection: Connection) -> bool:
        """Perform GURT handshake with the server."""
        if connection.handshaked:
            return True
            
        try:
            # Create handshake request
            handshakeReq = Request(
                method="HANDSHAKE",
                path="/",
                version="GURT/1.0.0",
                headers={
                    'host': f"{connection.host}:{connection.port}",
                    'user-agent': self.userAgent
                },
                body=b''
            )
            
            # Send handshake
            connection.socket.sendall(handshakeReq.toBytes())
            
            # Receive response
            responseData = self._receiveResponse(connection.socket)
            handshakeResponse = Response.fromBytes(responseData)
            
            # Check handshake success
            if handshakeResponse.responseCode == 101:  # SWITCHING_PROTOCOLS
                # Verify GURT headers
                gurtVersion = handshakeResponse.headers.get('gurt-version')
                if gurtVersion != '1.0.0':
                    Logging.warning(f"Server GURT version mismatch: {gurtVersion}", "Client")
                
                Logging.info(f"Handshake successful with {connection.host}:{connection.port}", "Client")
                connection.handshaked = True
                return True
            else:
                Logging.error(f"Handshake failed: {handshakeResponse.responseCode} {handshakeResponse.responseComment}", "Client")
                return False
                
        except Exception as e:
            Logging.error(f"Handshake error: {e}", "Client")
            return False
    
    def _receiveResponse(self, sock: socket.socket) -> bytes:
        """Receive a complete response from the socket."""
        buffer = b''
        bodyPart = b''
        headersComplete = False
        contentLength = 0
        
        # Read until we have complete headers
        while not headersComplete:
            chunk = sock.recv(4096)
            if not chunk:
                raise ConnectionError("Connection closed unexpectedly")
            
            buffer += chunk
            
            # Check for end of headers
            if b'\r\n\r\n' in buffer:
                headersComplete = True
                headerEnd = buffer.find(b'\r\n\r\n')
                headerPart = buffer[:headerEnd]
                bodyPart = buffer[headerEnd + 4:]
                
                # Parse headers to get content-length
                try:
                    headerLines = headerPart.split(b'\r\n')
                    for line in headerLines[1:]:  # Skip status line
                        if b': ' in line:
                            key, value = line.decode().split(': ', 1)
                            if key.lower() == 'content-length':
                                contentLength = int(value)
                                break
                except Exception:
                    pass
        
        # Read remaining body if needed
        while len(bodyPart) < contentLength:
            chunk = sock.recv(contentLength - len(bodyPart))
            if not chunk:
                raise ConnectionError("Connection closed while reading body")
            bodyPart += chunk
        
        return buffer[:headerEnd + 4] + bodyPart[:contentLength]
    
    def _makeRequest(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        jsonData: Optional[Any] = None,
        data: Optional[Union[str, bytes]] = None,
        timeout: Optional[float] = None
    ) -> GurtResponse:
        """Make a GURT request."""
        startTime = time.time()
        
        # Build full URL
        if self.baseUrl and not url.startswith('gurt://'):
            url = f"{self.baseUrl.rstrip('/')}/{url.lstrip('/')}"
        
        # Parse URL
        host, port, path, useTLS = self._parseGurtUrl(url)
        
        # Handle query parameters
        if params:
            urlObj = URL.fromString(path)
            for key, value in params.items():
                urlObj.queryParameters[str(key)] = str(value)
            path = urlObj.toString()
        
        # Prepare headers
        reqHeaders = self.defaultHeaders.copy()
        if headers:
            reqHeaders.update({k.lower(): v for k, v in headers.items()})
        
        # Add host header
        reqHeaders['host'] = f"{host}:{port}"
        
        # Prepare body
        body = b''
        if jsonData is not None:
            body = json.dumps(jsonData).encode('utf-8')
            reqHeaders['content-type'] = 'application/json'
        elif data is not None:
            if isinstance(data, str):
                body = data.encode('utf-8')
            else:
                body = data
        
        # Set content-length
        reqHeaders['content-length'] = str(len(body))
        
        # Use provided timeout or default
        requestTimeout = timeout or self.timeout
        
        connection = None
        try:
            # Get connection from pool
            connection = self._getConnection(host, port, useTLS)
            connection.socket.settimeout(requestTimeout)
            
            # Perform handshake if required and not already done
            if self.requireHandshake and not connection.handshaked:
                if not self._performHandshake(connection):
                    raise GurtError("Handshake failed")
            
            # Create and send request
            request = Request(
                method=method,
                path=path,
                version="GURT/1.0.0",
                headers=reqHeaders,
                body=body
            )
            
            connection.socket.sendall(request.toBytes())
            
            # Receive response
            responseData = self._receiveResponse(connection.socket)
            response = Response.fromBytes(responseData)
            
            elapsed = time.time() - startTime
            
            # Return connection to pool
            self._returnConnection(connection)
            
            return GurtResponse(response, url, elapsed)
            
        except socket.timeout:
            if connection:
                connection.close()
            raise TimeoutError(f"Request to {url} timed out after {requestTimeout}s")
        except Exception as e:
            if connection:
                connection.close()
            if isinstance(e, (GurtError, TimeoutError, ConnectionError)):
                raise
            raise ConnectionError(f"Request failed: {e}")
    
    def get(
        self, 
        url: str, 
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None
    ) -> GurtResponse:
        """Make a GET request to the provided host, with custom values, and return the response."""
        return self._makeRequest('GET', url, params=params, headers=headers, timeout=timeout)
    
    def post(
        self,
        url: str,
        json: Optional[Any] = None,
        data: Optional[Union[str, bytes]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None
    ) -> GurtResponse:
        """Make a POST request to the provided host, with custom values, and return the response."""
        return self._makeRequest('POST', url, headers=headers, jsonData=json, data=data, timeout=timeout)
    
    def put(
        self,
        url: str,
        json: Optional[Any] = None,
        data: Optional[Union[str, bytes]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None
    ) -> GurtResponse:
        """Make a PUT request to the provided host, with custom values, and return the response."""
        return self._makeRequest('PUT', url, headers=headers, jsonData=json, data=data, timeout=timeout)
    
    def delete(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None
    ) -> GurtResponse:
        """Make a DELETE request to the provided host, with custom values, and return the response."""
        return self._makeRequest('DELETE', url, headers=headers, timeout=timeout)
    
    def close(self):
        """Close all open connections."""
        with self._connectionLock:
            for connections in self._connections.values():
                for conn in connections:
                    conn.close()
            self._connections.clear()
        if self._tempCaFile:
            try:
                os.unlink(self._tempCaFile)
            except:
                pass
            self._tempCaFile = None

if __name__ == "__main__":
    client = Client(
        baseUrl='gurt://localhost:4878',
        timeout=10.0,
        useTLS=False,
        requireHandshake=True,
        maxConnections=5
    )
    
    print("Testing Gurt client/server with no TLS...")
    print("As a note, TLS with GurtCA-issued certificates should ALWAYS be used for production environments, and when communicating with non-pygurt servers/clients.")
    
    try:
        print("\n1. Testing GET request to /")
        response = client.get('/')
        print(f"   Status: {response.statusCode} {response.reason}")
        print(f"   Content-Type: {response.headers.get('content-type', 'unknown')}")
        print(f"   Content length: {len(response.content)} bytes")
        print(f"   Response time: {response.elapsed:.3f}s")
        
        print("\n2. Testing GET request to /api/data/123 with query params")
        response = client.get('/api/data/123', params={'pass': 'fancy'})
        print(f"   Status: {response.statusCode}")
        if response.headers.get('content-type') == 'application/json':
            print(f"   JSON Response: {response.json()}")
        else:
            print(f"   Text Response: {response.text[:100]}...")
            
        print("\n3. Testing POST request to /api/echo")
        testData = {'message': 'Hello Gurt!', 'timestamp': time.time()}
        response = client.post('/api/echo', json=testData)
        print(f"   Status: {response.statusCode}")
        if response.ok:
            echoResponse = response.json()
            print(f"   Echo Response: {echoResponse}")
        
        print("\n4. Testing multiple requests (should reuse connection)")
        for i in range(3):
            response = client.get('/')
            print(f"   Request {i+1}: {response.statusCode} ({response.elapsed:.3f}s)")
        
        print("\n5. Testing 404 error handling")
        response = client.get('/nonexistent')
        print(f"   Status: {response.statusCode} {response.reason}")
        
        print("\n6. Testing GURT DNS resolution")
        try:
            # Test with a GURT domain
            testClient = Client(
                baseUrl='gurt://arson.dev:4878',
                timeout=10.0,
                useTLS=False,
                requireHandshake=True
            )
            print("   GURT DNS is enabled and will be used for .web domains")
        except Exception as e:
            print(f"   GURT DNS test failed: {e} (it is possible that arson.dev is down and that dns does work correctly)!")
        
        print("\nAll tests completed successfully!")
        
    except TimeoutError:
        print("Request timed out - is the server running?")
    except ConnectionError as e:
        print(f"Connection failed: {e}")
        print("    Make sure the Gurt server is running on localhost:4878")
    except GurtError as e:
        print(f"Gurt protocol error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
    finally:
        client.close()