"""
This file is part of pygurt by ItsThatOneJack.

pygurt (C) 2025 ItsThatOneJack

pygurt is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

pygurt is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License along with pygurt. If not, see <https://www.gnu.org/licenses/>.
"""

from typing import Union, Optional, Any
import re
import time
import asyncio
import os
import mimetypes
from pathlib import Path

from .common import Request, Response, ResponseCode, URL, Logging

class HandshakeMiddlewareRequest:
    """
    The request object passed to pre-handshake middleware functions.
    This object is read-only, only the methods can modify its data.
    
    Properties:
        rawRequest: Request - The raw handshake request object.
        clientAddress: str - The IP and port making the request.
        version: str - The version of GURT being used.
        headers: dict[str,str] - A dictionary of attached headers and their values, always strings.
        blocked: bool - Whether this middleware is trying to block the request.
        bypassed: bool - Whether this middleware is trying to bypass the other middleware.
    
    Methods:
        allow: None - Allow this handshake request, it will be passed to the next middleware for handshakes, if all dont block then it is granted.
        block: None - Block this handshake request, it will be passed to the next middleware for handshakes, if none bypass allow then it is blocked.
        bypass: None - Allow or block this handshake request, bypassing the other middleware and acting immiediately.
    """
    def __init__(
            self,
            rawRequest: Request,
            clientAddress: str,
            version: str = "",
            headers: dict[str,str] = {}
        ):
        super().__setattr__("rawRequest", rawRequest)
        super().__setattr__("clientAddress", clientAddress)
        super().__setattr__("version", version)
        super().__setattr__("headers", headers)
        super().__setattr__("_blocked", False)
        super().__setattr__("_bypass", False)
    
    def allow(self) -> None:
        """Allow this handshake request, it will be passed to the next middleware for handshakes, if all dont block then it is granted."""
        super().__setattr__("_bypass", False)
        super().__setattr__("_blocked", False)
    
    def block(self) -> None:
        """Block this handshake request, it will be passed to the next middleware for handshakes, if none bypass allow then it is blocked."""
        super().__setattr__("_bypass", False)
        super().__setattr__("_blocked", True)
    
    def bypass(self, allow: bool) -> None:
        """Allow or block this handshake request, bypassing the other middleware and acting immiediately."""
        super().__setattr__("_bypass", True)
        super().__setattr__("_blocked", not allow)
    
    @property
    def blocked(self) -> bool:
        return super().__getattribute__("_blocked")
    
    @property
    def bypassed(self) -> bool:
        return super().__getattribute__("_bypass")
    
    def __setattr__(self, name, value):
        return

class MiddlewareRequest:
    def __init__(
            self,
            rawRequest: Request,
            clientAddress: str,
            pathParameters: dict[str, str],
            queryParameters: dict[str,str],
            version: str = "",
            serverRef = None
        ):
        # Main data
        self.raw = rawRequest
        self.method = rawRequest.method
        self.path = rawRequest.path
        self.version = version
        self.headers = rawRequest.headers
        self.body = rawRequest.body
        self.pathParameters = pathParameters
        self.queryParameters = queryParameters
        self.clientAddress = clientAddress
        
        # Middleware control
        self._blocked = False
        self._bypass = False
        self._serverRef = serverRef
        
        # Mutable properties (for middleware)
        self._targetPath = rawRequest.path
        self._targetMethod = rawRequest.method
    
    def header(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Get a header's value."""
        return self.headers.get(key, default)
    
    def param(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Get a path parameter's value."""
        return self.pathParameters.get(key, default)
    
    def query(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Get a query parameter's value."""
        return self.queryParameters.get(key, default)
    
    def json(self) -> dict:
        """Get the request's body as usable JSON data."""
        import json
        try:
            return json.loads(self.body.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}
    
    def text(self) -> str:
        """Get the request's body as usable text."""
        try:
            return self.body.decode()
        except UnicodeDecodeError:
            return ""
    
    def allow(self) -> None:
        """Allow this request, it will be passed to the next middleware, if all dont block then it is granted."""
        self._bypass = False
        self._blocked = False
    
    def block(self) -> None:
        """Block this request, it will be passed to the next middleware, if none bypass allow then it is blocked."""
        self._bypass = False
        self._blocked = True
    
    def bypass(self, allow: bool) -> None:
        """Allow or block this request, bypassing the other middleware and acting immiediately."""
        self._bypass = True
        self._blocked = not allow
    
    def revokeHandshake(self) -> None:
        """Revoke the handshake for this client."""
        if self._serverRef and self.clientAddress in self._serverRef._handshakedClients:
            del self._serverRef._handshakedClients[self.clientAddress]
            Logging.info(f"Handshake revoked for {self.clientAddress}", "Middleware")
    
    def redirectTo(self, path: str, method: Optional[str] = None) -> None:
        """Change the target path and method this packet will go to."""
        self._targetPath = path
        if method:
            self._targetMethod = method
    
    def setHeader(self, key: str, value: str) -> None:
        """Set a header in the request to an arbitrary string value."""
        self.headers[key.lower()] = value
        self.raw.headers[key.lower()] = value
    
    @property
    def blocked(self) -> bool:
        return self._blocked
    
    @property
    def bypassed(self) -> bool:
        return self._bypass
    
    @property 
    def targetPath(self) -> str:
        return self._targetPath
    
    @property
    def targetMethod(self) -> str:
        return self._targetMethod

class RequestConnection:
    """
    A Gurt protocol request object, more user-friendly than `Request`.

    Properties:
        raw: Request - The raw request object.
        method: str - The method the request is using.
        version: str - The version of the Gurt protocol being used.
        headers: dict[str,str] - A dictionary of headers, always represented as strings.
        body: bytes - The body of the request.
        pathParameters: dict[str,str] - A dictionary of path parameters to their values, always as strings.
        queryParameters: dict[str,str] - A dictionary of query parameters to their values, always as strings.
        clientAddress: str - The address the request originates from.
    
    Methods:
        header: Optional[str] - Get a header by its name.
        param: Optional[str] - Get a path parameter by its name.
        query: Optional[str] - Get a query parameter by its name.
        json: dict - The request's body as usable JSON data.
        text: str - The request's body as usable text.
    """
    def __init__(self, request: Request, pathParameters: dict[str, str], queryParameters: dict[str,str], clientAddress: str):
        self.raw = request
        self.method = request.method
        self.path = request.path
        self.version = request.version
        self.headers = request.headers
        self.body = request.body
        self.pathParameters = pathParameters
        self.queryParameters = queryParameters
        self.clientAddress = clientAddress
    
    def header(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Get a header by its name."""
        return self.headers.get(key, default)
    
    def param(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Get a path parameter by its name."""
        return self.pathParameters.get(key, default)
    
    def query(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Get a query parameter by its name."""
        return self.queryParameters.get(key, default)
    
    def json(self) -> dict:
        """The request's body as usable JSON data."""
        import json
        try:
            return json.loads(self.body.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}
    
    def text(self) -> str:
        """The request's body as usable text."""
        try:
            return self.body.decode()
        except UnicodeDecodeError:
            return ""

class ResponseConnection:
    """Enhanced response object with fluent interface for building responses."""
    def __init__(self, version: str = "GURT/1.0.0"):
        self._statusCode = 200
        self._statusText = "OK"
        self._headers = {"Content-Type": "text/plain"}
        self._body = b""
        self._version = version

    def status(self, code: Union[int, ResponseCode], text: Optional[str] = None) -> 'ResponseConnection':
        if isinstance(code, ResponseCode):
            self._statusCode = code.value
            self._statusText = code.name.replace('_', ' ').title() if text is None else text
        else:
            self._statusCode = code
            statusTexts = {
                200: "OK", 201: "Created", 202: "Accepted", 204: "No Content",
                400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 
                404: "Not Found", 405: "Method Not Allowed", 408: "Timeout",
                413: "Payload Too Large", 415: "Unsupported Media Type",
                500: "Internal Server Error", 501: "Not Implemented",
                502: "Bad Gateway", 503: "Service Unavailable", 504: "Gateway Timeout"
            }
            self._statusText = statusTexts.get(code, "Unknown") if text is None else text
        return self

    def header(self, key: str, value: Union[str, bool, int]) -> 'ResponseConnection':
        self._headers[key] = str(value)
        return self

    def headers(self, headers: dict[str, Union[str, bool, int]]) -> 'ResponseConnection':
        for key, value in headers.items():
            self._headers[key] = str(value)
        return self

    def json(self, data: Any) -> 'ResponseConnection':
        import json
        self._body = json.dumps(data).encode()
        self._headers["Content-Type"] = "application/json"
        self._headers["Content-Length"] = str(len(self._body))
        return self

    def text(self, text: str) -> 'ResponseConnection':
        self._body = text.encode()
        self._headers["Content-Type"] = "text/plain"
        self._headers["Content-Length"] = str(len(self._body))
        return self

    def html(self, html: str) -> 'ResponseConnection':
        self._body = html.encode()
        self._headers["Content-Type"] = "text/html"
        self._headers["Content-Length"] = str(len(self._body))
        return self

    def gfht(self, content: str) -> 'ResponseConnection':
        self._body = content.encode()
        self._headers["Content-Type"] = "text/gfht"
        self._headers["Content-Length"] = str(len(self._body))
        return self

    def file(self, filepath: str, contentType: Optional[str] = None) -> 'ResponseConnection':
        try:
            path = Path(filepath)
            if not path.exists():
                return self.status(404).text("File not found")

            if not path.is_file():
                return self.status(400).text("Path is not a file")

            with open(path, 'rb') as f:
                self._body = f.read()

            if contentType is None:
                contentType, _ = mimetypes.guess_type(str(path))
                if contentType is None:
                    contentType = "application/octet-stream"

            self._headers["Content-Type"] = contentType
            self._headers["Content-Length"] = str(len(self._body))

        except Exception as e:
            return self.status(500).text(f"Error reading file: {str(e)}")

        return self

    def bytes(self, data: bytes, contentType: str = "application/octet-stream") -> 'ResponseConnection':
        self._body = data
        self._headers["Content-Type"] = contentType
        self._headers["Content-Length"] = str(len(self._body))
        return self

    def build(self) -> Response:
        return Response(
            self._statusCode,
            self._statusText,
            self._version,
            self._headers,
            self._body
        )

class ResponseMiddleware:
    """Middleware for modifying outgoing responses."""
    def __init__(
            self,
            response: Response,
            originalRequest: Request,
            clientAddress: str,
            serverRef = None
        ):
        self.response = response
        self.originalRequest = originalRequest
        self.clientAddress = clientAddress
        self._serverRef = serverRef
        self._blocked = False
        self._bypass = False

    def block(self) -> None:
        self._blocked = True

    def allow(self) -> None:
        self._blocked = False

    def bypass(self, allow: bool) -> None:
        self._bypass = True
        self._blocked = not allow

    def setHeader(self, key: str, value: Union[str, bool, int]) -> None:
        self.response.headers[key.lower()] = str(value)

    def setStatus(self, code: Union[int, ResponseCode], message: Optional[str] = None) -> None:
        if isinstance(code, ResponseCode):
            self.response.responseCode = code.value
            self.response.responseComment = code.name.replace('_', ' ').title() if message is None else message
        else:
            self.response.responseCode = code
            if message:
                self.response.responseComment = message

    def setBody(self, body: Union[str, bytes, dict]) -> None:
        if isinstance(body, str):
            self.response.body = body.encode()
            self.response.headers["content-length"] = str(len(self.response.body))
        elif isinstance(body, bytes):
            self.response.body = body
            self.response.headers["content-length"] = str(len(self.response.body))
        elif isinstance(body, dict):
            import json
            jsonStr = json.dumps(body)
            self.response.body = jsonStr.encode()
            self.response.headers["content-type"] = "application/json"
            self.response.headers["content-length"] = str(len(self.response.body))

    def revokeHandshake(self) -> None:
        if self._serverRef and self.clientAddress in self._serverRef._handshakedClients:
            del self._serverRef._handshakedClients[self.clientAddress]
            Logging.info(f"Handshake revoked for {self.clientAddress}", "Response Middleware")

    @property
    def blocked(self) -> bool:
        return self._blocked

    @property
    def bypassed(self) -> bool:
        return self._bypass

class Server:
    def __init__(
            self,
            requireHandshake: bool = True,
            caCertPath: Optional[str] = None,
            caCertContent: Optional[str] = None
        ):
        self._routes = {}
        self._preHandshakeMiddleware = []
        self._postHandshakeMiddleware = []
        self._responseMiddleware = []
        self._handshakedClients = {}
        self._interface = []
        self._connections = set()
        self._version = "GURT/1.0.0"
        self._staticDirs = {}
        self._requireHandshake = requireHandshake
        self._tlsCert = None
        self._tlsKey = None
        self._routeRegistrationOrder = []

        self._caCertPath = caCertPath
        self._caCertContent = caCertContent
        self._tempCaFile = None

        try:
            self._eventLoop = asyncio.get_running_loop()
        except RuntimeError:
            self._eventLoop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._eventLoop)
        self._cleanupTask = None
    
    def _getSslContext(self):
        """Create SSL context with custom CA if provided."""
        if not (self._tlsCert and self._tlsKey):
            return None
        
        import ssl
        sslContext = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        sslContext.load_cert_chain(self._tlsCert, self._tlsKey)
        sslContext.set_alpn_protocols(['GURT/1.0'])
        
        # Add custom CA for client certificate verification if needed
        if self._caCertContent or self._caCertPath:
            if self._caCertContent:
                if not self._tempCaFile:
                    import tempfile
                    fd, self._tempCaFile = tempfile.mkstemp(suffix='.pem', prefix='gurtca_')
                    with os.fdopen(fd, 'w') as f:
                        f.write(self._caCertContent)
                sslContext.load_verify_locations(cafile=self._tempCaFile)
            elif self._caCertPath:
                sslContext.load_verify_locations(cafile=self._caCertPath)
        
        return sslContext
    
    def middleware(self, beforeHandshake: bool = False, responseMiddleware: bool = False):
        def decorator(func):
            if beforeHandshake:
                self._preHandshakeMiddleware.append(func)
            elif responseMiddleware:
                self._responseMiddleware.append({
                    'func': func, 
                    'order': len(self._postHandshakeMiddleware)
                })
            else:
                self._postHandshakeMiddleware.append({
                    'func': func, 
                    'order': len(self._postHandshakeMiddleware)
                })
            return func
        return decorator
    
    def static(self, routePath: str, directory: str):
        self._staticDirs[routePath.rstrip('/')] = directory
        return self
    
    def route(self, path: str, methods: list[str] = ["GET"]):
        pattern = re.sub(r"<(\w+)>", r"(?P<\1>[^/]+)", path)
        regex = re.compile(f"^{pattern}$")

        def decorator(func):
            routeOrder = len(self._routeRegistrationOrder)
            self._routeRegistrationOrder.append(path)
            
            applicableMiddleware = [
                mw for mw in self._postHandshakeMiddleware 
                if mw['order'] < routeOrder
            ]
            applicableResponseMiddleware = [
                mw for mw in self._responseMiddleware 
                if mw['order'] < routeOrder
            ]
            
            self._routes[path] = {
                "callback": func,
                "methods": methods,
                "regex": regex,
                "middleware": applicableMiddleware,
                "responseMiddleware": applicableResponseMiddleware,
                "order": routeOrder
            }
            return func
        return decorator
    
    def _handleRequest(self, request: bytes, clientAddress: str) -> Response:
        req = Request.fromBytes(request)
        
        if req.method == "HANDSHAKE":
            blocked = False
            for middleware in self._preHandshakeMiddleware:
                requestObj = HandshakeMiddlewareRequest(
                    rawRequest=req,
                    clientAddress=clientAddress,
                    version=self._version,
                    headers=req.headers
                )
                middleware(requestObj)
                if requestObj.bypassed:
                    if requestObj.blocked:
                        blocked = True
                        break
                    else:
                        blocked = False
                        break
                else:
                    blocked = requestObj.blocked
            
            if blocked:
                return Response(ResponseCode.FORBIDDEN, "Forbidden", self._version, {}, b"Handshake blocked")
            
            self._handshakedClients[clientAddress] = time.time()
            headers = {
                "gurt-version": "1.0.0",
                "encryption": "TLS/1.3", 
                "alpn": "GURT/1.0",
                "server": self._version,
                "date": time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
            }
            return Response(ResponseCode.SWITCHING_PROTOCOLS, "Switching Protocols", self._version, headers, b"")
        
        if self._requireHandshake and clientAddress not in self._handshakedClients:
            return Response(ResponseCode.FORBIDDEN, "Handshake Required", self._version, {}, b"Handshake required")
        
        # Route processing
        callback, pathParameters, queryParameters = self._processPath(req.path, req.method)
        
        if callback is None:
            return Response(ResponseCode.NOT_FOUND, "Not Found", self._version, {}, b"Route not found")
        
        try:
            if not isinstance(queryParameters, dict):
                    queryParameters = {}
            requestConn = RequestConnection(req, pathParameters, queryParameters, clientAddress)
            responseConn = ResponseConnection(self._version)
            
            result = callback(requestConn, responseConn, **pathParameters)
            
            if isinstance(result, Response):
                return result
            elif isinstance(result, ResponseConnection):
                return result.build()
            elif isinstance(result, str):
                return responseConn.text(result).build()
            elif isinstance(result, (dict, list)):
                return responseConn.json(result).build()
            else:
                return responseConn.build()
                
        except Exception as e:
            Logging.error(f"Error in route handler: {str(e)}", "Server")
            return Response(ResponseCode.INTERNAL_SERVER_ERROR, "Internal Server Error", self._version, {}, b"Internal server error")

    def _processPath(self, fullPath: str, method: str):
        url = URL.fromString(fullPath)

        for routeInfo in self._routes.values():
            if method not in routeInfo["methods"]:
                continue
            match = routeInfo["regex"].match(url.path)
            if match:
                pathParameters = match.groupdict()
                return routeInfo["callback"], pathParameters, url.queryParameters

        return None, {}, []
    
    async def cleanupHandshakes(self, timeout: int = 30, interval: int = 10):
        try:
            while True:
                now = int(time.time())
                expired = [client for client, ts in self._handshakedClients.items() if now - ts > timeout]
                for client in expired:
                    del self._handshakedClients[client]
                    Logging.info(f"Removed handshake for {client}", "Cleanup")
                await asyncio.sleep(interval)
        except asyncio.CancelledError:
            Logging.info("Handshake cleanup task stopped", "Cleanup")
    
    async def handleClient(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        MAX_PACKET_SIZE = 10 * 1024 * 1024
        addr = writer.get_extra_info("peername")
        Logging.info(f"Connection from {addr}", "Server")
        
        # Track handshake status for this specific connection
        connectionHandshaked = False

        try:
            while True:
                buffer = b""
                headersDone = False

                while not headersDone:
                    try:
                        chunk = await asyncio.wait_for(reader.read(4096), timeout=30.0)
                        if not chunk:
                            return
                    except asyncio.TimeoutError:
                        return
                    
                    buffer += chunk

                    if len(buffer) > MAX_PACKET_SIZE:
                        response = Response(ResponseCode.TOO_LARGE, "Payload Too Large", self._version, {}, b"Request size >10MB.")
                        writer.write(response.toBytes())
                        await writer.drain()
                        return

                    endOfHeaders = buffer.find(b"\r\n\r\n")
                    if endOfHeaders != -1:
                        headersDone = True
                        headerBytes = buffer[:endOfHeaders + 4]
                        bodyStart = endOfHeaders + 4

                request = Request.fromBytes(headerBytes)
                contentLength = int(request.headers.get("content-length", 0))

                if contentLength > MAX_PACKET_SIZE:
                    response = Response(ResponseCode.TOO_LARGE, "Payload Too Large", self._version, {}, b"Declared size exceeds 10MB.")
                    writer.write(response.toBytes())
                    await writer.drain()
                    return

                body = buffer[bodyStart:]
                while len(body) < contentLength:
                    remaining = contentLength - len(body)
                    try:
                        chunk = await asyncio.wait_for(reader.read(remaining), timeout=30.0)
                        if not chunk:
                            return
                        body += chunk
                    except asyncio.TimeoutError:
                        return

                request.body = body
                Logging.info(f"Request from {addr}: {request.method} {request.path}", "Server")

                # Handle handshake for this connection
                if request.method == "HANDSHAKE":
                    connectionHandshaked = True
                    headers = {
                        "gurt-version": "1.0.0",
                        "encryption": "TLS/1.3", 
                        "alpn": "GURT/1.0",
                        "server": self._version,
                        "date": time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
                    }
                    response = Response(ResponseCode.SWITCHING_PROTOCOLS, "Switching Protocols", self._version, headers, b"")
                    writer.write(response.toBytes())
                    await writer.drain()
                    continue
                
                # Check if handshake is required for non-handshake requests
                if self._requireHandshake and not connectionHandshaked:
                    response = Response(ResponseCode.FORBIDDEN, "Forbidden", self._version, {}, b"Handshake required")
                    writer.write(response.toBytes())
                    await writer.drain()
                    continue

                # Process regular requests
                callback, pathParameters, queryParameters = self._processPath(request.path, request.method)
                
                # Ensure queryParameters is a dict[str, str]
                if not isinstance(queryParameters, dict):
                    queryParameters = {}

                if callback is None:
                    response = Response(ResponseCode.NOT_FOUND, "Not Found", self._version, {}, b"Route not found")
                else:
                    try:
                        requestConn = RequestConnection(request, pathParameters, queryParameters, str(addr))
                        responseConn = ResponseConnection(self._version)
                        
                        result = callback(requestConn, responseConn, **pathParameters)
                        
                        if isinstance(result, Response):
                            response = result
                        elif isinstance(result, ResponseConnection):
                            response = result.build()
                        elif isinstance(result, str):
                            response = responseConn.text(result).build()
                        elif isinstance(result, (dict, list)):
                            response = responseConn.json(result).build()
                        else:
                            response = responseConn.build()
                            
                    except Exception as e:
                        Logging.error(f"Error in route handler: {str(e)}", "Server")
                        response = Response(ResponseCode.INTERNAL_SERVER_ERROR, "Internal Server Error", self._version, {}, b"Internal server error")
                
                writer.write(response.toBytes())
                await writer.drain()

                connectionHeader = request.headers.get('connection', '').lower()
                if connectionHeader == 'close':
                    break

        except Exception as e:
            Logging.error(f"Error handling client {addr}: {e}", "Server")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
            Logging.info(f"Connection with {addr} closed", "Server")

    def tls(self, certPath: str, keyPath: str):
        self._tlsCert = certPath
        self._tlsKey = keyPath
        return self
    
    def bind(self, interface: str = "0.0.0.0", port: int = 4878):
        self._interface = [interface, port]
        return self
    
    async def main(self):
        self._cleanupTask = self._eventLoop.create_task(self.cleanupHandshakes())

        sslContext = self._getSslContext()
        if sslContext:
            Logging.info("TLS enabled with certificates", "Server")
        elif self._requireHandshake:
            Logging.warning("GURT protocol requires TLS, but no certificates provided", "Server")

        self._server = await asyncio.start_server(
            self.handleClient, 
            self._interface[0], 
            self._interface[1],
            ssl=sslContext
        )
        Logging.info(f"GURT server bound to {self._interface[0]}:{self._interface[1]}", "Server")
        async with self._server:
            await self._server.serve_forever()
    
    def start(self):
        if self._interface == []:
            Logging.error("You need to bind to an interface before you can start the server!", "Server")
            return self
        self._eventLoop.run_until_complete(self.main())
        return self

# Example usage
if __name__ == "__main__":
    server = Server(requireHandshake=True)
    
    print("Starting GURT Server...")
    print("Server will be available at: gurt://localhost:4878")
    print("Press Ctrl+C to stop the server")
    print("="*50)
    
    @server.route("/", methods=["GET"])
    def index(req, res):
        gfhtContent = """
        <html>
            <head><title>GURT Server</title></head>
            <body>
                <h1>Welcome to GURT Server</h1>
                <p>This is a test page served over GURT protocol with GFHT content type.</p>
            </body>
        </html>
        """
        return res.gfht(gfhtContent)
    
    @server.route("/api/data/<id>", methods=["GET", "POST"])
    def getData(req, res, id):
        data = {"id": id, "method": req.method, "client": req.clientAddress}
        return res.json(data)
    
    @server.route("/api/echo", methods=["POST"])
    def echoData(req, res):
        try:
            jsonData = req.json()
            return res.json({"echo": jsonData, "receivedAt": time.time()})
        except:
            return res.status(400).text("Invalid JSON")
    
    try:
        server.bind("0.0.0.0", 4878).start()
    except KeyboardInterrupt:
        print("\nServer stopped by user")
    except Exception as e:
        print(f"Server error: {e}")