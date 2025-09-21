"""
This file is part of pygurt by ItsThatOneJack.

pygurt (C) 2025 ItsThatOneJack

pygurt is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

pygurt is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License along with pygurt. If not, see <https://www.gnu.org/licenses/>.
"""

from enum import Enum
from typing import Union
from rich import print

class ClassProperty:
    def __init__(self, fget):
        if not callable(fget):
            raise TypeError("fget must be callable")
        self.fget = fget

    def __get__(self, obj, cls=None):
        if cls is None:
            cls = type(obj)
        return self.fget(cls)

class Logging:
    @staticmethod
    def info(message: str, domain: str|None = ""):
        domain = "" if domain is None else f" [{domain}]"
        print(f"[blue][bold] [INFO][/bold]{domain} {message}[/blue]")
    @staticmethod
    def error(message: str, domain: str|None = ""):
        domain = "" if domain is None else f" [{domain}]"
        print(f"[red][bold][ERROR][/bold]{domain} {message}[/red]")
    @staticmethod
    def warning(message: str, domain: str|None = ""):
        domain = "" if domain is None else f" [{domain}]"
        print(f"[yellow][bold] [WARN][/bold]{domain} {message}[/yellow]")

class ResponseCode(Enum):
    SWITCHING_PROTOCOLS = 101
    OK = 200
    CREATED = 201
    ACCEPTED = 202
    NO_CONTENT = 204
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    FORBIDDEN = 403
    NOT_FOUND = 404
    METHOD_NOT_ALLOWED = 405
    TIMEOUT = 408
    TOO_LARGE = 413
    UNSUPPORTED_MEDIA_TYPE = 415
    INTERNAL_SERVER_ERROR = 500
    NOT_IMPLEMENTED = 501
    BAD_GATEWAY = 502
    SERVICE_UNAVAILABLE = 503
    GATEWAY_TIMEOUT = 504

class Request:
    def __init__(self, method: str, path: str, version: str, headers: dict[str,str], body: bytes):
        self.method = method
        self.path = path
        self.version = version
        self.headers = headers
        self.body = body

    @classmethod
    def fromBytes(cls, request: bytes):
        body = bytes()
        headers = {}
        method = ''
        path = ''
        version = ''

        requestParts = request.split(b'\r\n\r\n', 1)
        headerPart = requestParts[0]
        body = requestParts[1] if len(requestParts) > 1 else b''

        try:
            headerLines = headerPart.split(b'\r\n')
            requestLine = headerLines[0].decode('utf-8', errors='replace')
            
            # Handle potential malformed request lines
            parts = requestLine.split(' ')
            if len(parts) >= 3:
                method, path, version = parts[0], parts[1], parts[2]
            elif len(parts) == 2:
                method, path = parts
                version = "GURT/1.0.0"  # Default version
            else:
                raise ValueError("Malformed request line")

            for header in headerLines[1:]:
                headerStr = header.decode('utf-8', errors='replace')
                if ': ' in headerStr:
                    key, value = headerStr.split(': ', 1)
                    # GURT protocol uses lowercase headers
                    headers[key.lower()] = value
                
        except (UnicodeDecodeError, ValueError, IndexError):
            # Return a malformed request that can be handled gracefully
            return cls("BAD_REQUEST", "/", "GURT/1.0.0", {}, b'')
        
        return cls(method, path, version, headers, body)

    def toBytes(self):
        requestLine = f"{self.method} {self.path} {self.version}\r\n"
        headerLines = ""
        for header in self.headers.keys():
            headerLines += f"{header}: {self.headers[header]}\r\n"
        return (requestLine + headerLines + '\r\n').encode('utf-8') + self.body

class Response:
    def __init__(self, responseCode: Union[int,ResponseCode], responseComment: str, version: str, headers: dict[str,str], body: bytes):
        
        if isinstance(responseCode, ResponseCode):
            self.responseCode = responseCode.value
        else:
            self.responseCode = responseCode
        self.responseComment = responseComment
        self.version = version
        self.headers = headers
        self.body = body

    @classmethod
    def fromBytes(cls, response: bytes):
        body = bytes()
        headers = {}
        version = ''
        responseCode = 500
        responseComment = 'Internal Server Error'

        responseParts = response.split(b'\r\n\r\n', 1)
        headerPart = responseParts[0]
        body = responseParts[1] if len(responseParts) > 1 else b''

        try:
            headerLines = headerPart.split(b'\r\n')
            responseLine = headerLines[0].decode('utf-8', errors='replace')
            
            # Handle potential malformed response lines
            parts = responseLine.split(' ', 2)  # Split into max 3 parts
            if len(parts) >= 3:
                version, responseCodeStr, responseComment = parts
                responseCode = int(responseCodeStr)
            elif len(parts) == 2:
                version, responseCodeStr = parts
                responseCode = int(responseCodeStr)
                responseComment = "OK" if responseCode == 200 else "Error"
            else:
                raise ValueError("Malformed response line")

            for header in headerLines[1:]:
                headerStr = header.decode('utf-8', errors='replace')
                if ': ' in headerStr:
                    key, value = headerStr.split(': ', 1)
                    # GURT protocol uses lowercase headers
                    headers[key.lower()] = value
                    
        except (UnicodeDecodeError, ValueError, IndexError):
            # Return a default error response
            responseCode = 500
            responseComment = "Internal Server Error"
            version = "GURT/1.0.0"
        
        return cls(responseCode, responseComment, version, headers, body)

    def toBytes(self):
        responseLine = f"{self.version} {self.responseCode} {self.responseComment}\r\n"
        headerLines = ""
        for header in self.headers.keys():
            headerLines += f"{header}: {self.headers[header]}\r\n"
        return (responseLine + headerLines + '\r\n').encode('utf-8') + self.body

class URL:
    def __init__(
            self,
            queryParameters: dict[str,str] = {},
            segments: list[str] = []
        ):
        self.segments = segments if segments is not None else []
        # rebuild path from segments
        self.path = "/" + "/".join(self.segments)
        self.queryParameters = queryParameters or {}
    
    @classmethod
    def fromString(cls, url: str):
        path = url
        queryParameters = {}
        segments = []

        # split query string manually
        if '?' in url:
            path, queryString = url.split('?', 1)
            for param in queryString.split('&'):
                if '=' in param:
                    # URL decode the key and value
                    key, value = param.split('=', 1)
                    key = cls._urlDecode(key)
                    value = cls._urlDecode(value)
                    queryParameters[key] = value
                else:
                    # Handle parameters without values
                    key = cls._urlDecode(param)
                    queryParameters[key] = ""
        
        # split path into segments, handling empty segments
        segments = [segment for segment in path.split("/") if segment]
        
        return cls(queryParameters, segments)
    
    @staticmethod
    def _urlDecode(text: str) -> str:
        """Basic URL decoding for common cases."""
        import urllib.parse
        return urllib.parse.unquote_plus(text)
    
    @staticmethod
    def _urlEncode(text: str) -> str:
        """Basic URL encoding for common cases."""
        import urllib.parse
        return urllib.parse.quote_plus(text)
    
    def toString(self):
        queryString = '&'.join(f"{self._urlEncode(x)}={self._urlEncode(self.queryParameters[x])}" for x in self.queryParameters.keys())
        return f"{self.path}?{queryString}" if queryString else self.path