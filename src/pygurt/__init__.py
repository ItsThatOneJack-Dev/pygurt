"""
pygurt
=========

A Python implementation of the GURT standard, including both a client and server!
"""

"""
This file is part of pygurt by ItsThatOneJack.

pygurt (C) 2025 ItsThatOneJack

pygurt is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

pygurt is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License along with pygurt. If not, see <https://www.gnu.org/licenses/>.
"""

from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("pygurt")
except PackageNotFoundError:
    __version__ = "0.0.0"
__author__  = "ItsThatOneJack"
__license__ = "GNU AGPL v3.0"

from .common import ResponseCode, Response, Request, URL
from .server import ResponseMiddleware, MiddlewareRequest, HandshakeMiddlewareRequest, Server
from .client import GurtError, ConnectionError, TimeoutError, GurtResponse, Client

__all__ = [
    "ResponseCode", "Response", "Request", "URL",
    "ResponseMiddleware", "MiddlewareRequest", "HandshakeMiddlewareRequest", "Server",
    "GurtError", "ConnectionError", "TimeoutError", "GurtResponse", "Client"
]
