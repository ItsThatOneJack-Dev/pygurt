# pygurt

> pygurt: GURT for python!

Say hello to pygurt, a Python implementation of the GURT standard, including both a client and server!

## The pygurt client

pygurt comes with both a client and a server, this allows you to easily make more complex projects such as proxies!

### Getting started with the client

To get started with the client, import `Client` from `pygurt`, and configure an instance of it!

Here is an example, supporting TLS and automatically fetching the GurtCA root certificate:

```Python

from pygurt import Client

client = Client(
    base_url='gurt://135.125.163.131:4878',
    timeout=10.0,
    use_tls=True,
    require_handshake=True,
    max_connections=5
)
client.loadCaFromGurtca() # Automatically fetch and load the GurtCA root certificate from http://135.125.163.131:8876/ca/root

print(client.post( # Print out the DNS looup information for `gurt://arson.dev`
    "/resolve-full",
    json="{'domain':'arson.dev'}"
).json())

```

## The pygurt server

The pygurt server is a bit more complex, mainly because you need TLS certificates issed by GurtCA to be able to accept connections.
But in reality, this is quite easy as Gurted has a tool for this exact purpose!

### Getting started with the server

1. Download and install GurtCA, you can use community builds or build from the source in the Gurted GitHub repository.
2. Run `curtca request <your domain>`, and wait for it to prompt you to add a TXT record.
3. Sign into `dns.web` on Flumi, and select your domain's dashboard.
4. Add a TXT record with the name `_gurtca-challenge`, and the value gurtCA is telling you.
5. Press enter on GurtCA, if verification passes then you should be left with a `certs` directory containing a `.crt` and `.key` file.
6. Set up your server code, like this following example:

```python
from pygurt import Server

server = Server(requireHandshake=True) # Must be true to be able to be connected to by clients, unless they are a pygurt client with handshakes disabled (which is very rare)!

server.tls("", "") # Pass your `.crt` file path, then your `.key` file path, both as strings.

@server.route("/", methods=["GET"])
def root_page(request, response):
    return response.status(200).text(request.text) # Sends back any body text it recieves

server.bind("0.0.0.0").start() # Defaults to `0.0.0.0` on port 4878
```

Tada! You have a working pygurt webserver that echoes data back to clients, and uses TLS!

## Notes

Further documentation about exactly what everything is for (and does), as well as info about more advanced features is available in docstrings!
Your linter should display them to you!

## Legal

pygurt (C) 2025 ItsThatOneJack

The pygurt project is not affiliated — nor endorsed by — Outpoot, and its related person(s) in any way. No attempt is made by the proliferation of pygurt to claim association or affiliation with Outpoot.

The pygurt project is licensed under the GNU Affero General Public License version 3.0, you should have received a copy of the license along with pygurt. If not, see <https://www.gnu.org/licenses/>.

pygurt is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

pygurt is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.
