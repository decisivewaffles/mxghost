# mxx - Inbound SMTP proxy using HAProxy PROXY v2 protocol

This is an attempt to optimize privacy and reliability constraints for small SMTP servers which may not always be reachable. It's a hybrid between a layer 4 TCP proxy and a TLS terminating L7 store and forward MX.

This requires a backend MX which supports HAProxy's PROXY v2 protocol. From the backend MX perspective, it's as if the mail was being delivered directly - the connecting IP is passed via PROXY headers and the mailer treats it as if directly connected, thus IP based filtering can be done at the backend MX without further configuration.

On each inbound connection, if the backend is reachable, the proxy does no TLS termination and sends traffic directly to the backend MX at the TCP layer. If that connection times out, it will receive and queue mail locally, using the TLS certificate and allowlist provided. No further filtering will be done. The backend server will be periodically retried to drain the queue, using PROXY protocol to replay the IP the message was originally received from.

NOTE: This is meant for small scale deployments where filtering can be usually handled by the backend MX, and the rare offline cases can be handled with limited local intelligence. Larger deployments should use a full store and forward architecture with local spam filtering, etc. Mail, once accepted by this proxy, will be dropped without DSN if the backend MX rejects it permanently.

## Features

- Allowlist filtering by domain and/or email address when queuing
- Live reload of allowlist and TLS certificate
- Socket activation (systemd) is supported, but not required
- Logging of connections and queuing behavior

## Planned but not implemented

- Add header to queued messages to indicate datetime received
- Sender rate limits and/or blacklist

## Compatibility

I've only tested this on linux, but it should be usable other platforms. On linux it will drop unneeded capabilities after binding, on other platforms there is no such functionality implemented.

## Privacy and security

In order to implement store and forward, the TLS certificate used by the MX being proxied is required, thus comprimise of the box holding it allows MITM attacks on future traffic. It is not, however, sufficent to decode traffic which is proxied at L4 (the usual case) because of how TLS sessions negotiate their own keypairs. During that mode of operation this proxy has no access to the content of messages (assuming TLS) and does not store data.

When the backend is unreachable, the TLS certificate is used and messages to targets on the allowlist are stored in the queue directory for future delivery. You may use an encrypted filesystem for this mount point. There is currently no pure in-memory mode, but a tmpfs mount can be used similarly to prevent physical disk writes of mail. Where possible in coordination with the backend MX, PGP would be theoretically appropriate for protecting message body content at rest but is not currently implemented.

If your security model makes storing messages worse than being offline, I recommend using other solutions such as an L4 TCP proxy (e.g. HAProxy or nginx) or L3 network mappings.

## Configuration

  -allowlist string
    	Path to list of allowed recipients (required)
  -banner string
    	Hostname announced in the SMTP 220 greeting (required)
  -cert Path
    	Path to TLS certificate file (.crt) (required)
  -config string
    	Path to YAML config file
  -key Path
    	Path to TLS private key file (.key) (required)
  -listen addr:port
    	Listen on addr:port; use brackets for IPv6, e.g. [::1]:25
    		(repeatable; default: 0.0.0.0:25 and [::]:25)
       		NOTE: ignored if env LISTEN_FDS is set (for socket activation)
  -mxaddr string
    	Primary MX IP address and port (required)
  -mxname string
    	Primary MX name (for TLS validation) (required)
  -mxtimeout int
    	Primary MX connection timeout (seconds) before engaging store and forward
        Default 1.0 seconds
  -queue Directory
    	Directory used for queue storage (required)
  -reconnect interval
    	Queue retry interval (seconds) when the queue is non-empty
  -rwtimeout int
    	Read/write activity timeout (seconds) before closing connection

The configuration file supports the same settings under the same name. For `listen` use a YAML list rather than repeating the entry.

If environment variable LISTEN_FDS is set, `listen` configuration will be ignored.

## Install

## License

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see [https://www.gnu.org/licenses/](https://www.gnu.org/licenses/).
