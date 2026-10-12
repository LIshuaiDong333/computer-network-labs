# Computer Network Labs

A teaching network stack in C, with ARP, Ethernet, IPv4, ICMP, UDP, TCP, and example servers.

- `net-lab/src`, `net-lab/include`: protocol implementations and headers.
- `net-lab/app`: UDP, TCP, and HTTP server examples.
- `net-lab/app/resource`: example web pages and reviewed campus image fixtures.
- `net-lab/Npcap/Include`: supplied packet-capture headers with original attribution.

The project includes CMake and Makefile build definitions. Install a compatible compiler, CMake, and libpcap (or the matching Npcap development libraries on Windows). Bundled binary libraries are excluded. Configure the lab network interface in `include/config.h` for your environment before running the examples. Packet captures, build output, IDE settings, and original Git history are excluded.

## Publication scope

This is a reviewed export of local coursework. Word/PDF reports, archives, credentials, personal submission names, build output, and old Git history are excluded. Original source bytes and encodings are preserved except for the anonymous CSAPP identity placeholders. Upstream attribution and license files are retained where supplied.

The root `.gitignore` uses an explicit file allowlist. Review new files for personal information before adding them. Some experiments depend on their original course framework or external development tools.
