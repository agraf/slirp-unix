# Slirp UNIX domain socket proxy

Virtualization.Framework on macOS can tunnel network traffic via a UNIX domain socket.
This proxy adds a simple backend for this mechanism using slirp. This allows VMs to
communicate to the outside world even if the NAT network target does not work, for
example due to corporate firewall policy settings.

## Usage

The application has a builting usage text:

```
Slirp UNIX socket proxy
-----------------------

Usage: ./slirp_unix [-p path] [-f host_port:guest_port]

  -p path                  Define the path for the UNIX socket. Defaults to /tmp/slirp.
  -f host_port:guest_port  Add port forward to a guest socket. Can be supplied multiple times.
```

To connect to it, make sure to create a UNIX domain socket that also binds to a path, like this:

```C
struct sockaddr_un caddr = {
    .sun_family = AF_UNIX,
    .sun_path = "/tmp/client"
};
struct sockaddr_un addr = {
    .sun_family = AF_UNIX,
    .sun_path = "/tmp/slirp"
};

fd = socket(AF_UNIX, SOCK_DGRAM, 0);
bind(fd, (struct sockaddr *)&caddr, sizeof(caddr));
connect(fd, (struct sockaddr *)&addr, sizeof(addr));
```

After that, you can freely send and receive ethernet frames over the local UNIX DGRAM socket.

## Building

To build, first install libslirp using brew

```bash
$ brew install libslirp
```

and then build the proxy application

```bash
$ make
```

This provides a `slirp_unix` binary in the build directory which you can run from there.
