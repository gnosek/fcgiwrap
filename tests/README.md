# Silent CGI disconnect regression test

Build fcgiwrap, then run:

```sh
perl tests/disconnect.pl /absolute/path/to/fcgiwrap
```

The test requires core Perl modules and Unix-domain sockets. It needs neither
root access nor a web server. It starts isolated single-worker instances and
temporary CGI fixtures in a private temporary directory.

Cases cover disconnects before and after response headers, retaining an idle
CGI while its connection remains open, and eight repeated disconnects. Each
case verifies that the abandoned CGI exits and the same worker can serve a
subsequent request. Unpatched fcgiwrap fails the first case.

The fixtures use their own sessions so cleanup targets only test processes.
The test does not exercise TCP half-close, FastCGI keep-connection cancellation,
systemd activation, or all platform-specific poll semantics.
