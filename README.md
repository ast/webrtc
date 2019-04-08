# Erlang WebRTC work in progress

## Background

The overall goal is to implement a WebRTC stack in Erlang with support for, at least, data channels and Opus audio.

## TODO:

### DTLS with use_srtp

This repo contains a GnuTLS NIF library with support for use_srtp.
It would be nicer with pure Erlang but there are some limitations in the Erlang SSL stack which
makes this difficult.

### SRTP implementation

I plan to write an libsrtp2 NIF library.

### ICE implementation

Should be quite easy in pure Erlang, I hope.

### SDP

Here is an Erlang implementation of ABNF which includes an SDP parser.

* https://github.com/nygge/abnfc


### SCTP implementation

Not sure about this one...

