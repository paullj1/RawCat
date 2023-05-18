# RawCat
Send crafted TCP or UDP (with pseudo-reliability) across raw socket.  Binds UNIX
domain socket, and transmits received data.

# Reliability
Reliability across the raw socket is minimally implemented, and very slow. It
does hold up against packet loss and congestion, but there aren't any window
adjustments.
