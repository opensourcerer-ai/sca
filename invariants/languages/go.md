# Go Invariants (v1)
- net/http servers must set timeouts (ReadHeaderTimeout, ReadTimeout, WriteTimeout, IdleTimeout).
- SQL must use prepared statements / parameterization.
- exec.Command must not be built from untrusted input.
- tls.Config: no InsecureSkipVerify in production paths.
