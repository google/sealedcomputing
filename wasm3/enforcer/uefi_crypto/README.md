This package provides the Enforcer the low-level crypto primitives it needs,
using code from BoringSSL, linked to Nanolibc, which is a tiny implementation
of popular libc APIs.  Nanolibc translates I/O to UEFI calls over a simple I/O
device designed for simple host communication.

We pull individual files from BoringSSL rather than whole packages because it
simplifies linking the crypto used by the Enforcer to Nanolibc, by minimizing
the number of libc calls linked in.
