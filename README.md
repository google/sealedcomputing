# The Sealed Computing Platform
_Minimal trusted computing base for enforcing privacy policies_

[Sealed Computing](https://arxiv.org/abs/1906.07841)
is what Apple and Google do when protecting your lock screen secrets in HSMs or
[Titan
chips](https://security.googleblog.com/2018/10/building-titan-better-security-through.html),
so you can [recover your encrypted
data](https://developer.android.com/about/versions/pie/security/ckv-whitepaper)
from the cloud after losing your device.  The secure hardware makes it hard for
the cloud provider to see your data.  It is similar to ["Confidential
Computing"](https://cloud.google.com/confidential-computing), which is
when users can run their virtual-machines in the cloud inside "secure enclaves",
which in theory stops the cloud provider from snooping on what you're doing on
their hardware.  Sealed computing has some portion of the code, called the
"privacy policy", which is non-updatable, other than as the privacy policy
itself allows, for example with user consent.  An existing sealed enclave is
incapable of violating its hardware-enforced privacy policy.

Any data users encrypt to sealed enclaves can only be used in accordance with
the privacy policy, assuming the hardware and algorithms remain secure.  In
other words:

_Sealed computing, when secure, ensures user data is used in accordance with the
privacy policy._

Privacy policies are just publicly disclosed algorithms running in 3rd-party
attested hardware such as Intel TDX, or AMD SEV-SNP.  Privacy policies can only
be attested if the source code is public and the builds are reproducible.  For
Google's Sealed Computing effort, that source code lives here.
