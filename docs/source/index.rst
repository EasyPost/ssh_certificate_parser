ssh_certificate_parser documentation
====================================

**ssh_certificate_parser** is a small library for interacting with `OpenSSH host/user certificates <https://cvsweb.openbsd.org/cgi-bin/cvsweb/~checkout~/src/usr.bin/ssh/PROTOCOL.certkeys?rev=1.15&content-type=text/plain>`_. Specifically, it supports RSA, DSA, and Ed25519 keys signed by an RSA certificate authority. It does not currently validate the CA signature, but merely parses out some fields.

This work is available under the terms of the ISC License.

Contents
--------

.. toctree::
   :maxdepth: 1

   CHANGES.md

Members
-------

.. autoclass:: ssh_certificate_parser.SSHCertificate
   :members:
   :undoc-members:

.. autoclass:: ssh_certificate_parser.CertType
   :members:
   :undoc-members:

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

