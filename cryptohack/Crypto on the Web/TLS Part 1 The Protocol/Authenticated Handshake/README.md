# Authenticated Handshake (40pts)
## TLS Part 1: The Protocol

Authentication occurs in the TLS handshake in three messages:  Certificate. Contains the identity of the server, with signatures on the certificate chaining up to a certificate authority trusted by the client. In mutual TLS, the client also sends a certificate of its own identity for the server to v
