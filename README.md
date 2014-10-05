SSL Tester
----------

by Andrew Brampton (bramp.net) (c) 2014

Intro
=====

*This is still a work in progress*

SSL Tester is a command line tool for checking if your servers adhere to your SSL policies. Given a list of IP address
and a config it will check various criteria on each server, such as:

 * Minimum level of SSL protocol, e.g  TLS 1.0 or higher
 * Minimum strength algorithms and key size
 * Certificates correctly issued, and chains provided
 * Check for visibilities (Heartbleed for example)
    

Notes
=====
    https://www.ssllabs.com/downloads/SSL_TLS_Deployment_Best_Practices_1.3.pdf
    https://www.openssl.org/docs/ssl/SSL_get_peer_certificate.html#
    https://www.openssl.org/docs/ssl/SSL_get_peer_cert_chain.html#
    SSL_set_tlsext_host_name SNI