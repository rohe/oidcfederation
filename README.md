# OpenID Connect Federation

[![Build Status](https://travis-ci.org/rohe/oidcfederation.svg?branch=master)](https://travis-ci.org/rohe/oidcfederation)

A document that describes how to do a multilateral federation with OpenID Connect (OIDC).

Text and HTML versions can be found in the draft directory.

## build drafts
````
pip install xml2rfc

xml2rfc draft/openid-connect-federation-1_0.xml  -v 3 --text -o draft/openid-connect-federation-1_0.txt
xml2rfc draft/openid-connect-federation-1_0.xml  -v 3 --html -o draft/openid-connect-federation-1_0.html
````
