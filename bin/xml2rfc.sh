#! /bin/bash

mkdir public
docker run -v $(pwd):/rfc -w /rfc paulej/rfctools xml2rfc draft/oidcfed.hf.xml --text -o public/oidcfed-05.txt
docker run -v $(pwd):/rfc -w /rfc paulej/rfctools xml2rfc draft/oidcfed.hf.xml --html -o public/oidcfed-05.html
ls -la .
ls -la public

# mv oidcfed-05.html public/
