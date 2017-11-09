#!/bin/bash
set -e

# Apache gets grumpy about PID files pre-existing
rm -f /usr/local/apache2/logs/httpd.pid

if [ -n "$HTTPS_CERT_FILE" ]; then
    rm -f /etc/apache2/cert.pem
    cp "$HTTPS_CERT_FILE" /etc/apache2/cert.pem
    chown www-data /etc/apache2/cert.pem
    chmod 0644 /etc/apache2/cert.pem
fi

if [ -n "$HTTPS_PRIVKEY_FILE" ]; then
    rm -f /etc/apache2/privkey.pem
    cp "$HTTPS_PRIVKEY_FILE" /etc/apache2/privkey.pem
    chown www-data /etc/apache2/privkey.pem
fi

sed -i 's/ulimit -n [0-9]*/ulimit -n 100/' /usr/sbin/apachectl
cd /etc/shibboleth && ln -sf /opt/shibboleth-sp/etc/shibboleth/surfconext.pem .
cd /etc/shibboleth && ln -sf /run/sp/sp-* .

/etc/init.d/shibd restart

exec apachectl -DFOREGROUND
