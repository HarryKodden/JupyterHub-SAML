#!/bin/bash
set -e

# Apache gets grumpy about PID files pre-existing
rm -f /usr/local/apache2/logs/httpd.pid

sed -i 's/ulimit -n [0-9]*/ulimit -n 100/' /usr/sbin/apachectl
cd /etc/shibboleth && ln -sf /opt/shibboleth-sp/etc/shibboleth/surfconext.pem .
cd /etc/shibboleth && ln -sf /run/sp/sp-* .

/etc/init.d/shibd restart

sed -i 's~%%SERVER_NAME%%~'"$SERVER_NAME"'~g' /etc/apache2/sites-enabled/000-default.conf

exec apachectl -DFOREGROUND
