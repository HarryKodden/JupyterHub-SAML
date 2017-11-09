FROM debian:jessie

MAINTAINER Harry Kodden <harry@kodden.nl>

RUN apt-get update \
    && apt-get -y install apache2 libapache2-mod-shib2 lynx\
    && a2enmod headers \
    && a2enmod ssl \
    && a2enmod rewrite \
    && a2enmod proxy \
    && a2enmod proxy_http \
    && a2enmod proxy_wstunnel \
    && cd /etc/apache2 \
    && ln -s /etc/ssl/certs/ssl-cert-snakeoil.pem cert.pem \
    && ln -s /etc/ssl/private/ssl-cert-snakeoil.key privkey.pem \
    && apt-get clean

COPY 000-default.conf /etc/apache2/sites-enabled/
COPY start.sh /usr/local/bin/
RUN chmod a+x /usr/local/bin/start.sh

EXPOSE 80 443

CMD ["start.sh"]
