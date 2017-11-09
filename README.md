# JupyterHub-SAML

![alt text](diagram.svg)

What do we need:

- docker
- docker-compose
- domain name
- SAML Configuration

### docker
Please make sure you have docker up and running on your system. 

~~~
https://docs.docker.com/get-started/
~~~

#### docker-compose
Please make sure also docker-compose is installed on your system.

~~~
https://docs.docker.com/compose/install/
~~~

### domain name
For this demomnstration we like to have an domain name that we can reach on the public internet. If you have a domain name already and you hav control over de the DNS settings of that domain, then the recommendation is to reserve a subdomain and register a A-record to the IP-Address of your Docker VPS/Machine. Make sure that port 443 is open on the firewall.

### SAML Configuration
Here we need several steps.

If you are new to SAML and Federated Authentication, here is some good readings that will you get prepared with the required background information

~~~
https://wiki.surfnet.nl/display/surfconextdev/Schematic+overview
~~~

Our VPS machine will act as a "Service Provider"
During this demonstration, we make use of surfconext to connect to our "Identity Providers"

In preparation for that we need the following:

#### Service Provider key-set

The following commands will generate a self-signed keyset that is OK for this demonstration.
 
~~~
openssl genrsa -out server.key
openssl req -new -x509 -key server.key -out server.crt -days 365
~~~

#### Service Provide Metadata

Here we need to prepare Metadata that we can pass on to the Identity Provider in order to establish a bilateral "trust-relation" between us.

This template can be used and adjusted where appropriate

File: ***metadata.xml***

~~~
<?xml version="1.0"?>
<!--
     Author: Harry Kodden
-->
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xml:id="MyData" entityID="https://%%% SERVICE NAME %%%/sp/metadata-1f68bf6b-4f43-41d4-8460-f997a94ca485">
   <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
      <ds:Reference URI="#MyData">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <ds:DigestValue/>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue/>
    <ds:KeyInfo>
      <ds:KeyName/>
    </ds:KeyInfo>
  </ds:Signature>  <md:Extensions xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport">
    <alg:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
    <alg:DigestMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#sha384"/>
    <alg:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
    <alg:DigestMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#sha224"/>
    <alg:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
    <alg:SigningMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"/>
    <alg:SigningMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"/>
    <alg:SigningMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/>
    <alg:SigningMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224"/>
    <alg:SigningMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"/>
    <alg:SigningMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"/>
    <alg:SigningMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    <alg:SigningMethod Algorithm="http://www.w3.org/2009/xmldsig11#dsa-sha256"/>
    <alg:SigningMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1"/>
    <alg:SigningMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
    <alg:SigningMethod Algorithm="http://www.w3.org/2000/09/xmldsig#dsa-sha1"/>
  </md:Extensions>
    <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:Extensions>
      <mdui:UIInfo xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui">
        <mdui:DisplayName xml:lang="nl">My Velocity Service</mdui:DisplayName>
        <mdui:DisplayName xml:lang="en">My Velocity Service</mdui:DisplayName>
        <mdui:Description xml:lang="nl">Een mooie voorbeelddienst om te laten zien hoe Shibboleth werkt</mdui:Description>
        <mdui:Description xml:lang="en">A nice example Service to show how to work with Shibboleth and SURFconext</mdui:Description>
        <mdui:Logo height="300" width="500">https://%%% DOMAIN %%%/static/img/logo.png</mdui:Logo>
      </mdui:UIInfo>
      <init:RequestInitiator xmlns:init="urn:oasis:names:tc:SAML:profiles:SSO:request-init" Binding="urn:oasis:names:tc:SAML:profiles:SSO:request-init" Location="https://%%% DOMAIN %%%/saml/Login"/>
    </md:Extensions>
    <md:KeyDescriptor>
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:KeyName>%%% SERVICE NAME %%%</ds:KeyName>
        <ds:X509Data>
          <ds:X509SubjectName>CN=%%% SERVICE NAME %%%</ds:X509SubjectName>
          <ds:X509Certificate>%%% X509 %%%</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
      <md:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/>
      <md:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes192-gcm"/>
      <md:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/>
      <md:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>
      <md:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes192-cbc"/>
      <md:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/>
      <md:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#tripledes-cbc"/>
      <md:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep"/>
      <md:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>
    </md:KeyDescriptor>
    <md:ArtifactResolutionService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://%%% DOMAIN %%%/saml/Artifact/SOAP" index="1"/>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://%%% DOMAIN %%%/saml/SLO/SOAP"/>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://%%% DOMAIN %%%/saml/SLO/Redirect"/>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://%%% DOMAIN %%%/saml/SLO/POST"/>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" Location="https://%%% DOMAIN %%%/saml/SLO/Artifact"/>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://%%% DOMAIN %%%/saml/SAML2/POST" index="1"/>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign" Location="https://%%% DOMAIN %%%/saml/SAML2/POST-SimpleSign" index="2"/>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" Location="https://%%% DOMAIN %%%/saml/SAML2/Artifact" index="3"/>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:PAOS" Location="https://%%% DOMAIN %%%/saml/SAML2/ECP" index="4"/>
  </md:SPSSODescriptor>
  <md:Organization>
    <md:OrganizationName xml:lang="nl">Voorbeeld (NL)</md:OrganizationName>
    <md:OrganizationName xml:lang="en">Example (NL)</md:OrganizationName>
    <md:OrganizationDisplayName xml:lang="nl">Voorbeeld Service</md:OrganizationDisplayName>
    <md:OrganizationDisplayName xml:lang="en">Example Service</md:OrganizationDisplayName>
    <md:OrganizationURL xml:lang="nl">https://%%% DOMAIN %%%/</md:OrganizationURL>
    <md:OrganizationURL xml:lang="en">https://%%% DOMAIN %%%/</md:OrganizationURL>
  </md:Organization>
  <md:ContactPerson contactType="support">
    <md:GivenName>John</md:GivenName>
    <md:SurName>Doe</md:SurName>
    <md:EmailAddress>John.Doe@example.org</md:EmailAddress>
  </md:ContactPerson>
  <md:ContactPerson contactType="technical">
    <md:GivenName>John</md:GivenName>
    <md:SurName>Doe</md:SurName>
    <md:EmailAddress>John.Doe@example.org</md:EmailAddress>
  </md:ContactPerson>
  <md:ContactPerson contactType="administrative">
    <md:GivenName>John</md:GivenName>
    <md:SurName>Doe</md:SurName>
    <md:EmailAddress>John.Doe@example.org</md:EmailAddress>
  </md:ContactPerson>
</md:EntityDescriptor>
~~~

Please replace at least these placeholders with the appropriate valeus:

| Placeholder | To be replaced by |
| ------ | ----------- |
| %%% DOMAIN %%%   | the full domain name, for example: ***https://www.example.org*** |
| %%% X509 %%% | output of command ***openssl x509 -in etc/sp/sp-cert.pem*** 
|	|(please remove the lines BEGIN CERTICATE and END CERTIFICATE). |

Before this Metadata can be send to the Identity Provider, we need to sign the contents.

This can be achieved from command line by using '***xmlsec1***'

~~~
xmlsec1 --sign --output signed_metadata.xml --privkey-pem server.key metadata.xml
~~~


 

## Installation

## Configuration

### Configure SP

#### Configure NGINX - Reverse Proxy

~~~
~~~

#### Configure Apache + Shibboleth

~~~
<VirtualHost *:80>
  ServerName http://%%SERVER_NAME%%:80
  RewriteEngine On
  RewriteCond %{HTTPS} off
  RewriteRule ^ https://%{HTTP_HOST}:443%{REQUEST_URI} [R=302,L,QSA]
</VirtualHost>

<VirtualHost *:443>
  ServerName https://%%SERVER_NAME%%:443

  RedirectMatch 301 /jupyter/hub/logout https://%%SERVER_NAME%%/saml/Logout?return=https%3A//%%SERVER_NAME%%/jupyter

  ErrorLog ${APACHE_LOG_DIR}/error.log
  CustomLog ${APACHE_LOG_DIR}/access.log combined

  LogLevel warn

  Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains"

  SSLEngine on
  SSLProtocol all -SSLv2 -SSLv3
  SSLCipherSuite EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH
  SSLHonorCipherOrder on

  SSLCertificateFile /etc/apache2/cert.pem
  SSLCertificateKeyFile /etc/apache2/privkey.pem

  <Location "/saml">
    SetHandler shib
  </Location>

  <Location /jupyter>
    AuthType shibboleth
    ShibRequestSetting requireSession 1
    Require valid-user

    RewriteEngine On
    RewriteCond %{LA-U:REMOTE_USER} (.*)
    RewriteRule . - [E=RU:%1]
    RequestHeader set REMOTE_USER "%{RU}e" env=RU
  </Location>

  ProxyPreserveHost On

  ProxyPass /jupyter              http://jupyter:8000/
  ProxyPassReverse /jupyter       http://jupyter:8000/

  ProxyPass /jupyter/hub          http://jupyter:8000/hub
  ProxyPassReverse /jupyter/hub   http://jupyter:8000/hub

</VirtualHost>
~~~


### Prepare Notebook image



