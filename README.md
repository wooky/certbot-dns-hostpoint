***This project is no longer maintained as I am not using Hostpoint anymore. As of writing this, the plugin is working fine. Feel free to continue using it, or fork it.***
---

# certbot-dns-hostpoint

[Hostpoint](https://www.hostpoint.ch/en/) DNS Authenticator plugin for Certbot.

This plugin automates the process of completing a dns-01 challenge by creating, and subsequently removing, TXT records by manually calling Hostpoint HTTP endpoints, as Hostpoint does not have a publically accessible REST API.

## Installation

The plugin has been developed and tested on Python 3.9. Once you have that and pip installed, get the latest version by running:

```bash
pip install https://github.com/wooky/certbot-dns-hostpoint/archive/refs/heads/master.zip
```

## Configuration File

The required configuration file is an INI file with these entries:

* `dns_hostpoint_username`: Username of the Hostpoint account
* `dns_hostpoint_password`: Password of the Hostpoint account
* `dns_hostpoint_domain`: Target domain that is registered on the Hostpoint account

The configuration file should not be readable by outside users, i.e. owned by root with chmod 600.

## Named Arguments

The following arguments must/can be used when running Certbot with the plugin:

* `--authenticator dns-hostpoint`: (required) use the Hostpoint DNS Authenticator plugin
* `--dns-hostpoint-credentials`: (required) path to credentials INI file
* `--dns-hostpoint-propagation-seconds`: (optional, default: 30) waiting time for DNS to propagate before asking the ACME server to verify the DNS record

## Example

Supposing your base domain is example.tld, the basic configuration file should look like this:

```text
dns_hostpoint_username=username
dns_hostpoint_password=password
dns_hostpoint_domain=example.tld
```

Then, you can run Certbot with the base and wildcard domains like this:

```bash
certbot certonly \
  --authenticator dns-hostpoint \
  --dns-hostpoint-credentials /path/to/hostpoint.ini \
  -d 'example.tld' \
  -d '*.example.tld' \
  -d '*.subdomain.example.tld'
```

## Malformed DNS record populate response: Expecting value: line 1 column 1 (char 0)

If you get this error, it most likely means that Hostpoint requires you to enter a verification code. This plugin will not work until that issue is resolved.

Simply log in to Hostpoint through a browser on the same IP as the plugin is run, enter the verification code, and afterwards the plugin should start working. If you're unable to run a browser from the remote host, use a SOCKS5 proxy instead.
