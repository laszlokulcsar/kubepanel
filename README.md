# Kubepanel

Kubepanel is a free and open-source web hosting control panel based on Kubernetes (it supports microk8s out of the box at the moment).
The project is in an early PoC stage at the moment, the goal is to create an open source K8S based alternative to control panels like cPanel, DirectAdmin and others.
Since it's kubernetes native, the infrastructure is modular, you can add own container images to satisfy various customer needs.

# Prerequisites

- You need a preferably fresh installation of Ubuntu 20.04 LTS or 22.04 LTS with internet access 
- A public IP address and a DNS entry with an A record pointing to your public IP address. This is required to reach the Kubepanel UI after the installation. i.e.: if you have a domain name 'example.com' you can create an A record 'kubepanel.example.com' which resolves to your servers public IP address.
- Open port 443 on your firewall
  
# INSTALL on the 1st node:

```
bash <(curl \
https://raw.githubusercontent.com/laszlokulcsar/kubepanel-infra/refs/heads/main/kubepanel-install.sh)
```
# INSTALL on the 2nd and 3rd node:

```
bash <(curl \
https://raw.githubusercontent.com/laszlokulcsar/kubepanel-infra/refs/heads/main/join-node.sh)
```

After the successful installation you can reach the Kubepanel UI on your choosen domain name.


# Features

- Django based web application for account management
- A hosting account uses Nginx and PHP containers by default
- SFTP/SCP support (as sidecar container) for uploading codebase to the containers
- MariaDB as default database backend
- Postfix with DKIM signing for outgoing emails
- Automatic HTTPS certificate management by cert-manager
- Supports the latest Wordpress by default

# Mailbox management

For incoming e-mail and mailbox management I suggest to use the following project: https://github.com/technicalguru/docker-mailserver
