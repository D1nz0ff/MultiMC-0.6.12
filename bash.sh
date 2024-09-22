#!/bin/bash

# Define your own values for these variables
YOUR_USERNAME='vpn'
YOUR_PASSWORD='rtk121212'

# Define the L2TP subnet and IP addresses
L2TP_NET='192.168.42.0/24'
L2TP_LOCAL='192.168.42.1'
L2TP_POOL='192.168.42.10-192.168.42.250'
DNS_SRV1='8.8.8.8'
DNS_SRV2='8.8.4.4'

# Function to exit with an error message
exiterr() { echo "Error: $1" >&2; exit 1; }

# Function to check if the script is run as root
check_root() {
  if [ "$(id -u)" != 0 ]; then
    exiterr "Script must be run as root. Try 'sudo bash $0'"
  fi
}

# Function to check if the system is supported
check_os() {
  os_type=$(lsb_release -si 2>/dev/null)
  [ -z "$os_type" ] && [ -f /etc/os-release ] && os_type=$(. /etc/os-release && printf '%s' "$ID")
  case $os_type in
    [Uu]buntu)
      os_type=ubuntu
      ;;
    [Dd]ebian)
      os_type=debian
      ;;
    *)
      exiterr "This script only supports Ubuntu and Debian."
      ;;
  esac
  os_ver=$(sed 's/\..*//' /etc/debian_version | tr -dc 'A-Za-z0-9')
  if [ "$os_ver" -lt 20 ]; then
    exiterr "This script requires Ubuntu 20.04 or Debian 10 or later."
  fi
}

# Function to install required packages
install_packages() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get -yqq update || apt-get -yqq update
  apt-get -yqq install strongswan xl2tpd ppp libnss3-tools iptables iproute2 >/dev/null
}

# Function to detect the public IP address
detect_ip() {
  public_ip=$(curl -s https://ipv4.icanhazip.com)
  if ! check_ip "$public_ip"; then
    exiterr "Cannot detect this server's public IP. Define it as variable 'public_ip' and re-run this script."
  fi
}

# Function to check if an IP address is valid
check_ip() {
  IP_REGEX='^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
  printf '%s' "$1" | tr -d '\n' | grep -Eq "$IP_REGEX"
}

# Function to create IPsec configuration
create_ipsec_config() {
  conf_bk "/etc/ipsec.conf"
  cat > /etc/ipsec.conf <<EOF
config setup
  charondebug="ike 1, knl 1, cfg 0"
  uniqueids=no

conn l2tp-psk
  auto=add
  left=%defaultroute
  leftid=$public_ip
  leftauth=pubkey
  leftcert=server-cert.pem
  right=%any
  rightauth=eap-mschapv2
  rightauth2=xauth-pam
  rightsourceip=$L2TP_NET
  rightdns=$DNS_SRV1,$DNS_SRV2
  ike=aes256-sha256-modp2048,aes128-sha256-modp2048
  esp=aes256-sha256,aes128-sha256
  dpdaction=clear
  dpddelay=300s
  rekey=no
  keyingtries=1
  ikelifetime=24h
  salifetime=24h
  rekeymargin=3m
  rekeyfuzz=1%
  keylife=1h
  margintime=3m
  fragment=yes
  mobike=no
  dpd=30s
  rekey=yes
  reauth=yes
  leftsubnet=0.0.0.0/0
  rightsubnet=$L2TP_NET
  leftfirewall=yes
  rightfirewall=yes
  leftsendcert=always
  rightsendcert=never
  leftcert=server-cert.pem
  rightcert=client-cert.pem
  leftid=@server
  rightid=@client
  leftca=ca-cert.pem
  rightca=ca-cert.pem
  eap_identity=%any
  xauth_identity=%any
  xauth_password=$YOUR_PASSWORD
EOF
}

# Function to create xl2tpd configuration
create_xl2tpd_config() {
  conf_bk "/etc/xl2tpd/xl2tpd.conf"
  cat > /etc/xl2tpd/xl2tpd.conf <<EOF
[global]
port = 1701

[lns default]
ip range = $L2TP_POOL
local ip = $L2TP_LOCAL
require chap = yes
refuse pap = yes
require authentication = yes
name = l2tpd
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
EOF
}

# Function to create PPP options
create_ppp_options() {
  conf_bk "/etc/ppp/options.xl2tpd"
  cat > /etc/ppp/options.xl2tpd <<EOF
require-mschap-v2
ms-dns $DNS_SRV1
ms-dns $DNS_SRV2
asyncmap 0
auth
crtscts
lock
hide-password
modem
debug
name l2tpd
proxyarp
lcp-echo-interval 30
lcp-echo-failure 4
EOF
}

# Function to create PPP credentials
create_ppp_credentials() {
  conf_bk "/etc/ppp/chap-secrets"
  cat > /etc/ppp/chap-secrets <<EOF
$YOUR_USERNAME l2tpd $YOUR_PASSWORD *
EOF
}

# Function to update sysctl settings
update_sysctl() {
  conf_bk "/etc/sysctl.conf"
  cat >> /etc/sysctl.conf <<EOF

# Added by L2TP IPsec VPN script
net.ipv4.ip_forward = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.default.rp_filter = 0
EOF
  sysctl -p
}

# Function to update IPTables rules
update_iptables() {
  iptables -A INPUT -p udp --dport 500 -j ACCEPT
  iptables -A INPUT -p udp --dport 4500 -j ACCEPT
  iptables -A INPUT -p udp --dport 1701 -m policy --dir in --pol ipsec -j ACCEPT
  iptables -A FORWARD -s $L2TP_NET -j ACCEPT
  iptables -A FORWARD -d $L2TP_NET -j ACCEPT
  iptables -t nat -A POSTROUTING -s $L2TP_NET -o $(ip -4 route get 1 | awk '{print $5}') -j MASQUERADE
  iptables-save > /etc/iptables/rules.v4
}

# Function to enable services on boot
enable_services() {
  systemctl enable strongswan
  systemctl enable xl2tpd
  systemctl enable ipsec
}

# Function to start services
start_services() {
  systemctl restart strongswan
  systemctl restart xl2tpd
  systemctl restart ipsec
}

# Main function to set up the VPN
setup_vpn() {
  check_root
  check_os
  install_packages
  detect_ip
  create_ipsec_config
  create_xl2tpd_config
  create_ppp_options
  create_ppp_credentials
  update_sysctl
  update_iptables
  enable_services
  start_services
}

# Run the setup
setup_vpn

# Show VPN information
cat <<EOF

================================================

L2TP IPsec VPN server is now ready for use!

Connect to your new VPN with these details:

Server IP: $public_ip
Username: $YOUR_USERNAME
Password: $YOUR_PASSWORD

Write these down. You'll need them to connect!

VPN client setup: https://vpnsetup.net/clients

================================================

EOF