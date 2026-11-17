#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "run as root" >&2
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
UBUNTU_MIRROR=${UBUNTU_MIRROR:-https://mirror.yandex.ru/ubuntu/}

backup_dir="/var/backups/ci-master-$(date +%Y%m%d-%H%M%S)"
install -d -m 0700 "$backup_dir"

for path in \
    /etc/ssh/sshd_config \
    /etc/systemd/journald.conf \
    /etc/default/grub; do
    if [ -e "$path" ]; then
        cp -a "$path" "$backup_dir/"
    fi
done

sources_file=/etc/apt/sources.list.d/ubuntu.sources
if [ -f "$sources_file" ]; then
    sed -i -E \
        "s#^URIs: https?://([a-z]{2}\\.)?archive\\.ubuntu\\.com/ubuntu/?#URIs: ${UBUNTU_MIRROR}#" \
        "$sources_file"
fi

apt-get update
apt-get -y full-upgrade
apt-get install -y --no-install-recommends \
    acpid \
    ca-certificates \
    curl \
    git \
    jq \
    rsync \
    unattended-upgrades \
    unzip \
    zstd

hostnamectl set-hostname ci-master
if grep -qE '^127\.0\.1\.1[[:space:]]+' /etc/hosts; then
    sed -i -E 's/^127\.0\.1\.1[[:space:]]+.*/127.0.1.1 ci-master/' /etc/hosts
else
    printf '%s\n' '127.0.1.1 ci-master' >> /etc/hosts
fi

install -d -m 0755 /etc/systemd/journald.conf.d
printf '%s\n' \
    '[Journal]' \
    'SystemMaxUse=100M' \
    'RuntimeMaxUse=50M' \
    'MaxRetentionSec=7day' \
    'Compress=yes' \
    'Seal=yes' \
    > /etc/systemd/journald.conf.d/60-ci-master.conf

printf '%s\n' \
    '# CI VM reliability and low-memory profile.' \
    'vm.swappiness=10' \
    'vm.dirty_background_ratio=5' \
    'vm.dirty_ratio=15' \
    'kernel.panic=10' \
    'kernel.panic_on_oops=1' \
    'fs.inotify.max_user_instances=1024' \
    'fs.inotify.max_user_watches=524288' \
    > /etc/sysctl.d/60-ci-master.conf

printf '%s\n' \
    '* soft nofile 65536' \
    '* hard nofile 65536' \
    > /etc/security/limits.d/60-ci-master.conf

install -d -m 0755 /etc/apt/apt.conf.d
printf '%s\n' \
    'APT::Periodic::Update-Package-Lists "1";' \
    'APT::Periodic::Unattended-Upgrade "1";' \
    'APT::Periodic::AutocleanInterval "7";' \
    > /etc/apt/apt.conf.d/20auto-upgrades
printf '%s\n' \
    'Unattended-Upgrade::Automatic-Reboot "false";' \
    'Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";' \
    'Unattended-Upgrade::Remove-Unused-Dependencies "true";' \
    'Unattended-Upgrade::Remove-New-Unused-Dependencies "true";' \
    > /etc/apt/apt.conf.d/60-ci-master

printf '%s\n' \
    'GRUB_TIMEOUT=2' \
    'GRUB_TIMEOUT_STYLE=menu' \
    'GRUB_TERMINAL="console serial"' \
    'GRUB_SERIAL_COMMAND="serial --speed=115200 --unit=0 --word=8 --parity=no --stop=1"' \
    'GRUB_CMDLINE_LINUX_DEFAULT="console=tty0 console=ttyS0,115200n8"' \
    > /etc/default/grub.d/60-ci-master.cfg

if [ -s /home/ci_deployer/.ssh/authorized_keys ]; then
    install -d -m 0755 /etc/ssh/sshd_config.d
    printf '%s\n' \
        'PermitRootLogin no' \
        'PasswordAuthentication no' \
        'KbdInteractiveAuthentication no' \
        'PubkeyAuthentication yes' \
        'X11Forwarding no' \
        'AllowUsers ci_deployer' \
        'AuthenticationMethods publickey' \
        > /etc/ssh/sshd_config.d/00-ci-master.conf
    rm -f /etc/ssh/sshd_config.d/60-ci-master.conf
fi

install -d -o ci_deployer -g ci_deployer -m 0750 \
    /opt/actions-runner \
    /var/lib/gatebsd-ci

systemctl enable --now ssh acpid fstrim.timer unattended-upgrades.service

vm_unused_units="
bolt.service
fwupd.service
fwupd-refresh.timer
ModemManager.service
multipathd.service
multipathd.socket
packagekit.service
snapd.service
snapd.socket
snapd.seeded.service
udisks2.service
upower.service
"
for unit in $vm_unused_units; do
    systemctl disable --now "$unit" 2>/dev/null || true
    systemctl mask "$unit" 2>/dev/null || true
done

sysctl --system
update-grub
sshd -t
systemctl restart systemd-journald
systemctl reload ssh

apt-get -y autoremove
apt-get clean
journalctl --vacuum-size=100M

echo "ci-master optimization complete"
echo "backup: $backup_dir"
echo "reboot required if a new kernel was installed"
