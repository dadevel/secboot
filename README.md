# secboot

A Python script that uses [dracut](https://github.com/dracutdevs/dracut) to turn a Linux kernel image into a self-signed and bootable EFI binary.

## Setup & Usage

Requirements:

- Python 3.7 or newer
- dracut
- efitools
- efibootmgr
- openssl
- sbsigntools

Installation:

~~~ bash
git clone --depth 1 https://github.com/dadevel/secboot.git
sudo ./secboot/setup.sh
~~~

Configuration:

The configuration is stored in `/etc/secboot/config.json`.
A description of the options and their default values can be found in [secboot.py](./secboot.py#L14).
By default the EFI partition is expected to be mounted to `/boot/efi`.

Examples:

Configuration for Ubuntu with dynamic kernel modules:

~~~ json
{
  "esp-disk": "/dev/sda1",
  "kernel-params": "rw root=LABEL=root",
  "dkms-signing-enabled": true,
  "dkms-files": ["/usr/lib/modules/{version}/updates/dkms/*.ko"]
}
~~~

Configuration for Arch Linux that boots the Zen kernel by default, but builds an EFI bundle for the LTS kernel as fallback.

~~~ json
{
  "esp-disk": "/dev/disk/by-label/boot",
  "initramfs-compression": "zstd",
  "kernel-params": "rw root=LABEL=root",
  "kernel-priority": ["linux-zen", "linux-lts"]
}
~~~
