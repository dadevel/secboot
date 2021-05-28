# secboot

A Python script that uses [dracut](https://github.com/dracutdevs/dracut) to turn a Linux kernel image into a self-signed and bootable EFI binary.

## Setup

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
