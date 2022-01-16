# secboot

A Python script that uses [Dracut](https://github.com/dracutdevs/dracut) to turn a Linux kernel image into a self-signed and bootable EFI binary.

## Setup & Usage

Requirements:

- Python 3.7 or newer
- dracut
- efitools
- efibootmgr
- openssl
- sbsigntools

First install the dependencies listed above with your package manager of choice.
Then install the `secboot` utility together with accompanying package manager hooks.
Currently supported are `apt` on Debian/Ubuntu and `pacman` on Arch Linux.

~~~ bash
git clone --depth 1 https://github.com/dadevel/secboot.git
sudo ./secboot/setup.sh
~~~

The next step is the configuration of `secboot`.
A description of the options and their default values can be found at the top of [secboot.py](./secboot.py#L16).
By default the EFI partition is expected to be labeled `efi` and mounted at `/boot/efi`.
The configuration is stored at `/etc/secboot/config.json`.

Example for Ubuntu with automatic signing of dynamic kernel modules:

~~~ json
{
  "esp-disk": "/dev/sda1",
  "kernel-params": "rw root=/dev/sda2",
  "dkms-files": ["/usr/lib/modules/{version}/updates/dkms/*.ko"]
}
~~~

Example for Arch Linux that utilizes partition labels, boots the Zen kernel by default and uses the LTS kernel as fallback:

~~~ json
{
  "esp-disk": "/dev/disk/by-label/boot",
  "initramfs-compression": "zstd",
  "kernel-params": "rw root=LABEL=root",
  "kernel-priority": ["linux-zen", "linux-lts"]
}
~~~

Now generate the certificates for Secure Boot and enroll them.

~~~ bash
sudo secboot generate-certificates && sudo secboot enroll-certificates && secboot check-enrollment
~~~

Finally build the EFI binary and configure the EFI bootloader.

For example on Arch Linux:

~~~ bash
sudo secboot update-bundle linux-zen "$(uname -r)"
~~~

For example on Debian/Ubuntu:

~~~ bash
sudo secboot update-bundle linux-"$(uname -r)" "$(uname -r)"
~~~
