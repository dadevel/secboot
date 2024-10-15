# secboot

An all-in-one Python script to secure your Linux boot process.

Included features:

- enrollment of self-signed Secure Boot certificates
- direct kernel boot trough [Unified Kernel Images](https://wiki.archlinux.org/title/Unified_kernel_image) built with [Dracut](https://github.com/dracutdevs/dracut)
- LUKS encryption keys stored in TPM and protected by TPM PIN via [systemd-cryptenroll](https://www.freedesktop.org/software/systemd/man/latest/systemd-cryptenroll.html)
- integrated support for [fwupd](https://github.com/fwupd/fwupd)

Supported distributions:

- Arch Linux (stable)
- Debian/Ubuntu (experimental)

Hardware requirements:

- TPM 2.0 in firmware or dedicated

## Setup & Usage

The setup can be performed on an existing installation as long as the installation is booted via UEFI and has a LUKS-encrypted root partition.

First install the following dependencies with the package manager of your distro:

- Python 3.11 or newer
- cryptsetup
- dracut
- efibootmgr
- efitools
- fwupd
- openssl
- sbsigntools
- tpm2-tools

Then install the `secboot` utility together with accompanying package manager hooks.
Currently supported are `apt` on Debian/Ubuntu and `pacman` on Arch Linux.

~~~ bash
git clone --depth 1 https://github.com/dadevel/secboot.git
sudo ./secboot/setup.sh
~~~

The next step is the configuration of `secboot`.
A description of the options and their default values can be found at the top of [main.py](./secboot/main.py#L18).
The configuration is always stored at `/etc/secboot/config.json`.

Example for Ubuntu with automatic signing of dynamic kernel modules:

~~~ json
{
  "efi-partition": "/dev/sda1",
  "efi-mountpoint": "/boot/efi",
  "efi-subdir": "/boot/efi/EFI/Linux",
  "luks-partition": "/dev/sda2",
  "kernel-params": "rw root=LABEL=root",
  "dkms-files": ["/usr/lib/modules/{version}/updates/dkms/*.ko"]
}
~~~

Example for Arch Linux with additional hardening and fallback to LTS kernel:

~~~ json
{
  "efi-partition": "/dev/nvme0n1p1",
  "efi-mountpoint": "/boot",
  "efi-subdir": "/boot/EFI/Linux",
  "luks-partition": "/dev/nvme0n1p2",
  "kernel-params": "rw rd.luks.allow-discards rd.luks.timeout=0 root=LABEL=root rootflags=x-systemd.device-timeout=0 lsm=capability,landlock,lockdown,yama,bpf,integrity rd.shell=0 rd.emergency=reboot quiet",
  "kernel-priority": ["linux", "linux-lts"],
  "initramfs-compression": "zstd"
}
~~~

Before you continue bring your UEFI firmware into Secure Boot Setup Mode.
The procedure on Lenovo ThinkPads is the following:

1. Power cycle your laptop and press `F1` when the Lenovo logo appears to open BIOS settings.
2. Ensure that `Security/Secure Boot/Secure Boot` is `Enabled`.
3. Select `Security/Secure Boot/Reset to Setup Mode` and `Security/Secure Boot/Clear All Secure Boot Keys`.
4. Make sure the TPM module is enabled.
5. Save and exit with `F10`.  

After your computer booted back up generate the Secure Boot certificates and enroll them.
The command is idempotent and can be repeated in case of failure.

~~~ bash
sudo secboot enroll-certificates
~~~

Then trigger a rebuild of the UKI by reinstalling the kernel package.

~~~ bash
# Arch Linux
sudo pacman -S linux
# Debian/Ubuntu
sudo apt install --reinstall -y linux-image-6.5.0-21-generic
~~~

Next reboot your computer.

~~~ bash
sudo systemctl reboot
~~~

Wait until the reboot completed and verify that Secure Boot is active.

~~~ bash
sudo fwupdtool security 2> /dev/null | grep -i 'secure boot'
~~~

Now add a TPM-protected key to LUKS.
The command is idempotent as well.

~~~ bash
sudo secboot enroll-tpm
~~~

Then trigger another UKI rebuild.

~~~ bash
# Arch Linux
sudo pacman -S linux
# Debian/Ubuntu
sudo apt install --reinstall -y linux-image-6.5.0-21-generic
~~~

And reboot one more time.

~~~ bash
sudo systemctl reboot
~~~

On Arch Linux you can now remove `mkinitcpio`.

~~~ bash
sudo pacman -Rns mkinitcpio
~~~

## Troubleshooting

The warning *data remaining: gaps between PE/COFF sections?* is caused by `sbsign` and can be safely ignored.

If fwupd fails on Arch Linux with the error *Secure Boot is enabled, but shim isn't installed* then run `sudo touch /boot/efi/EFI/arch/shimx64.efi`.

## References

- [User:Krin/Secure Boot, full disk encryption, and TPM2 unlocking install](http://web.archive.org/web/20231203112801/https://wiki.archlinux.org/title/User:Krin/Secure_Boot,_full_disk_encryption,_and_TPM2_unlocking_install)
- [Unlocking LUKS2 volumes with TPM2, FIDO2, PKCS#11 Security Hardware on systemd 248](http://web.archive.org/web/20240209114847/http://0pointer.net/blog/unlocking-luks2-volumes-with-tpm2-fido2-pkcs11-security-hardware-on-systemd-248.html)
