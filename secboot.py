#!/usr/bin/env python3
from __future__ import annotations
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Generator, Union
import json
import logging
import os
import re
import shlex
import subprocess
import sys
import uuid

DEFAULTS = {
    # path to the EFI partition
    'esp-disk': '/dev/disk/by-label/efi',
    # path to the mountpoint of the EFI partition
    'esp-mountpoint': '/boot/efi',
    # path to a subdirectory on the EFI partition where the EFI bundles will be stored
    'esp-subdir': '/boot/efi/EFI/Linux',
    # kernel parameters, the stuff you would normally put into the GRUB_CMDLINE_LINUX_DEFAULT variable in /etc/default/grub
    'kernel-params': '',
    # which compression algorithm to use, zstd supported since linux kernel 5.9
    'initramfs-compression': 'lz4',
    # sign dkms modules
    'dkms-signing-enabled': False,
    'dkms-files': [],
    # where to store the generated certificates
    'certificate-storage': '/etc/secboot',
    # additional command line parameters passed to dracut
    'dracut-params': [],
    # arch linux only: which kernel to boot by default
    'kernel-priority': [],
    # if your are using systemd there's no need to touch the following options
    'machine-id': '/etc/machine-id',
    'efi-stub': '/usr/lib/systemd/boot/efi/linuxx64.efi.stub',
}


def main(args: list[str]) -> None:
    dpkg_params = os.environ.get('DEB_MAINT_PARAMS', '').lower()
    entrypoint = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter)
    entrypoint.add_argument('-c', '--config', type=lambda x: Path(x), default=Path('/etc/secboot/config.json'))
    entrypoint.add_argument('-l', '--log-level', choices=('debug', 'info', 'warning', 'error', 'critical'), default='info')
    if dpkg_params:
        entrypoint.add_argument('name', nargs=1, help='package name')
        entrypoint.add_argument('path', nargs='?', help='image path (not used)')
    else:
        subparsers = entrypoint.add_subparsers(dest='action', required=True)
        for action in ('update-bundle', 'remove-bundle'):
            parser = subparsers.add_parser(action)
            parser.add_argument('name', nargs=1, help='package name')
            parser.add_argument('version', nargs=1, help='kernel version')
        for action in ('generate-certificates', 'enroll-certificates'):
            parser = subparsers.add_parser(action)
        for action in ('pacman-update', 'pacman-remove'):
            parser = subparsers.add_parser(action, help='pacman hook')

    opts = entrypoint.parse_args(args)
    logging.basicConfig(level=opts.log_level.upper(), stream=sys.stderr, format='%(levelname)s %(message)s')
    logging.debug(f'options: {opts}')

    config = Configuration.read(opts.config, opts.log_level)
    logging.debug(f'configuration: {config}')

    if dpkg_params:
        if dpkg_params.startswith('configure '):
            dpkg_postinst(opts.name[0], config)
        elif dpkg_params.startswith('remove '):
            dpkg_postrm(opts.name[0], config)
        else:
            logging.warning('called from dpkg: wrong phase')
    else:
        actions = {
            'update-bundle': lambda o: update_bundle(o.name[0], o.version[0], config),
            'remove-bundle': lambda o: remove_bundle(o.name[0], o.version[0], config),
            'generate-certificates': lambda _: generate_certificates(config),
            'enroll-certificates': lambda _: enroll_certificates(config),
            'pacman-update': lambda _: pacman_update(config),
            'pacman-remove': lambda _: pacman_remove(config),
        }
        action = actions[opts.action]
        action(opts)


@dataclass
class Configuration:
    certificate_storage: Path
    machine_id: str
    esp_disk: Path
    esp_mountpoint: Path
    esp_subdir: Path
    efi_stub: Path
    initramfs_compression: str
    dracut_params: list
    kernel_params: str
    kernel_priority: list
    dkms_signing_enabled: bool
    dkms_files: list
    log_level: str

    def __post_init__(self) -> None:
        self.certificate_storage = Path(self.certificate_storage)
        self.machine_id = Path(self.machine_id).read_text().strip()
        self.esp_disk = Path(self.esp_disk)
        self.esp_mountpoint = Path(self.esp_mountpoint)
        self.esp_subdir = Path(self.esp_subdir)
        self.efi_stub = Path(self.efi_stub)
        self.initramfs_compression = str(self.initramfs_compression)
        self.dracut_params = [str(x) for x in self.dracut_params]
        self.kernel_params = str(self.kernel_params)
        self.kernel_priority = [str(x) for x in self.kernel_priority]
        self.dkms_signing_enabled = bool(self.dkms_signing_enabled)
        self.dkms_files = [str(x) for x in self.dkms_files]

    @classmethod
    def read(cls, path: Path, log_level: str) -> Configuration:
        try:
            options = DEFAULTS.copy()
            with open(path) as file:
                options.update(json.load(file))
            options = {key.replace('-', '_'): value for key, value in options.items()}
            return cls(**options, log_level=log_level)
        except Exception as e:
            raise AssertionError(f'invalid configuration: {e}') from e

    def find_dkms_files(self, version: str) -> Generator[Path, None, None]:
        for pattern in self.dkms_files:
            for path in Path('/').glob(pattern.format(version=version).lstrip('/')):
                if path.is_file():
                    yield path


@dataclass
class Bundle:
    name: str
    version: str
    config: Configuration

    @property
    def label(self) -> str:
        return f'{self.name}-{self.config.machine_id}'

    @property
    def path(self) -> Path:
        return self.config.esp_subdir/f'{self.label}.efi'

    @property
    def loader(self) -> str:
        return '\\' + self.path.relative_to(self.config.esp_mountpoint).as_posix().replace('/', '\\')


@dataclass
class BundleManager:
    config: Configuration

    def build(self, bundle: Bundle) -> None:
        self.config.esp_subdir.mkdir(parents=True, exist_ok=True)
        run(
            'dracut',
            '--force',
            '--stdlog', '7' if self.config.log_level == 'debug' else '3',
            # behavior
            '--persistent-policy', 'by-label',
            '--fstab',
            '--reproducible',
            # minify
            '--hostonly',
            '--strip',
            '--compress', self.config.initramfs_compression,
            # uefi
            '--uefi',
            '--uefi-stub', self.config.efi_stub,
            '--early-microcode',
            '--no-hostonly-cmdline',
            '--kernel-cmdline', self.config.kernel_params,
            *self.config.dracut_params,
            '--', bundle.path, bundle.version
        )

    def sign(self, bundle: Bundle) -> None:
        run('sbsign', '--key', self.config.certificate_storage/'db.key.pem', '--cert', self.config.certificate_storage/'db.crt.pem', '--output', bundle.path, bundle.path)

    def sign_modules(self, bundle: Bundle) -> None:
        signer = self._find_module_signing_tool(bundle.version)
        for path in self.config.find_dkms_files(bundle.version):
            run(signer, '-d', 'sha512', self.config.certificate_storage/'db.key.pem', self.config.certificate_storage/'db.crt.der', path)

    @staticmethod
    def _find_module_signing_tool(kver: str) -> Union[str, Path]:
        try:
            run('kmodsign', '--version', capture=True)
            return 'kmodsign'
        except RuntimeError:
            pass

        path = Path(f'/usr/lib/modules/{kver}/build/scripts/sign-file')
        if path.exists() and path.is_file():
            return path

        raise AssertionError('can not sign kernel modules, neither kmodsign nor sign-file could be found')

    def delete(self, bundle: Bundle) -> None:
        bundle.path.unlink()


@dataclass
class BootEntry:
    number: str
    name: str
    config: Configuration

    @property
    def label(self) -> str:
        return f'{self.name}-{self.config.machine_id}'

    @property
    def path(self) -> Path:
        return self.config.esp_subdir/f'{self.label}.efi'


@dataclass
class BootManager:
    config: Configuration

    def __post_init__(self) -> None:
        self.efibootmgr()

    def register(self, bundle: Bundle) -> None:
        if bundle.label not in {entry.label for entry in self.entries}:
            self.efibootmgr('--create', '--label', bundle.label, '--loader', bundle.loader)

    def delete_invalid(self) -> None:
        for entry in self.entries:
            if not entry.path.is_file():
                self.efibootmgr('--delete-bootnum', '--bootnum', entry.number)

    def rewrite_order(self) -> None:
        new_order = [entry.number for entry in self._sort_entries_by_priority()]
        new_order += [num for num in self.order if num not in new_order and num in self.misc_nums]
        if new_order != self.order:
            self.efibootmgr('--bootorder', ','.join(new_order))

    def efibootmgr(self, *args: Union[str, Path]) -> None:
        output = run('efibootmgr', '--disk', self.config.esp_disk, *args, capture=True)
        self.order, self.entries, self.misc_nums = self._parse_output(output)

    def _sort_entries_by_priority(self) -> list[BootEntry]:
        def comparator(entry):
            try:
                return self.config.kernel_priority.index(entry.name)
            except ValueError:
                return float('inf')

        return list(sorted(self.entries, key=comparator))

    def _parse_output(self, text: str) -> tuple[list[str], list[BootEntry], list[str]]:
        order_regex = re.compile(r'BootOrder: (.+?)')
        kernel_entry_regex = re.compile(r'Boot(....)\*?\s+(.+?)-' + re.escape(self.config.machine_id))
        misc_entry_regex = re.compile(r'Boot(....)\*?\s+.+')
        order = list()
        kernel_entries = list()
        misc_nums = list()
        for line in text.splitlines():
            if line.startswith('BootCurrent:') or line.startswith('Timeout:'):
                continue
            match = order_regex.fullmatch(line)
            if match:
                order = match.group(1).split(',')
                continue
            match = kernel_entry_regex.fullmatch(line)
            if match:
                entry = BootEntry(match.group(1), match.group(2), self.config)
                kernel_entries.append(entry)
                continue
            match = misc_entry_regex.fullmatch(line)
            if match:
                misc_nums.append(match.group(1))
                continue
            logging.warning(f'cant handle boot entry: {line}')
        return order, kernel_entries, misc_nums


def run(*args: Union[str, Path], capture=False) -> str:
    logging.info(f'{" ".join(shlex.quote(str(x)) for x in args)}')
    process = subprocess.run(args, check=False, capture_output=capture, text=True)
    if process.returncode != 0:
        if capture:
            raise RuntimeError(f'subprocess failed: {process.stderr.strip()}')
        raise RuntimeError(f'subprocess failed: exit code {process.returncode}')
    return process.stdout


def dpkg_postinst(version: str, config: Configuration) -> None:
    if not Path(f'/usr/lib/modules/{version}/modules.dep').is_file():
        run('depmod', '-a', '-F', f'/boot/System.map-{version}', version)
    update_bundle(f'linux-{version}', version, config)


def dpkg_postrm(version: str, config: Configuration) -> None:
    remove_bundle(f'linux-{version}', version, config)


def pacman_update(config: Configuration) -> None:
    pacman_hook(update_bundle, config)


def pacman_remove(config: Configuration) -> None:
    pacman_hook(remove_bundle, config)


def pacman_hook(callback: Callable, config: Configuration) -> None:
    kernel_regex = re.compile('^usr/lib/modules/[^/]+/vmlinuz$')
    ucode_regex = re.compile('^boot/[^/]+-ucode.img$')
    stub_regex = re.compile('^usr/lib/systemd/boot/efi/linux[^/]+.efi.stub$')
    for line in sys.stdin:
        line = line.strip()
        path = Path(line)
        if kernel_regex.match(line):
            pacman_hook_inner(callback, config, path)
        elif ucode_regex.match(line) or stub_regex.match(line):
            for kernel in Path('usr/lib/modules').glob('*/vmlinuz'):
                pacman_hook_inner(callback, config, kernel)
            return


def pacman_hook_inner(callback: Callable, config: Configuration, path: Path) -> None:
    kver = path.parent.name
    pkgbase = path.parent.joinpath('pkgbase').read_text().strip()
    return callback(pkgbase, kver, config)


def update_bundle(name: str, version: str, config: Configuration) -> None:
    bundle_manager = BundleManager(config)
    boot_manager = BootManager(config)
    bundle = Bundle(name, version, config)

    bundle_manager.build(bundle)
    bundle_manager.sign(bundle)
    if config.dkms_signing_enabled:
        bundle_manager.sign_modules(bundle)
    boot_manager.register(bundle)
    boot_manager.delete_invalid()
    boot_manager.rewrite_order()


def remove_bundle(name: str, version: str, config: Configuration) -> None:
    bundle_manager = BundleManager(config)
    boot_manager = BootManager(config)
    bundle = Bundle(name, version, config)

    bundle_manager.delete(bundle)
    boot_manager.delete_invalid()
    boot_manager.rewrite_order()


def generate_certificates(config: Configuration) -> None:
    try:
        run('openssl', 'version', capture=True)
    except RuntimeError as e:
        raise AssertionError('openssl not installed') from e

    try:
        run('cert-to-efi-sig-list', '--version', capture=True)
        run('sign-efi-sig-list', '--version', capture=True)
    except RuntimeError as e:
        raise AssertionError('sbsigntools not installed') from e

    storage = config.certificate_storage
    storage.mkdir(exist_ok=True)

    guid = str(uuid.uuid4())
    storage.joinpath('guid.txt').write_text(guid)

    # generate certificates
    run('openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-new', '-x509', '-sha256', '-days', '3650', '-subj', '/CN=Platform Key/', '-out', storage/'pk.crt.pem', '-outform', 'pem', '-keyout', storage/'pk.key.pem', '-keyform', 'pem')
    run('openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-new', '-x509', '-sha256', '-days', '3650', '-subj', '/CN=Key Exchange Key/', '-out', storage/'kek.crt.pem', '-outform', 'pem', '-keyout', storage/'kek.key.pem', '-keyform', 'pem')
    run('openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-new', '-x509', '-sha256', '-days', '3650', '-subj', '/CN=Signature Database Key/', '-out', storage/'db.crt.pem', '-outform', 'pem', '-keyout', storage/'db.key.pem', '-keyform', 'pem')

    # convert certificates
    run('openssl', 'x509', '-in', storage/'pk.crt.pem', '-inform', 'pem', '-out', storage/'pk.crt.der', '-outform', 'der')
    run('openssl', 'x509', '-in', storage/'kek.crt.pem', '-inform', 'pem', '-out', storage/'kek.crt.der', '-outform', 'der')
    run('openssl', 'x509', '-in', storage/'db.crt.pem', '-inform', 'pem', '-out', storage/'db.crt.der', '-outform', 'der')

    # generate signature lists
    run('cert-to-efi-sig-list', '-g', guid, storage/'pk.crt.pem', storage/'pk.esl')
    run('cert-to-efi-sig-list', '-g', guid, storage/'kek.crt.pem', storage/'kek.esl')
    run('cert-to-efi-sig-list', '-g', guid, storage/'db.crt.pem', storage/'db.esl')

    # sign signature lists
    run('sign-efi-sig-list', '-g', guid, '-k', storage/'pk.key.pem', '-c', storage/'pk.crt.pem', 'PK', storage/'pk.esl', storage/'pk.auth')
    run('sign-efi-sig-list', '-g', guid, '-k', storage/'pk.key.pem', '-c', storage/'pk.crt.pem', 'PK', '/dev/null', storage/'pk-rm.auth')
    run('sign-efi-sig-list', '-g', guid, '-k', storage/'pk.key.pem', '-c', storage/'pk.crt.pem', 'KEK', storage/'kek.esl', storage/'kek.auth')
    run('sign-efi-sig-list', '-g', guid, '-k', storage/'kek.key.pem', '-c', storage/'kek.crt.pem', 'db', storage/'db.esl', storage/'db.auth')


def enroll_certificates(config: Configuration) -> None:
    try:
        run('efi-updatevar', '--version')
        run('efi-readvar', '--version')
    except RuntimeError as e:
        raise AssertionError('efitools not installed') from e

    try:
        storage = config.certificate_storage
        run('efi-updatevar', '-e', '-f', storage/'db.esl', 'db')
        run('efi-updatevar', '-e', '-f', storage/'kek.esl', 'KEK')
        run('efi-updatevar', '-f', storage/'pk.auth', 'PK')
        run('efi-readvar')
    except RuntimeError as e:
        raise AssertionError('secureboot certificate enrollment failed, ensure that secureboot is in setup mode') from e


if __name__ == '__main__':
    main(sys.argv[1:])
