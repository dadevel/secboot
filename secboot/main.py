#!/usr/bin/env python3
from __future__ import annotations
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter, BooleanOptionalAction
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from typing import Any, Callable, Generator
import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import uuid

DEFAULTS = {
    # path to the EFI partition
    'efi-partition': '/dev/disk/by-label/efi',
    # path to the mountpoint of the EFI partition
    'efi-mountpoint': '/boot/efi',
    # path to a subdirectory on the EFI partition where the EFI bundles will be stored
    'efi-subdir': '/boot/efi/EFI/Linux',
    # LUKS partition containing the root filesystem
    'luks-partition': '/dev/disk/by-label/root',
    # kernel parameters, the stuff you would normally put into the GRUB_CMDLINE_LINUX_DEFAULT variable in /etc/default/grub
    'kernel-params': '',
    # which compression algorithm to use, zstd supported since linux kernel 5.9
    'initramfs-compression': 'lz4',
    # sign dkms modules
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
    # tpm setup
    'tpm-device': 'auto',
    'tpm-pcrs': '7',
}
LUKS_MAPPER_NAME = 'vault'


def main() -> None:
    entrypoint = ArgumentParser(formatter_class=lambda prog: ArgumentDefaultsHelpFormatter(prog, max_help_position=round(shutil.get_terminal_size().columns / 2)))

    entrypoint.add_argument('-c', '--config', type=lambda x: Path(x), default=Path('/etc/secboot/config.json'))
    entrypoint.add_argument('--debug', action=BooleanOptionalAction, help='verbose logging')
    dpkg_params = os.environ.get('DEB_MAINT_PARAMS', '').lower()
    if dpkg_params:
        entrypoint.add_argument('name', nargs=1, help='package name')
        entrypoint.add_argument('path', nargs='?', help='image path (not used)')
    else:
        subparsers = entrypoint.add_subparsers(dest='action', required=True)

        parser = subparsers.add_parser('enroll-certificates', help='setup Secure Boot')

        parser = subparsers.add_parser('enroll-tpm', help='setup TPM')

        parser = subparsers.add_parser('update-bundle', help='build UKI')
        parser.add_argument('name', nargs=1, help='package name')
        parser.add_argument('version', nargs=1, help='kernel version')

        parser = subparsers.add_parser('remove-bundle', help='delete UKI')
        parser.add_argument('name', nargs=1, help='package name')
        parser.add_argument('version', nargs=1, help='kernel version')

        parser = subparsers.add_parser('pacman-update', help='pacman hook receiver, do not use')

        parser = subparsers.add_parser('pacman-remove', help='pacman hook receiver, do not use')

    opts = entrypoint.parse_args()
    logging.basicConfig(level=logging.DEBUG if opts.debug else logging.INFO, stream=sys.stderr, format='%(levelname)s %(message)s')

    if dpkg_params:
        config = Configuration.read(opts.config, opts.debug)
        logging.debug(f'configuration: {config}')
        if dpkg_params.startswith('configure '):
            dpkg_postinst(opts.name[0], config)
        elif dpkg_params.startswith('remove '):
            dpkg_postrm(opts.name[0], config)
        else:
            logging.warning('called from dpkg: wrong phase')
    else:
        actions = {
            'enroll-certificates': lambda _o, c: enroll_certificates(c),
            'enroll-tpm': lambda _o, c: enroll_tpm(c),
            'update-bundle': lambda o, c: update_bundle(o.name[0], o.version[0], c),
            'remove-bundle': lambda o, c: remove_bundle(o.name[0], o.version[0], c),
            'pacman-update': lambda _o, c: pacman_update(c),
            'pacman-remove': lambda _o, c: pacman_remove(c),
        }
        try:
            action = actions[opts.action]
            config = Configuration.read(opts.config, opts.debug)
            action(opts, config)
        except UsageError as e:
            logging.error(f'error: {e}')
            logging.exception(e)
            sys.exit(1)
        except Exception as e:
            logging.error(f'exception: {e}')
            logging.exception(e)
            sys.exit(1)


class UsageError(Exception):
    pass


@dataclass
class Configuration:
    certificate_storage: Path
    machine_id: str
    efi_partition: Path
    efi_mountpoint: Path
    efi_subdir: Path
    efi_stub: Path
    initramfs_compression: str
    dracut_params: list
    kernel_params: str
    kernel_priority: list
    dkms_files: list
    debug: bool
    luks_partition: str
    tpm_device: str
    tpm_pcrs: str

    def __post_init__(self) -> None:
        self.certificate_storage = Path(self.certificate_storage)
        self.machine_id = Path(self.machine_id).read_text().strip()
        self.efi_partition = Path(self.efi_partition)
        self.efi_mountpoint = Path(self.efi_mountpoint)
        self.efi_subdir = Path(self.efi_subdir)
        self.efi_stub = Path(self.efi_stub)
        self.initramfs_compression = str(self.initramfs_compression)
        self.dracut_params = [str(x) for x in self.dracut_params]
        self.kernel_params = str(self.kernel_params)
        self.kernel_priority = [str(x) for x in self.kernel_priority]
        self.dkms_files = [str(x) for x in self.dkms_files]

    @classmethod
    def read(cls, path: Path, debug: bool) -> Configuration:
        try:
            with open(path) as file:
                options = json.load(file)
            options = dict(DEFAULTS.copy(), **options)
            options = {key.replace('-', '_'): value for key, value in options.items()}
            return cls(**options, debug=debug)
        except Exception as e:
            raise UsageError(f'invalid configuration: {e}') from e

    @property
    def dkms_signing_enabled(self) -> bool:
        return bool(self.dkms_files)

    def find_dkms_files(self, version: str) -> Generator[Path, None, None]:
        for pattern in self.dkms_files:
            for path in Path('/').glob(pattern.format(version=version).lstrip('/')):
                if path.is_file():
                    yield path

    @cached_property
    def luks_partition_uuid(self) -> str:
        luks_uuid = run('cryptsetup', 'luksUUID', self.luks_partition, capture=True).rstrip()
        assert luks_uuid
        return luks_uuid


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
        return self.config.efi_subdir/f'{self.label}.efi'

    @property
    def loader(self) -> str:
        return '\\' + self.path.relative_to(self.config.efi_mountpoint).as_posix().replace('/', '\\')


@dataclass
class BundleManager:
    config: Configuration

    def build(self, bundle: Bundle) -> None:
        kernel_params = f'rd.luks.name={self.config.luks_partition_uuid}={LUKS_MAPPER_NAME} {self.config.kernel_params}'
        logging.info(f'building UKI {bundle.path} with kernel cmdline {kernel_params!r}')
        logging.debug(f'using following kernel cmdline: {kernel_params}')
        self.config.efi_subdir.mkdir(parents=True, exist_ok=True)
        run(
            'dracut',
            # ignore config files
            '--conf', '/dev/null',
            '--confdir', '/var/empty',
            '--force',
            '--stdlog', '7' if self.config.debug else '3',
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
            '--kernel-cmdline', kernel_params,
            *self.config.dracut_params,
            '--', bundle.path, bundle.version
        )

    def sign(self, bundle: Bundle) -> None:
        sbsign(self.config, bundle.path)

    def sign_modules(self, bundle: Bundle) -> None:
        logging.info('signing dynamic kernel modules')
        signer = self._find_module_signing_tool(bundle.version)
        for path in self.config.find_dkms_files(bundle.version):
            run(signer, 'sha256', self.config.certificate_storage/'db.key.pem', self.config.certificate_storage/'db.crt.der', path)

    @staticmethod
    def _find_module_signing_tool(kver: str) -> str|Path:
        try:
            run('kmodsign', '--version', capture=True)
            return 'kmodsign'
        except Exception:
            pass

        path = Path(f'/usr/lib/modules/{kver}/build/scripts/sign-file')
        if path.exists() and path.is_file():
            return path

        raise UsageError('can not sign kernel modules, neither kmodsign nor sign-file could be found')

    def delete(self, bundle: Bundle) -> None:
        logging.info(f'updating UKI {bundle.path}')
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
        return self.config.efi_subdir/f'{self.label}.efi'


@dataclass
class BootManager:
    config: Configuration

    def __post_init__(self) -> None:
        self._efibootmgr()

    def register(self, bundle: Bundle) -> None:
        if bundle.label not in {entry.label for entry in self.entries}:
            logging.info(f'creating boot entry {bundle.label}')
            self._efibootmgr('--create-only', '--label', bundle.label, '--loader', bundle.loader)

    def clean_entries(self) -> None:
        seen = set()
        for entry in self.entries:
            if not entry.path.is_file():
                logging.info(f'deleting invalid boot entry {entry.label}')
                self._efibootmgr('--delete-bootnum', '--bootnum', entry.number)
            if (entry.label, entry.path) in seen:
                logging.info(f'deleting duplicated boot entry {entry.label}')
                self._efibootmgr('--delete-bootnum', '--bootnum', entry.number)
            seen.add((entry.label, entry.path))

    def rewrite_order(self) -> None:
        new_order = [entry.number for entry in self._sort_entries_by_priority()]
        new_order += [num for num in self.order if num not in new_order and num in self.misc_nums]
        if new_order != self.order:
            logging.info('updating boot order')
            self._efibootmgr('--bootorder', ','.join(new_order))

    def _efibootmgr(self, *args: str|Path) -> None:
        output = run('efibootmgr', '--disk', self.config.efi_partition, *args, capture=True)
        self.order, self.entries, self.misc_nums = self._parse_output(output)

    @staticmethod
    def _versionify(value: str) -> tuple:
        return tuple(int(x) if x.isnumeric() else x for x in re.split(r'\.|-', value))

    def _sort_entries_by_priority(self) -> list[BootEntry]:
        def comparator(entry):
            try:
                priority = self.config.kernel_priority.index(entry.name)
            except ValueError:
                priority = float('inf')
            return (-priority, self._versionify(entry.name))

        return list(reversed(sorted(self.entries, key=comparator)))

    def _parse_output(self, text: str) -> tuple[list[str], list[BootEntry], list[str]]:
        order_regex = re.compile(r'^BootOrder:\s+(\S+)')
        kernel_entry_regex = re.compile(r'^Boot(....)\*?\s+(.+?)-' + re.escape(self.config.machine_id))
        misc_entry_regex = re.compile(r'^Boot(....)\*?\s+\S+')
        order = list()
        kernel_entries = list()
        misc_nums = list()
        for line in text.splitlines():
            if line.startswith('BootCurrent:') or line.startswith('Timeout:'):
                continue
            match = order_regex.match(line)
            if match:
                order = match.group(1).split(',')
                continue
            match = kernel_entry_regex.match(line)
            if match:
                entry = BootEntry(match.group(1), match.group(2), self.config)
                kernel_entries.append(entry)
                continue
            match = misc_entry_regex.match(line)
            if match:
                misc_nums.append(match.group(1))
                continue
            logging.warning(f'cant handle boot entry: {line}')
        return order, kernel_entries, misc_nums


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
    boot_manager.clean_entries()
    boot_manager.rewrite_order()


def remove_bundle(name: str, version: str, config: Configuration) -> None:
    bundle_manager = BundleManager(config)
    boot_manager = BootManager(config)
    bundle = Bundle(name, version, config)

    bundle_manager.delete(bundle)
    boot_manager.clean_entries()
    boot_manager.rewrite_order()


def enroll_certificates(config: Configuration) -> None:
    try:
        check('openssl', 'version')
    except CommandError as e:
        raise UsageError('openssl not installed') from e

    try:
        check('cert-to-efi-sig-list', '--version')
        check('sign-efi-sig-list', '--version')
    except CommandError as e:
        raise UsageError('sbsigntools not installed') from e

    try:
        check('efi-updatevar', '--version')
        check('efi-readvar', '--version')
    except CommandError as e:
        raise UsageError('efitools not installed') from e

    config.certificate_storage.mkdir(exist_ok=True)

    guid_path = config.certificate_storage/'guid.txt'
    if guid_path.exists():
        guid = guid_path.read_text().strip()
        # assume that secure certificates and keys are present
    else:
        guid = str(uuid.uuid4())

        # generate certificates
        run('openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-new', '-x509', '-sha256', '-days', '3650', '-subj', '/CN=Platform Key/', '-out', config.certificate_storage/'pk.crt.pem', '-outform', 'pem', '-keyout', config.certificate_storage/'pk.key.pem', '-keyform', 'pem')
        run('openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-new', '-x509', '-sha256', '-days', '3650', '-subj', '/CN=Key Exchange Key/', '-out', config.certificate_storage/'kek.crt.pem', '-outform', 'pem', '-keyout', config.certificate_storage/'kek.key.pem', '-keyform', 'pem')
        run('openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-new', '-x509', '-sha256', '-days', '3650', '-subj', '/CN=Signature Database Key/', '-out', config.certificate_storage/'db.crt.pem', '-outform', 'pem', '-keyout', config.certificate_storage/'db.key.pem', '-keyform', 'pem')

        # convert certificates
        run('openssl', 'x509', '-in', config.certificate_storage/'pk.crt.pem', '-inform', 'pem', '-out', config.certificate_storage/'pk.crt.der', '-outform', 'der')
        run('openssl', 'x509', '-in', config.certificate_storage/'kek.crt.pem', '-inform', 'pem', '-out', config.certificate_storage/'kek.crt.der', '-outform', 'der')
        run('openssl', 'x509', '-in', config.certificate_storage/'db.crt.pem', '-inform', 'pem', '-out', config.certificate_storage/'db.crt.der', '-outform', 'der')

        # generate signature lists
        run('cert-to-efi-sig-list', '-g', guid, config.certificate_storage/'pk.crt.pem', config.certificate_storage/'pk.esl')
        run('cert-to-efi-sig-list', '-g', guid, config.certificate_storage/'kek.crt.pem', config.certificate_storage/'kek.esl')
        run('cert-to-efi-sig-list', '-g', guid, config.certificate_storage/'db.crt.pem', config.certificate_storage/'db.esl')

        # sign signature lists
        run('sign-efi-sig-list', '-g', guid, '-k', config.certificate_storage/'pk.key.pem', '-c', config.certificate_storage/'pk.crt.pem', 'PK', config.certificate_storage/'pk.esl', config.certificate_storage/'pk.auth')
        run('sign-efi-sig-list', '-g', guid, '-k', config.certificate_storage/'pk.key.pem', '-c', config.certificate_storage/'pk.crt.pem', 'PK', '/dev/null', config.certificate_storage/'pk-rm.auth')
        run('sign-efi-sig-list', '-g', guid, '-k', config.certificate_storage/'pk.key.pem', '-c', config.certificate_storage/'pk.crt.pem', 'KEK', config.certificate_storage/'kek.esl', config.certificate_storage/'kek.auth')
        run('sign-efi-sig-list', '-g', guid, '-k', config.certificate_storage/'kek.key.pem', '-c', config.certificate_storage/'kek.crt.pem', 'db', config.certificate_storage/'db.esl', config.certificate_storage/'db.auth')

        guid_path.write_text(guid)

    pk_enrolled = guid in run('efi-readvar', '-v', 'PK', capture=True)
    kek_enrolled = guid in run('efi-readvar', '-v', 'KEK', capture=True)
    db_enrolled = guid in run('efi-readvar', '-v', 'db', capture=True)
    if not pk_enrolled and not kek_enrolled and not db_enrolled:
        try:
            run('efi-updatevar', '-e', '-f', config.certificate_storage/'db.esl', 'db')
            run('efi-updatevar', '-e', '-f', config.certificate_storage/'kek.esl', 'KEK')
            run('efi-updatevar', '-f', config.certificate_storage/'pk.auth', 'PK')
        except CommandError as e:
            raise UsageError('automatic Secure Boot certificate enrollment failed, ensure that Secure Boot is in setup mode') from e
    elif pk_enrolled and kek_enrolled and db_enrolled:
        pass
    else:
        raise UsageError('partially enrolled Secure Boot certificates, please wipe Secure Boot certificates and try again')

    fwupd_binary = config.efi_mountpoint/'EFI/arch/fwupdx64.efi'
    if fwupd_binary.exists():
        sbsign(config, fwupd_binary)
    else:
        logging.warning('fwupd is missing')

    for kernel_name in config.kernel_priority:
        uki = config.efi_subdir/f'{kernel_name}-{config.machine_id}.efi'
        if not uki.is_file():
            logging.warning(f'{uki}: uki missing')
            continue
        if not sbverify(config, uki):
            logging.error(f'{uki}: uki not signed')


def enroll_tpm(config: Configuration) -> None:
    if not config.luks_partition:
        raise UsageError('luks-partition not specified in config')

    try:
        check('cryptsetup', '--version')
    except CommandError as e:
        raise UsageError('cryptsetup not installed') from e

    try:
        check('tpm2_pcrread')
    except CommandError as e:
        raise UsageError('tpm2-tools not installed') from e

    try:
        metadata = json.loads(run('cryptsetup', 'luksDump', '--dump-json-metadata', config.luks_partition, capture=True))
        tpm_enrolled = any(token['type'] == 'systemd-tpm2' and token['tpm2-pin'] for token in metadata['tokens'].values())
    except CommandError as e:
        raise UsageError(f'cloud not get LUKS metadata from {config.luks_partition}') from e

    if not tpm_enrolled:
        logging.info('protecting LUKS with TPM')
        run('systemd-cryptenroll', f'--tpm2-device={config.tpm_device}', f'--tpm2-pcrs={config.tpm_pcrs}', '--tpm2-with-pin=yes', config.luks_partition)

    crypttab_path = Path('/etc/crypttab')
    if crypttab_path.exists():
        with open(crypttab_path, 'r') as file:
            content = file.readlines()
    else:
        content = []
    indices = [index for index, line in enumerate(content) if f'UUID={config.luks_partition_uuid}' in line]
    entry = f'{LUKS_MAPPER_NAME} UUID={config.luks_partition_uuid} - tpm2-device={config.tpm_device},tpm2-pin=yes'
    if len(indices) == 0:
        logging.info('appending entry to crypttab')
        content.append(entry)
        with open(crypttab_path, 'w') as file:
            file.writelines(content)
    elif len(indices) == 1:
        index = indices[0]
        if content[index] != entry:
            logging.info('updating entry in crypttab')
            content[index] = entry
            with open(crypttab_path, 'w') as file:
                file.writelines(content)
    else:
        raise UsageError('found more then one matching entry in crypttab')


def sbverify(config: Configuration, path: Path) -> bool:
    return check('sbverify', '--cert', f'{config.certificate_storage}/db.crt.pem', path, stderr=subprocess.PIPE)


def sbsign(config: Configuration, path: Path) -> None:
    if not sbverify(config, path):
        logging.info(f'signing {path}')
        run('sbsign', '--key', config.certificate_storage/'db.key.pem', '--cert', config.certificate_storage/'db.crt.pem', '--output', path, path, stderr=subprocess.PIPE)


class CommandError(Exception):
    pass


def run(*args: str|Path, capture=False, **kwargs: Any) -> str:
    logging.debug(f'{" ".join(shlex.quote(str(x)) for x in args)}')
    try:
        process = subprocess.run(args, check=False, capture_output=capture, text=True, **kwargs)
    except Exception as e:
        raise CommandError(f'subprocess failed: {e}') from e
    if process.returncode != 0:
        if capture:
            raise CommandError(f'subprocess failed: {process.stderr.strip()}')
        raise CommandError(f'subprocess failed: exit code {process.returncode}')
    return process.stdout


def check(*args: str|Path, **kwargs: Any) -> bool:
    try:
        run(*args, capture=True, **kwargs)
        return True
    except CommandError:
        return False


if __name__ == '__main__':
    main()
