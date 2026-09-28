# MultiPool modernization — shared contract (all repos)

Flow: Multi-Pool-Installer/bootstrap.sh -> clones multipool_setup to ~/multipool/install and runs start.sh
-> menu -> bootstrap_single.sh / bootstrap_multi.sh clone multipool_yiimp_single to ~/multipool/yiimp_single
or multipool_yiimp_multi to ~/multipool/yiimp_multi and `source start.sh`.

## Target OS
Ubuntu 22.04 (jammy), 24.04 (noble), 26.04 (resolute) LTS, x86_64. Ubuntu 16.04/18.04/20.04 are NOT supported
any more — delete all xenial/bionic/16.04/18.04 branches. Packages must exist on all three releases (or be
selected by ${DISTRO}).

## /etc/multipool.conf (written by multipool_setup, sourced by everyone)
Written with `printf '%s=%q\n'` (values are shell-quoted; always `source` it, never parse it with cut/grep).
Keys:
- STORAGE_USER, STORAGE_ROOT (default crypto-data, /home/crypto-data)
- PUBLIC_IP, PUBLIC_IPV6, PRIVATE_IP
- DISTRO        "22" | "24" | "26"   (major version of Ubuntu LTS)
- UBUNTU_CODENAME  jammy | noble | resolute
- PHP_VERSION   default "8.3" (owner chose 8.3) — the PHP version to install from ppa:ondrej/php. NEVER hardcode a php version
                anywhere: use php${PHP_VERSION}-fpm, /run/php/php${PHP_VERSION}-fpm.sock, /etc/php/${PHP_VERSION}/...
                For older conf files that lack it, fall back: PHP_VERSION="${PHP_VERSION:-$MULTIPOOL_DEFAULT_PHP_VERSION}"
                (MULTIPOOL_DEFAULT_PHP_VERSION is defined in /etc/functions.sh).

## /etc/functions.sh (from multipool_setup/functions.sh — the canonical copy is at
/home/user/multipool_setup/functions.sh; read it). Functions available:
- colors: COL_RESET RED GREEN YELLOW BLUE MAGENTA CYAN
- hide_output CMD...   runs CMD quietly; on failure prints output and EXITS with CMD's status (the old version
                       never detected failures — now it does, so make sure commands that are allowed to fail
                       are not wrapped in hide_output, or add `|| true` appropriately outside it). Works with
                       functions and when stdout is not a tty (no spinner then).
- apt_get_quiet ARGS / apt_install PKGS...   (noninteractive, --force-confold, NEEDRESTART_MODE=a)
- ufw_allow ARGS...   restart_service NAME  (systemctl)
- generate_password [len]   random alnum (default 32). Use this instead of ad-hoc /dev/urandom|tr|fold|head
                            or `openssl rand -base64 8` pipelines.
- write_conf_file [-m MODE] [-o OWNER[:GROUP]] FILE VAR1 VAR2 ...   writes VAR=%q-quoted lines via
                            `sudo install`, always (re)setting MODE (default 0600) and OWNER (default: the user
                            running the installer, `id -un`, so their screens/cron can still source it). Use for any
                            generated conf that is later `source`d (e.g. .yiimp.conf, .wireguard.conf) instead
                            of echo '...'"${var}"'...' | tee. Pick owner/mode so every process that sources the
                            file can still read it (e.g. -m 0640 -o user:www-data if php-fpm needs it).
- is_valid_username NAME
- message_box, input_box, input_menu (dialog wrappers, unchanged API)
- get_publicip_from_web_service 4|6 (https), get_default_privateip 4|6
- multipool_fetch_repo REPO_NAME_OR_URL DEST REF, MULTIPOOL_GITHUB (default https://github.com/mygiglifeinc-glitch)
- MULTIPOOL_DEFAULT_PHP_VERSION
The multi repo ships a copy in required_remote_files/functions.sh that is pushed to remote servers: it must be
byte-identical to multipool_setup/functions.sh (copy it over after any change there). Same for editconf.py.

## Stack decisions
- PHP: ppa:ondrej/php via `add-apt-repository -y ppa:ondrej/php` (install software-properties-common first),
  version ${PHP_VERSION}. Package list must not include things that no longer exist: php-gettext,
  php*-recode, php*-xmlrpc, mcrypt, php-auth-sasl is fine?, check. Use php${PHP_VERSION}-{fpm,opcache,common,gd,mysql,imap,cli,
  curl,intl,pspell,sqlite3,tidy,xsl,zip,mbstring,memcache,imagick} (php${PHP_VERSION}-memcache / -imagick come from
  the ondrej PPA; do not use unversioned php-memcache/php-imagick which pull the distro default PHP).
- MariaDB: Ubuntu's own mariadb-server / mariadb-client packages (no third-party repo, no apt-key).
  Secure it: no anonymous users, no remote root, no test DB, root via unix_socket; app users with
  generated passwords granted only on the yiimp DB (multi-server: remote users restricted to the specific
  host/WireGuard IP, never '%').
- Certbot: Ubuntu `certbot` + `python3-certbot-nginx` packages (ppa:certbot is dead). No apt-key anywhere
  (removed in 24.04+). If a third-party apt repo is truly needed, use /etc/apt/keyrings/*.gpg + signed-by=.
- nginx: Ubuntu's nginx package is fine (drop the nginx.org repo / apt-key upgrade dance) unless there's a
  strong reason; TLS 1.2+1.3 only, modern ciphers, server_tokens off, security headers, HSTS only on SSL
  sites, deny dotfiles.
- Time sync: systemd-timesyncd (default) — drop ntp/ntpdate. Drop haveged, drop `dd ... of=/dev/urandom`.
- Remove linux-generic-hwe-16.04, update-grub-legacy-ec2, and other obsolete bits.
- Firewall: ufw, default deny incoming, allow detected SSH port, 80/443 where relevant; other servers only
  allow traffic from the specific peer IPs.
- SSH hardening (where the scripts already touch sshd): drop-in file in /etc/ssh/sshd_config.d/ (not sed
  on sshd_config), PermitRootLogin no, and only disable PasswordAuthentication if the user actually has a
  key in authorized_keys (never lock them out). Validate with `sshd -t` before reloading. Service name is
  `ssh` on Ubuntu.
- fail2ban: enable sshd jail via /etc/fail2ban/jail.d/*.local.
- unattended-upgrades: enable security updates.
- Files containing secrets: 0600 (or 0640 group-readable where a service needs it), owned by the right user.
  Never world-readable. Never echo passwords into logs.
- Use `mktemp` instead of fixed /tmp names. Use `sudo tee` for writing root files (NOT `echo x > sudo file`
  or `>> sudo file` which creates a file literally named "sudo").
- Remote multi-server: use ssh with StrictHostKeyChecking=accept-new (not "no") and a known_hosts file,
  never disable host key checking entirely; avoid putting passwords on command lines (visible in ps).

## Shell style
- `#!/usr/bin/env bash`, quote all expansions, $(...) not backticks, [[ ]] ok, `local` in functions.
- Scripts are `source`d from start.sh, so do NOT add `set -euo pipefail` globally (and remove the
  set -eu / set +eu toggling that leaks into the caller) unless you're sure every sourced file is safe.
- Must pass `shellcheck -S warning` (install shellcheck locally with apt/pip if missing: `pip install
  shellcheck-py`). Add targeted `# shellcheck disable=` with a reason only where genuinely needed
  (e.g. SC1091 for sourcing /etc/functions.sh — prefer a `.shellcheckrc` at repo root with
  `disable=SC1090,SC1091` and `external-sources=true`).
- Keep existing user-facing behavior/menus/questions unless they're broken or insecure.
- Keep the original "Source https://mailinabox.email/..." / cryptopool.builders credit headers.
- Bump the version string shown in the menu title.
