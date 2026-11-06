"""What common autostart entries are, in plain words.

Persist lists every unit, timer, autostart file and cron job; most are part of a normal
desktop. This table says what the well-known ones do, so a list of 200 files reads like a
list of 200 things you recognise. It goes by name only, so a name is never trusted by
itself: Persist still checks what each entry starts, and an entry that borrows a system
service's name from your home folder is flagged (see `borrowed`).

scope: where the name normally lives. "system" = /etc or /usr only, "user" = a per-user
unit or autostart file, "any" = both are normal.
"""

import os
import re

# name: (what it does, scope)
KNOWN = {
    # --- systemd: networking
    "NetworkManager.service": ("Connects you to Wi-Fi, Ethernet and VPNs.", "system"),
    "NetworkManager-dispatcher.service": ("Runs NetworkManager's scripts when a connection goes up or down.", "system"),
    "NetworkManager-wait-online.service": ("Holds back boot steps that need the network until it is up.", "system"),
    "systemd-networkd.service": ("systemd's own network setup (common on servers).", "system"),
    "systemd-resolved.service": ("Looks up website names (DNS) for programs.", "system"),
    "systemd-timesyncd.service": ("Keeps the clock right using internet time servers.", "system"),
    "chronyd.service": ("Keeps the clock right using internet time servers (chrony).", "system"),
    "ntpd.service": ("Keeps the clock right using internet time servers (ntp).", "system"),
    "wpa_supplicant.service": ("Handles Wi-Fi security (WPA) for the network manager.", "system"),
    "iwd.service": ("Intel's Wi-Fi manager.", "system"),
    "dhcpcd.service": ("Gets an IP address from your router.", "system"),
    "ModemManager.service": ("Talks to mobile-broadband modems (4G/5G sticks, built-in modems).", "system"),
    "avahi-daemon.service": ("Finds printers and devices on your home network (mDNS/Bonjour).", "system"),
    "avahi-daemon.socket": ("Starts avahi-daemon when something asks for it.", "system"),
    "firewalld.service": ("The firewall (common on Fedora and openSUSE).", "system"),
    "ufw.service": ("The firewall (common on Ubuntu and Arch).", "system"),
    "nftables.service": ("Loads firewall rules at boot.", "system"),
    "tailscaled.service": ("Tailscale's VPN service.", "system"),
    "mullvad-daemon.service": ("Mullvad VPN's service.", "system"),
    "nordvpnd.service": ("NordVPN's service.", "system"),
    "sshd.service": ("Lets other computers log in to this one over SSH. Only needed if you use that.", "system"),
    "ssh.service": ("Lets other computers log in to this one over SSH. Only needed if you use that.", "system"),
    "sshd.socket": ("Starts the SSH server when someone connects.", "system"),
    # --- systemd: hardware, power, desktop plumbing
    "bluetooth.service": ("Bluetooth.", "system"),
    "cups.service": ("Printing.", "system"),
    "cups.socket": ("Starts printing when a program prints.", "system"),
    "cups.path": ("Starts printing when a print job appears.", "system"),
    "upower.service": ("Reports battery and power state to the desktop.", "system"),
    "power-profiles-daemon.service": ("Switches between power-saver, balanced and performance modes.", "system"),
    "tuned.service": ("Tunes power and performance settings (Fedora).", "system"),
    "tlp.service": ("Laptop battery saving.", "system"),
    "thermald.service": ("Keeps Intel CPUs from overheating.", "system"),
    "accounts-daemon.service": ("Gives the desktop the list of user accounts and their pictures.", "system"),
    "polkit.service": ("Decides which programs may ask for admin rights (the password dialog).", "system"),
    "rtkit-daemon.service": ("Lets audio get real-time priority so sound doesn't stutter.", "system"),
    "udisks2.service": ("Mounts USB drives and disks for the desktop.", "system"),
    "colord.service": ("Screen and printer colour profiles.", "system"),
    "geoclue.service": ("Tells apps your approximate location when you allow it.", "system"),
    "switcheroo-control.service": ("Picks the graphics card on laptops with two.", "system"),
    "fwupd.service": ("Updates device firmware when you ask it to.", "system"),
    "fwupd-refresh.timer": ("Checks now and then for new device firmware.", "system"),
    "nvidia-persistenced.service": ("Keeps the NVIDIA driver loaded between uses.", "system"),
    "nvidia-powerd.service": ("NVIDIA laptop power management.", "system"),
    "nvidia-suspend.service": ("Saves NVIDIA graphics memory when the PC sleeps.", "system"),
    "nvidia-resume.service": ("Restores NVIDIA graphics memory after sleep.", "system"),
    "nvidia-hibernate.service": ("Saves NVIDIA graphics memory when the PC hibernates.", "system"),
    "smartd.service": ("Watches disk health (SMART).", "system"),
    "irqbalance.service": ("Spreads hardware interrupts across CPU cores.", "system"),
    "earlyoom.service": ("Ends a runaway program before the PC freezes for lack of memory.", "system"),
    "systemd-oomd.service": ("Ends a runaway program before the PC freezes for lack of memory.", "system"),
    "lvm2-monitor.service": ("Watches LVM disk volumes.", "system"),
    "zram-generator.service": ("Compressed swap in memory.", "system"),
    "gdm.service": ("GNOME's login screen.", "system"),
    "sddm.service": ("KDE's login screen.", "system"),
    "lightdm.service": ("A login screen (LightDM).", "system"),
    "display-manager.service": ("The login screen (a link to gdm, sddm or lightdm).", "system"),
    "getty@.service": ("A text login on a virtual console (Ctrl+Alt+F2 and so on).", "system"),
    "systemd-journald.service": ("Collects system logs.", "system"),
    "rsyslog.service": ("Writes system logs to /var/log.", "system"),
    "auditd.service": ("The kernel audit log (security events).", "system"),
    "apparmor.service": ("Loads AppArmor security profiles.", "system"),
    "sssd.service": ("Network logins (company directories, LDAP, Active Directory).", "system"),
    "cronie.service": ("Runs scheduled cron jobs.", "system"),
    "crond.service": ("Runs scheduled cron jobs.", "system"),
    "cron.service": ("Runs scheduled cron jobs.", "system"),
    "atd.service": ("Runs one-off jobs scheduled with `at`.", "system"),
    "anacron.service": ("Runs daily and weekly jobs the PC missed while it was off.", "system"),
    # --- systemd: software, containers, virtual machines
    "docker.service": ("Docker containers.", "system"),
    "docker.socket": ("Starts Docker when a program talks to it.", "system"),
    "containerd.service": ("Runs containers for Docker and Kubernetes.", "system"),
    "podman.socket": ("Starts Podman's API when a program talks to it.", "any"),
    "libvirtd.service": ("Virtual machines (virt-manager, GNOME Boxes).", "system"),
    "vboxdrv.service": ("Loads VirtualBox's kernel drivers.", "system"),
    "snapd.service": ("Snap packages.", "system"),
    "snapd.socket": ("Starts snapd when a program talks to it.", "system"),
    "flatpak-system-helper.service": ("Installs Flatpak apps for all users.", "system"),
    "packagekit.service": ("Lets software centres install updates.", "system"),
    "ollama.service": ("Runs local AI models (Ollama).", "system"),
    # --- timers: housekeeping
    "fstrim.timer": ("Tells SSDs which blocks are free, once a week.", "system"),
    "man-db.timer": ("Rebuilds the manual-page index.", "system"),
    "logrotate.timer": ("Compresses and removes old logs.", "system"),
    "shadow.timer": ("Checks the user and password files for errors, daily.", "system"),
    "plocate-updatedb.timer": ("Rebuilds the file-name index for `locate`.", "system"),
    "updatedb.timer": ("Rebuilds the file-name index for `locate`.", "system"),
    "mlocate-updatedb.timer": ("Rebuilds the file-name index for `locate`.", "system"),
    "paccache.timer": ("Deletes old package downloads (Arch).", "system"),
    "reflector.timer": ("Picks fast Arch download mirrors.", "system"),
    "archlinux-keyring-wkd-sync.timer": ("Refreshes Arch packagers' signing keys.", "system"),
    "pamac-cleancache.timer": ("Deletes old package downloads (Manjaro).", "system"),
    "pamac-mirrorlist.timer": ("Picks fast Manjaro download mirrors.", "system"),
    "systemd-tmpfiles-clean.timer": ("Cleans up old temporary files, daily.", "system"),
    "apt-daily.timer": ("Downloads package lists for updates (Debian/Ubuntu).", "system"),
    "apt-daily-upgrade.timer": ("Installs automatic updates (Debian/Ubuntu).", "system"),
    "unattended-upgrades.service": ("Installs security updates automatically (Debian/Ubuntu).", "system"),
    "dnf-makecache.timer": ("Refreshes package lists for updates (Fedora).", "system"),
    "dnf-automatic.timer": ("Installs automatic updates (Fedora).", "system"),
    "snapper-timeline.timer": ("Takes hourly Btrfs snapshots (openSUSE, some Arch setups).", "system"),
    "snapper-cleanup.timer": ("Deletes old Btrfs snapshots.", "system"),
    "btrfs-scrub@.timer": ("Checks a Btrfs disk for errors, monthly.", "system"),
    "grub-btrfsd.service": ("Adds Btrfs snapshots to the boot menu.", "system"),
    "e2scrub_all.timer": ("Checks ext4 disks for errors.", "system"),
    "motd-news.timer": ("Fetches Ubuntu's login news.", "system"),
    # --- per-user units
    "pipewire.service": ("Sound and screen sharing.", "user"),
    "pipewire.socket": ("Starts PipeWire when a program plays sound.", "user"),
    "pipewire-pulse.service": ("Lets PulseAudio programs play through PipeWire.", "user"),
    "pipewire-pulse.socket": ("Starts pipewire-pulse when a program plays sound.", "user"),
    "wireplumber.service": ("Routes sound between apps and devices for PipeWire.", "user"),
    "pulseaudio.service": ("Sound (PulseAudio).", "user"),
    "pulseaudio.socket": ("Starts PulseAudio when a program plays sound.", "user"),
    "xdg-desktop-portal.service": ("Lets sandboxed apps open files and share the screen when you allow it.", "user"),
    "xdg-desktop-portal-gtk.service": ("GNOME/GTK dialogs for the desktop portal.", "user"),
    "xdg-desktop-portal-kde.service": ("KDE dialogs for the desktop portal.", "user"),
    "xdg-desktop-portal-gnome.service": ("GNOME dialogs for the desktop portal.", "user"),
    "xdg-user-dirs-update.service": ("Creates Documents, Downloads, Music and the other home folders.", "user"),
    "gnome-keyring-daemon.service": ("Keeps your saved passwords (the GNOME keyring).", "user"),
    "gnome-keyring-daemon.socket": ("Starts the keyring when an app needs a password.", "user"),
    "gvfs-daemon.service": ("Lets the file manager open network shares, phones and trash.", "user"),
    "gvfs-udisks2-volume-monitor.service": ("Shows USB drives in the file manager.", "user"),
    "tracker-miner-fs-3.service": ("Indexes your files for desktop search (GNOME).", "user"),
    "localsearch-3.service": ("Indexes your files for desktop search (GNOME).", "user"),
    "ssh-agent.service": ("Remembers your unlocked SSH keys for this session.", "user"),
    "gpg-agent.socket": ("Remembers your unlocked GnuPG keys for this session.", "user"),
    "gpg-agent.service": ("Remembers your unlocked GnuPG keys for this session.", "user"),
    "dbus.service": ("The message bus programs use to talk to each other.", "any"),
    "dbus.socket": ("Starts the message bus.", "any"),
    "dbus-broker.service": ("The message bus programs use to talk to each other.", "any"),
    "obex.service": ("Bluetooth file transfer.", "user"),
    "mpris-proxy.service": ("Lets Bluetooth headphones' buttons control the music player.", "user"),
    "syncthing.service": ("Syncthing: keeps folders in sync between your devices.", "any"),
    "syncthing@.service": ("Syncthing for one user.", "system"),
    "kdeconnect.service": ("KDE Connect: links your phone.", "user"),
    "plasma-kwin_wayland.service": ("KDE's window manager.", "user"),
    "plasma-plasmashell.service": ("KDE's desktop and panel.", "user"),
    "org.gnome.Shell@wayland.service": ("GNOME's desktop.", "user"),
    "podman.service": ("Podman's API.", "any"),
    "flatpak-session-helper.service": ("Helps Flatpak apps run in your session.", "user"),
    "at-spi-dbus-bus.service": ("Accessibility: lets screen readers read apps.", "user"),
    "emacs.service": ("Emacs running in the background.", "user"),
    # --- XDG autostart (.desktop files in /etc/xdg/autostart or ~/.config/autostart)
    "gnome-keyring-pkcs11.desktop": ("Starts the GNOME keyring's smart-card part at login.", "system"),
    "gnome-keyring-secrets.desktop": ("Starts the GNOME keyring (saved passwords) at login.", "system"),
    "gnome-keyring-ssh.desktop": ("Starts the GNOME keyring's SSH-key part at login.", "system"),
    "xdg-user-dirs.desktop": ("Creates Documents, Downloads and the other home folders at login.", "system"),
    "xdg-user-dirs-kde.desktop": ("Creates the standard home folders at login (KDE).", "system"),
    "user-dirs-update-gtk.desktop": ("Renames the home folders when you change language.", "system"),
    "at-spi-dbus-bus.desktop": ("Accessibility support at login.", "system"),
    "nm-applet.desktop": ("The network icon in the panel.", "system"),
    "blueman.desktop": ("The Bluetooth icon in the panel.", "system"),
    "pulseaudio.desktop": ("Starts sound at login (PulseAudio).", "system"),
    "print-applet.desktop": ("The printer icon in the panel.", "system"),
    "polkit-gnome-authentication-agent-1.desktop": ("Shows the admin-password dialog.", "system"),
    "polkit-kde-authentication-agent-1.desktop": ("Shows the admin-password dialog (KDE).", "system"),
    "org.kde.plasma-polkit-agent.desktop": ("Shows the admin-password dialog (KDE).", "system"),
    "baloo_file.desktop": ("Indexes your files for desktop search (KDE).", "system"),
    "org.kde.kdeconnect.daemon.desktop": ("KDE Connect: links your phone.", "system"),
    "org.kde.discover.notifier.desktop": ("Tells you when updates are available (KDE).", "system"),
    "org.gnome.Software.desktop": ("Checks for updates in the background (GNOME Software).", "system"),
    "gnome-initial-setup-first-login.desktop": ("The welcome tour on first login.", "system"),
    "geoclue-demo-agent.desktop": ("Asks you before apps get your location.", "system"),
    "ibus-daemon.desktop": ("Typing in other languages (IBus input methods).", "system"),
    "org.fcitx.Fcitx5.desktop": ("Typing in other languages (Fcitx input methods).", "system"),
    "im-launch.desktop": ("Starts the input-method framework (typing other languages).", "system"),
    "spice-vdagent.desktop": ("Copy-paste and screen resizing inside a virtual machine.", "system"),
    "vmware-user.desktop": ("VMware guest tools.", "system"),
    "xapp-sn-watcher.desktop": ("Tray icons for the Cinnamon/MATE/Xfce panel.", "system"),
    "light-locker.desktop": ("Locks the screen (LightDM).", "system"),
    "xfce4-power-manager.desktop": ("Power settings for Xfce.", "system"),
    "xfce4-notifyd.desktop": ("Notifications for Xfce.", "system"),
    "picom.desktop": ("Window shadows and transparency (picom).", "any"),
    "redshift-gtk.desktop": ("Warmer screen colours in the evening.", "any"),
    "org.flameshot.Flameshot.desktop": ("The Flameshot screenshot tool.", "any"),
    "steam.desktop": ("Steam, if you chose to start it at login.", "any"),
    "discord.desktop": ("Discord, if you chose to start it at login.", "user"),
    "com.discordapp.Discord.desktop": ("Discord (Flatpak), if you chose to start it at login.", "user"),
    "dropbox.desktop": ("Dropbox file sync.", "any"),
    "com.nextcloud.desktopclient.nextcloud.desktop": ("Nextcloud file sync.", "any"),
    "Nextcloud.desktop": ("Nextcloud file sync.", "any"),
    "org.keepassxc.KeePassXC.desktop": ("KeePassXC, your password manager.", "any"),
    "signal-desktop.desktop": ("Signal, if you chose to start it at login.", "user"),
    "solaar.desktop": ("Logitech wireless device manager.", "any"),
    "gnome-software-service.desktop": ("Checks for updates in the background (GNOME Software).", "system"),
    "tracker-miner-fs-3.desktop": ("Indexes your files for desktop search (GNOME).", "system"),
    "kaccess.desktop": ("Accessibility features for KDE.", "system"),
    "pam_kwallet_init.desktop": ("Unlocks KWallet (saved passwords) with your login (KDE).", "system"),
    "powerdevil.desktop": ("Power settings for KDE.", "system"),
    "xembedsniproxy.desktop": ("Tray icons for older apps (KDE).", "system"),
    "gmenudbusmenuproxy.desktop": ("App menus in the KDE panel.", "system"),
    # --- cron files
    "0hourly": ("Runs the hourly cron folder (cron.hourly).", "system"),
    "0anacron": ("Runs jobs the PC missed while it was off (anacron).", "system"),
    "e2scrub_all": ("Checks ext4 disks for errors.", "system"),
    "popularity-contest": ("Debian's opt-in package survey.", "system"),
    "sysstat": ("Collects performance statistics for `sar`.", "system"),
    "logrotate": ("Compresses and removes old logs.", "system"),
    "man-db": ("Rebuilds the manual-page index.", "system"),
    "mlocate": ("Rebuilds the file-name index for `locate`.", "system"),
    "plocate": ("Rebuilds the file-name index for `locate`.", "system"),
    "apt-compat": ("Runs Debian's daily package jobs.", "system"),
    "dpkg": ("Backs up Debian's package database daily.", "system"),
    "raid-check": ("Checks software RAID disks (Fedora).", "system"),
}
# Families of names: KDE, GNOME and systemd ship many entries with a shared prefix.
PREFIXES = [
    ("org.gnome.SettingsDaemon.", "Part of GNOME's settings service (keyboard, power, sound and similar).", "system"),
    ("org.gnome.Evolution-alarm-notify", "Calendar reminders (GNOME Evolution).", "system"),
    ("org.kde.", "Part of KDE Plasma.", "any"),
    ("systemd-", "Part of systemd, the system's service manager.", "system"),
    ("user@", "Your user session's service manager.", "system"),
    ("xfce4-", "Part of the Xfce desktop.", "system"),
    ("mate-", "Part of the MATE desktop.", "system"),
    ("cinnamon-", "Part of the Cinnamon desktop.", "system"),
]
USER_UNIT_DIRS = ("/.config/systemd/user/", "/.local/share/systemd/user/")


def _key(path):
    name = os.path.basename(path)
    return re.sub(r"@[^.]+\.", "@.", name) if "@" in name else name   # getty@tty1.service -> getty@.service


def lookup(path):
    """{"name", "what", "scope"} for a well-known entry, or None."""
    k = _key(path)
    if k in KNOWN:
        what, scope = KNOWN[k]
        return {"name": k, "what": what, "scope": scope}
    for prefix, what, scope in PREFIXES:
        if k.startswith(prefix):
            return {"name": k, "what": what, "scope": scope}
    return None


def borrowed(e):
    """The known system entry this file borrows a name from, if it sits in your home folder.

    A user unit with a system service's name is how persistence hides in plain sight
    ("NetworkManager.service" in ~/.config/systemd/user would never be the real one: system
    services don't run in your user session). Drop-in folders (name.service.d/) and copies
    of autostart .desktop files (how desktops let you switch login items off) are ordinary
    and not counted."""
    path = e.get("path") or ""
    if e.get("scope") != "user" or not any(p in path for p in USER_UNIT_DIRS) or ".d/" in path:
        return None
    k = _key(path)
    hit = KNOWN.get(k)
    if hit and hit[1] == "system":
        return {"name": k, "what": hit[0]}
    return None
