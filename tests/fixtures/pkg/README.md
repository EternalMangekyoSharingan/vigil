# PKGBUILD fixtures (SYNTHETIC)

Every PKGBUILD, .install and .SRCINFO here was written by hand for Vigil Pkg's tests.
They are **synthetic**: the malicious-looking ones only *look* malicious to a static
reader. Their URLs use documentation addresses (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24), `example.org`/`example.com`, or made-up paste IDs, and nothing here is
ever run: Vigil reads them as text, and the tests check that.

| Folder | What it exercises |
| --- | --- |
| benign | a tidy release PKGBUILD: checksummed https sources, writes only under $pkgdir |
| benign-vcs | a -git package: SKIP for git sources, local wheel install, local submodules |
| squat | known malicious name (librewolf-fix-bin), SKIP on a -bin download |
| sources | bare IP, pastebin, link shortener, file host, plain http, another site than url= |
| builder | curl into sh, network in build(), eval, base64 decode into sh, encoded blob, chmod +x then run, /dev/tcp |
| installer | a .install script: download, enable a service, system user, wheel group, cron, setuid, firewall off, /etc/sudoers |
| outside | writes outside $pkgdir, sudo, ~/.bashrc, systemctl --user |
| toplevel | commands outside functions; $(curl ...) at the top level |
| srcinfo | a .SRCINFO that names a different source than the PKGBUILD |
