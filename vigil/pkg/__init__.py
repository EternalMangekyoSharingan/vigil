"""Vigil Pkg: is this AUR package safe to build and install?

Static review of a PKGBUILD folder (and its .install script) before makepkg, plus an
audit of foreign packages already installed. It reads text only: it never runs
makepkg, never sources the PKGBUILD and never downloads sources. Fetching AUR
metadata is an explicit, opt-in network call."""
