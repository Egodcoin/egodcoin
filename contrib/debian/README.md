
Debian
====================
This directory contains files used to package egodcoind/egodcoin-qt
for Debian-based Linux systems. If you compile egodcoind/egodcoin-qt yourself, there are some useful files here.

## egodcoin: URI support ##


egodcoin-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install egodcoin-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your egodcoin-qt binary to `/usr/bin`
and the `../../share/pixmaps/egodcoin128.png` to `/usr/share/pixmaps`

egodcoin-qt.protocol (KDE)

