# Packaging

Installs Shield for the current user without sudo:

```sh
bash packaging/install.sh
```

It builds the release binary and installs:

- `~/.local/bin/shield` — the executable
- `~/.local/share/applications/shield.desktop` — the app-menu launcher
- `~/.config/autostart/shield.desktop` — starts at login, hidden in the tray
- `~/Desktop/shield.desktop` — a desktop icon, when `~/Desktop` exists
  (right-click → *Allow Launching* if Cinnamon marks it untrusted)

The icon uses the system theme name `security-high`; no image file is shipped.

To remove:

```sh
rm -f ~/.local/bin/shield \
      ~/.local/share/applications/shield.desktop \
      ~/.config/autostart/shield.desktop \
      ~/Desktop/shield.desktop
```
