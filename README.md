# BackhaulManager

Modern terminal manager for creating and operating [Backhaul](https://github.com/Musixal/Backhaul) tunnels with a clean interactive workflow.

![BackhaulManager showcase](assets/showcase.png)

## Highlights

- Interactive Iran/Kharej role selection with auto-detection
- One-command Backhaul binary install/update flow
- Guided tunnel creation for `tcp`, `tcpmux`, `wsmux`, and `wssmux`
- Preset and advanced tuning modes for production-style configs
- Systemd service generation, start/stop/restart, live logs, and deletion
- Config backup/restore and firewall helper for UFW or iptables
- WSSMUX TLS certificate generation with OpenSSL

## Requirements

- Linux server with `systemd`
- Root access
- `bash`, `curl` or `wget`, `tar`
- Optional: `ufw`, `iptables`, `openssl`

## Quick Start

```bash
chmod +x backhaul-manager.sh
sudo ./backhaul-manager.sh
```

Use **Install / Update Binary** first if Backhaul is not installed yet, then create a tunnel from the main menu.

## Typical Workflow

1. Run the script on the Iran server and choose `IRAN`.
2. Create a tunnel and copy the generated transport, port, and token.
3. Run the script on the Kharej server and choose `KHAREJ`.
4. Create the matching tunnel using the Iran server address and the same token.
5. Use **Manage Tunnels** to inspect status, follow logs, restart, edit, or delete services.

## Notes

- Generated configs are stored in `/etc/backhaul`.
- Services are created as `backhaul-<role>-<transport>-<port>.service`.
- Existing configs are backed up before overwrite/edit/delete operations.
- For WSSMUX, the script can generate a self-signed TLS certificate automatically.

## License

No license has been added yet.
