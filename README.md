# cablecheck

> Bulk CAT cable tester for Windows — no hardware required.

Plug both ends of a patch cable into the same laptop and cablecheck tells you if it passes in under 10 seconds. Built for testing large cable runs fast.

---

## Download

**[⬇ Download the latest installer](https://github.com/Bryson-he/cablecheck/releases/latest)**

`cablecheck_setup.exe` — installs everything, no technical knowledge needed.

---

## What it tests

| | |
|---|---|
| Dead cable / open circuit | ✓ |
| Packet loss from bad crimp | ✓ |
| Link below Gigabit (pairs 4,5,7,8) | ✓ |
| NIC error counters (split pair) | ✓ |
| Marginal cable / high latency | ✓ |

Results are automatically saved to a CSV log for record keeping.

---

## How to use it

1. Plug one end of the cable into the laptop's built-in ethernet port
2. Plug the other end into a USB-to-ethernet adapter
3. Launch **cablecheck** from the desktop shortcut
4. Select your adapters and hit **Run Test**

Enable **Auto-test** to go hands-free — cablecheck detects when you swap cables and starts the next test automatically.

---

## Requirements

- Windows 10 or 11
- Built-in ethernet port + USB-to-ethernet adapter
- Administrator rights (prompted automatically)
- [Npcap](https://npcap.com/) — installed automatically by the setup wizard

---

## License

MIT
