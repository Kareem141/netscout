# NetScout

**NetScout** is a command-line network scanner that helps you discover devices on your network, scan their open ports, identify running services, and even guess their operating system, all from your terminal.

## What Can NetScout Do?

- **Find Devices on Your Network**: Automatically discover all computers, phones, printers, and IoT devices connected to your local network.
- **Scan Open Ports**: Check which ports are open on any device (like checking which doors are unlocked).
- **Identify Services**: Find out what software is running on open ports (e.g., a web server on port 80, SSH on port 22).
- **Detect Operating Systems**: Guess whether a device is running Windows, Linux, macOS, or other OSes.
- **Find MAC Vendors**: Look up the manufacturer of any network device by its MAC address.
- **Export Results**: Save your scan results as JSON or CSV files for reports or further analysis.
- **Beautiful Output**: Results are displayed in clean, color-coded tables right in your terminal.

## Quick Start

```bash
# 1. Install NetScout
pip install netscout

# 2. Discover devices on your local network
netscout discover 192.168.1.0/24

# 3. Scan a device for open ports
netscout scan 192.168.1.1
```

> **Note**: Some features (like ARP discovery and stealth SYN scans) require administrator/root privileges. See the platform-specific instructions below.

---

## Installation & Setup by Platform

### Windows

#### Step 1: Install Python

1. Download Python from [python.org](https://www.python.org/downloads/)
2. Run the installer and **check the box** that says "Add Python to PATH"
3. Click "Install Now"
4. Verify installation by opening Command Prompt and running:
   ```cmd
   python --version
   ```
   You should see Python 3.10 or higher.

#### Step 2: Install Npcap (Required for Packet Capture)

NetScout needs Npcap to capture network packets on Windows:

1. Download Npcap from [npcap.com](https://npcap.com/#download)
2. Run the installer
3. During installation, **check the box** "Install Npcap in WinPcap API-compatible Mode" (this ensures compatibility)
4. Click "Install" and wait for it to finish
5. Restart your computer after installation

#### Step 3: Install NetScout

Open **Command Prompt** (or PowerShell) and run:

```cmd
pip install netscout
```

#### Step 4: Run as Administrator (for Full Features)

For host discovery and SYN scans, you need to run NetScout with administrator privileges:

1. Click Start, type "cmd" or "PowerShell"
2. Right-click on "Command Prompt" or "Windows PowerShell"
3. Select **"Run as administrator"**
4. Now you can use all NetScout features:

```cmd
netscout discover 192.168.1.0/24
netscout scan 192.168.1.1 --ports 1-1000
```

> **Tip**: If you don't want to run as administrator, you can still use connect scans (the default) and ICMP discovery:
> ```cmd
> netscout discover 10.0.0.0/24 --method icmp
> netscout scan 192.168.1.1
> ```

---

### Linux

#### Step 1: Install Python

On most Linux distributions, Python is already installed. Check with:

```bash
python3 --version
```

If Python is not installed or your version is below 3.10:

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install python3 python3-pip
```

**Fedora:**
```bash
sudo dnf install python3 python3-pip
```

**Arch Linux:**
```bash
sudo pacman -S python python-pip
```

#### Step 2: Install libpcap (Required for Packet Capture)

```bash
# Ubuntu/Debian
sudo apt install libpcap0.8

# Fedora
sudo dnf install libpcap

# Arch Linux
sudo pacman -S libpcap
```

#### Step 3: Install NetScout

```bash
pip3 install netscout
```

#### Step 4: Run with sudo (for Full Features)

ARP discovery and SYN scans require root privileges on Linux:

```bash
# Full ARP discovery (recommended for local networks)
sudo netscout discover 192.168.1.0/24

# SYN scan (faster and stealthier)
sudo netscout scan 192.168.1.1 --syn

# Without sudo (limited but still functional)
netscout discover 10.0.0.0/24 --method icmp
netscout scan 192.168.1.1
```

---

### macOS

#### Step 1: Install Python

macOS may come with an older Python version. Install the latest using Homebrew:

```bash
# Install Homebrew if you don't have it
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python
brew install python
```

Verify installation:
```bash
python3 --version
```

#### Step 2: Install libpcap

macOS includes libpcap by default, so no additional installation is needed.

#### Step 3: Install NetScout

```bash
pip3 install netscout
```

#### Step 4: Run with sudo (for Full Features)

```bash
# ARP discovery on your local network
sudo netscout discover 192.168.1.0/24

# SYN scan
sudo netscout scan 192.168.1.1 --syn

# Without sudo (ICMP discovery and connect scans)
netscout discover 10.0.0.0/24 --method icmp
netscout scan 192.168.1.1
```

---

## Usage Guide

### Finding Devices on Your Network

The `discover` command finds all active devices on a network range.

```bash
# Scan your entire local network (most common)
netscout discover 192.168.1.0/24

# Use ICMP ping sweep (no admin required, works across subnets)
netscout discover 10.0.0.0/24 --method icmp

# See detailed information about the scanning process
netscout discover 192.168.1.0/24 --verbose
```

**What's the difference between ARP and ICMP?**
- **ARP** (default): Fast and accurate on your local network. Finds all devices, even those that block pings. Requires admin/root.
- **ICMP**: Works like a regular ping. Slower but doesn't need admin rights. May miss devices that block ping requests.

### Scanning Ports on a Device

The `scan` command checks which ports are open on a target device.

```bash
# Quick scan of the most common ports (default)
netscout scan 192.168.1.1

# Scan specific ports
netscout scan 192.168.1.1 --ports 22,80,443,8080

# Scan a range of ports
netscout scan 192.168.1.1 --ports 1-1000

# Scan all 65,535 ports (takes longer)
sudo netscout scan 192.168.1.1 --ports 1-65535 --syn

# Identify services running on open ports
netscout scan 192.168.1.1 --banners

# Try to detect the operating system
netscout scan 192.168.1.1 --os-detect
```

**What's the difference between SYN and Connect scans?**
- **Connect scan** (default): Works without admin rights. Slower but reliable.
- **SYN scan** (`--syn`): Faster and stealthier. Requires admin/root. Sends only the first part of a TCP handshake.

### Detecting Operating Systems

```bash
# Guess the OS of a device based on its network behavior
netscout os-detect 192.168.1.1
```

This uses TTL (Time-To-Live) values from network packets to make an educated guess about the operating system. Results are heuristic-based and may not always be 100% accurate.

### Exporting Results

Save your scan results for later analysis or reporting:

```bash
# Save as JSON (great for scripts and further processing)
netscout scan 192.168.1.1 --output json --output-file results.json

# Save as CSV (great for spreadsheets)
netscout scan 192.168.1.1 --output csv --output-file results.csv

# Print JSON directly to the terminal
netscout scan 192.168.1.1 --output json
```

---

## Common Use Cases

### "What devices are on my home network?"
```bash
sudo netscout discover 192.168.1.0/24
```

### "Is my server exposing any unexpected ports?"
```bash
sudo netscout scan your-server-ip --ports 1-65535 --syn
```

### "What services are running on this device?"
```bash
netscout scan 192.168.1.100 --banners
```

### "I need a report of all open ports for documentation"
```bash
netscout scan 192.168.1.1 --output csv --output-file port-report.csv
```

---

## Troubleshooting

### "Permission denied" or "Operation not permitted"
You need to run the command with elevated privileges:
- **Windows**: Run Command Prompt as Administrator
- **Linux/macOS**: Add `sudo` before the command

### "No module named 'scapy'" or import errors
Reinstall NetScout:
```bash
pip install --upgrade netscout
```

### "Cannot find device" or packet capture errors
- **Windows**: Make sure Npcap is installed and you've restarted your computer
- **Linux**: Install libpcap (`sudo apt install libpcap0.8`)
- **macOS**: libpcap should be pre-installed

### Scan is very slow
- Try scanning fewer ports: `--ports 1-1000` instead of `--ports 1-65535`
- Use SYN scan for speed: `--syn` (requires sudo)
- Increase timeout if network is slow: adjust `--timeout` if available

### Device not showing up in discovery
- The device might be blocking discovery packets
- Try ICMP method: `netscout discover 192.168.1.0/24 --method icmp`
- Make sure you're on the same network as the target

---

## Project Structure

```
netscout/
├── cli/                  # Command-line interface
│   ├── main.py           # Entry point and commands
│   ├── validators.py     # Input validation
│   └── privileges.py     # Admin/root detection
├── scanner/              # Core scanning engine
│   ├── base.py           # Base scanner class
│   ├── arp_discovery.py  # ARP host discovery
│   ├── icmp_sweep.py     # ICMP ping sweep
│   ├── tcp_scan.py       # Port scanning (SYN + Connect)
│   └── banner_grab.py    # Service identification
├── analysis/             # Device analysis
│   ├── os_fingerprint.py # OS detection
│   └── mac_vendor.py     # MAC vendor lookup
├── output/               # Result formatting
│   ├── models.py         # Data models
│   ├── table.py          # Colored terminal output
│   ├── json_export.py    # JSON export
│   └── csv_export.py     # CSV export
└── data/
    └── oui.txt           # MAC vendor database
```

---

## Development

Want to modify NetScout?

```bash
# Clone the repository
git clone https://github.com/Kareem141/netscout.git
cd netscout

# Install with development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage report
pytest --cov=netscout --cov-report=term-missing

# Check code quality
ruff check netscout/

# Auto-format code
ruff format netscout/

# Type checking
mypy netscout/
```

---

## Security Note

NetScout is designed for **legitimate network administration and security testing only**. Always ensure you have permission to scan any network or device you don't own. Unauthorized scanning of networks you don't own may violate local laws.

---

## License

MIT
