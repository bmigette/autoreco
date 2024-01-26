# Requirements
NMAP will be run as sudo. You user should be able to do "sudo nmap" without being prompted (add it in your sudoers file)
```
userid ALL=(ALL) NOPASSWD:nmap_path
```

# Installation
```
pip install -r requirements.txt
```

# Configuration
There's a few hardcoded path in the config.py that matches default path for a Kali Linux installation. Might need to be adjusted for your system
Other options can also be fine tuned in this file.

# Usage
python main.py -h
