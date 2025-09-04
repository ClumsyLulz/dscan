# dscan
dscan Drupal Web Vulnerability Scanner

# Summary
dscan is a high-performance, production-ready web reconnaissance and security auditing tool designed for both penetration testers and system administrators. It automates the process of enumerating sensitive files, directories, and common endpoints on target websites, while simultaneously checking for missing critical security headers that could expose the application to attacks. With a comprehensive built-in path database covering Drupal-specific routes, CMS defaults, and general web assets, dscan also includes automated detection of known Drupal vulnerabilities like Drupalgeddon2 and Drupalgeddon3. The tool is fully multi-threaded, supports custom concurrency levels, and offers a polished CLI interface complete with a visually striking banner, -h/--help options, and interactive prompts, making it versatile, fast, and ready for global deployment on Unix-like systems including Debian 12. It provides actionable insights in real time, bridging the gap between vulnerability discovery and proactive security hardening.

# Installation ( Debian )
```bash
git clone https://github.com/ClumsyLulz/dscan
cd dscan
chmod +x dscan.sh
sudo bash dscan.sh
cd ..
sudo mv dscan /usr/local/bin/
dscan -h
```

# Usage
```bash
dscan -h
dscan http://example.com
dscan -t 100 http://example.com
```
