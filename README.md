## WhoisX

**WhoisX** is a **powerful WHOIS lookup tool** written in C. It is designed to be more reliable and flexible than normal whois tools. If one server fails, WhoisX will automatically switch to another, ensuring you still get results. It can also follow referral servers to provide more accurate information. The tool supports multiple queries at the same time using worker threads, and the output can be shown either in plain text for easy reading or in JSON format for use in scripts and automation.

## Features

- Automatically switches to another server if one fails

- Comes with default global WHOIS servers (IANA, ARIN, RIPE, APNIC, LACNIC, AFRINIC, whois.verisign-grs.com, whois.pir.org))

- Custom connection timeout (default: 7 seconds)

- Option to follow referral WHOIS servers

- Multi-threaded for handling multiple queries

- JSON output support for automation and scripting

## Installation

1. **Clone the repository:**
```bash
git clone https://github.com/s-r-e-e-r-a-j/WhoisX.git
```
2. **Navigate to the project directory:**
```bash
cd WhoisX
```
3. **Run the installer to setup the system-wide command (Linux & Termux):**
```bash
sudo bash install.sh
```

## Command Line Options  

| Option                  | Description                                   |
|-------------------------|-----------------------------------------------|
| `-S server1,server2,...`| Use custom WHOIS servers (comma-separated)    |
| `-p port`               | Set the port (default: 43)                    |
| `-t timeout_ms`         | Set timeout in milliseconds (default: 7000)   |
| `-r`                    | Follow referral WHOIS servers                 |
| `-j`                    | Show output in JSON format                    |
| `-h`                    | Show help menu                                |


##  Usage  

```bash
whoisx [options] query1 [query2 ...]
```

## 📌 Examples  

**Lookup a domain**  
```bash
whoisx example.com
```

**Use JSON output**
```bash
whoisx -j github.com
```

**Follow referral servers**
```bash
whoisx -r google.com
```

**Set custom servers**
```bash
whoisx -S whois.verisign-grs.com,whois.pir.org example.org
```

**Multiple queries in one run**
```bash
whoisx example.com github.com google.com
```

## Uninstallation
```bash
sudo bash uninstall.sh
```
This will remove the whoisx command from your system(Termux & Linux).

## License
This project is licensed under the GNU General Public License v3.0
