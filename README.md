## WhoisX

**WhoisX** is a **powerful WHOIS lookup tool** written in C. It is designed to be more reliable and flexible than normal whois tools. If one server fails, WhoisX will automatically switch to another, ensuring you still get results. It can also follow referral servers to provide more accurate information. The tool supports multiple queries at the same time using worker threads, and the output can be shown either in plain text for easy reading or in JSON format for use in scripts and automation.

## Features

- Automatically switches to another server if one fails

- Comes with default global WHOIS servers (IANA, ARIN, RIPE, APNIC, LACNIC, AFRINIC)

- Custom connection timeout (default: 7 seconds)

- Option to follow referral WHOIS servers

- Multi-threaded for handling multiple queries

- JSON output support for automation and scripting
