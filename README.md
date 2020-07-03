# ewwwil_sniffer
Simple packet sniffer for educational purposes written in C
- Supports Windows only (it is compilable for Linux, but it is not working correctly yet)
- You need to have sufficient privileges to run this code, because it uses RAW sockets

```text
|=============================================================================================================================|
| Switch |     Arguments     | Description                                                                                    |
|-----------------------------------------------------------------------------------------------------------------------------|
| ?                          | Shows this content                                                                             |
| -I       <IP>              | Address of interface to be spectated                                                           |
| -sIP     <IP>              | Filter packets according to source IP                                                          |
| -sP      <Port>            | Filter packets according to source port (only for protocols using ports)                       |
| -dIP     <IP>              | Filter packets according to destination IP                                                     |
| -dP      <Port>            | Filter packets according to destination port (only for protocols using ports)                  |
| -B                         | Shows number of Bytes send to destination IP (destination IP must be set)                      |
| -S       <Protocol>        | Shows data for selected protocol (RAW can be set for raw data)                                 |
| -Sd      <Protocol>        | Shows detailed data for selected protocol (RAW can be set for raw data + ASCII representation) |
|=============================================================================================================================|
```

**Example command**
```
./ewwwil_sniffer -I 10.20.30.40 -Sd IP -dIP 40.30.20.10
```

**Example output**
```
Raw packet [0154 Bytes]
45 00 00 9A 2A 29 00 00 01 11 81 2C 0A AA 13 5A EF FF FF FA | E..............Z....
E1 14 07 6C 00 86 DA D9 4D 2D 53 45 41 52 43 48 20 2A 20 48 | ...l....M.SEARCH...H
54 54 50 2F 31 2E 31 0D 0A 48 4F 53 54 3A 20 32 33 39 2E 32 | TTP.1.1..HOST..239.2
35 35 2E 32 35 35 2E 32 35 30 3A 31 39 30 30 0D 0A 4D 41 4E | 55.255.250.1900..MAN
3A 20 22 73 73 64 70 3A 64 69 73 63 6F 76 65 72 22 0D 0A 4D | ...ssdp.discover...M
58 3A 20 31 0D 0A 53 54 3A 20 75 72 6E 3A 64 69 61 6C 2D 6D | X..1..ST..urn.dial.m
75 6C 74 69 73 63 72 65 65 6E 2D 6F 72 67 3A 73 65 72 76 69 | ultiscreen.org.servi
63 65 3A 64 69 61 6C 3A 31 0D 0A 0D 0A 00                   | ce.dial.1.....

|=================================|
| IPV4                            |
|---------------------------------|
| Version      : 4                |
| IHL          : 5     DWORDS     |
| DSCP         : 0                |
| ECN          : 0                |
| Total Length : 154   Bytes      |
| ID           : 10793            |
| Flags        : 0                |
| Frag. Offset : 0                |
| TTL          : 1                |
| Protocol     : 17               |
| CRC          : 33068            |
| Src IP       : 10.170.19.90     |
| Dst IP       : 239.255.255.250  |
|=================================|
```
