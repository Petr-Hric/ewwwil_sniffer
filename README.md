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
| Src IP       : 10.20.30.40      |
| Dst IP       : 40.30.20.10      |
|=================================|
```
