# ewwwil_sniffer
Simple packet sniffer written in C for educational purposes
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
