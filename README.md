# Operation Systems (OSs) Course Assignment 3

### For Computer Science B.S.c Ariel University

**By Roy Simanovich and Linor Ronen**

## Description

In this assignment we implemented a tool called STNC (Stands for Student Network Communication) tool, that has two main functions:

* **Chat** – A chat cmd tool that can send messages over the network, to the same tool, listening on the other side, and get the response, so there will be 2 sides communication. The communication is based of IPv4 TCP protocol.
* **Network Performance Tool** – A network performance tool that checks the internal and external network between two processes (that can be in two different machines). The tool generates a 100MB of random, data, saves it to a file and sends it to the other side via one of the 8 different protocols:
  * **IPv4** – TCP or UDP (local or remote machine).
  * **IPv6** – TCP or UDP (local or remote machine).
  * **Unix Domain Socket (UDS)** – Stream (equivalent to TCP) or Datagram (equivalent to UDP), local machine only.
  * **Memory Mapped File** – Copy the generated file to the memory and share it (local machine only).
  * **Piping** – Transfer the generated file via piping (local machine only).

## Requirements

* Linux machine (Ubuntu 22.04 LTS preferable)
* OpenSSL crypto library
* GNU C Compiler
* Make

## Building

```
# Cloning the repo to local machine.
git clone https://github.com/RoySenpai/opsys_hw3.git

# Install OpenSSL crypto library
sudo apt-get install libssl-dev

# Building all the necessary files & the main programs.
make all
```

## Running

```
# Open STNC in client normal chat mode.
./stnc -c <IP> <PORT>

# Open STNC in server normal chat mode.
./stnc -s <PORT>

# Open STNC in client performance mode.
./stnc -c <IP> <PORT> -p <TYPE> <PARAM>

# Open STNC in server performance mode.
./stnc -s <PORT> -p

# Open STNC in server performance and quiet mode.
./stnc -s <PORT> -p -q
```

### Options for TYPE and PARAM:

```
# IPv4 & TCP mode
ipv4 tcp

# IPv4 & UDP mode
ipv4 udp

# IPv6 & TCP mode
ipv6 tcp

# IPv6 & UDP mode
ipv6 udp

# UDS & Datagram mode
uds dgram

# UDS & Stream mode
uds stream

# Memory map mode with specific file
mmap filename

# Pipe mode with specific file
pipe filename
```
