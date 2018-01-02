# rtlmm

_Created by Evariste Courjaud F5OEO. Code is GPL_

**rtlmm** is software to sniff minimed RF packets using a RTLSDR dongle

This work is inspired by and partially based on Evariste Courjaud's great tool: https://github.com/F5OEO/rtlomni

# Installation
```sh

git clone https://github.com/ps2/rtlmm
cd rtlmm
make

#Install rtl-sdr driver and utilities (rtl_test, rtl_sdr ...)
sudo apt-get install rtl-sdr

```

# Launching rtlmm
you can launch :
```sh
./rtlmm some_file.cu8
```
It outputs messages from a RF sample file included in the folder.

For live message recording, there is a script
```sh
./recordiq.sh
```
