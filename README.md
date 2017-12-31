# rtlmm

_Created by Evariste Courjaud F5OEO. Code is GPL_

**rtlmm** is software to sniff minimed RF packets using a RTLSDR dongle

This work is inspired by and partially based on Evariste Courjaud's great tool: https://github.com/F5OEO/rtlomni

SDR demodulation and signal processing is based on excellent https://github.com/jgaeddert/liquid-dsp/

# Installation under Debian based system
```sh
sudo apt-get install autoconf git

git clone https://github.com/jgaeddert/liquid-dsp/
cd liquid-dsp
./bootstrap.sh     # <- only if you cloned the Git repo
./configure
make
sudo make install
sudo ldconfig

git clone https://github.com/ps2/rtlmm
cd rtlmm
make

#Install rtl-sdr driver and utilities (rtl_test, rtl_sdr ...)
sudo apt-get install rtl-sdr

```

# Launching rtlmm
you can launch :
```sh
./rtlmm
```
It outputs messages from a RF sample file included in the folder.

For live message recording, there is a script 
```sh
./recordiq.sh
```


