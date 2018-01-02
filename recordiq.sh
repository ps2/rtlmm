mkfifo fifo.cu8
rtl_sdr -p 76 -g 20 -f 916548000 -s 1024000 fifo.cu8 &
./rtlmm fifo.cu8 1
