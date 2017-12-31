mkfifo fifo.cu8
rtl_sdr -p 76 -g 20 -f 434248000 -s 1300000 fifo.cu8 &
./rtlomni fifo.cu8 1

