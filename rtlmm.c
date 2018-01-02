/*
rtlomni is a software to sniff RF packets using a RTLSDR dongle in order to analysis Omnipod protocol.

Credits :

This work is inspired by and partially based on Evariste Courjaud's great tool: https://github.com/F5OEO/rtlomni

License:

  Copyright 2018 Pete Schwamb
  Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
  The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <complex.h>

// IQ file sample rate (should match the -s param to rtl_sdr)
// This gets us about 62 samples per symbol
#define IQSR 1024000.0

// Symbol rate
#define BAUDRATE 16384

// Samples per symbol
#define SAMPLES_PER_SYMBOL (IQSR / BAUDRATE)

// Magnitude threshold for 'on' bit
#define ON_BIT_THRESHOLD 0.7

#define PACKET_LEN 255

int main(int argc, char*argv[])
{
  FILE* iqfile = NULL;
  char *inputname=argv[1];
  if(argc>=2)
  {
    if(inputname[strlen(inputname)-1]=='8') {
      iqfile = fopen (argv[1], "r");
      if (!iqfile) {
        printf("Could not open iqfile: %s\n", inputname);
        exit(1);
      }
    } else {
      printf("Unknown input file type: %s\n", inputname);
      exit(1);
    }
  } else {
    printf("Please specify input file.\n");
    exit(1);
  }

  unsigned int batch_size = 64;

  uint8_t* iq_buffer; // 1Byte I, 1Byte Q
  iq_buffer = (uint8_t *)malloc(batch_size*2*sizeof(uint8_t)); // 1Byte I, 1Byte Q

  float complex *input_samples;
  input_samples = (float complex*)malloc(batch_size*sizeof(float complex));

  unsigned int k = SAMPLES_PER_SYMBOL;
  unsigned int sample_counter = 0;
  uint8_t last_symbol = 0;
  unsigned int sample_index = k/2;

  unsigned int i,j;
  uint32_t syncword = 0xff00ff00;
  uint32_t sync_acc = 0;
  uint8_t symbol;
  uint8_t data_acc;
  uint8_t packet[PACKET_LEN];
  uint8_t bits_received = 0;
  uint8_t packet_len = 0;

  typedef enum {MODE_SQUELCH, MODE_PREAMBLE,MODE_PACKET} ScanMode;
  ScanMode scan_mode = MODE_SQUELCH;

  while(1) {
    unsigned bytes_read = fread(iq_buffer, 1, batch_size*2, iqfile);
    if (bytes_read > 0) {
      for(j=0, i=0; j<bytes_read; j+=2, i++)
      {
        float complex r=
             (((uint8_t*)iq_buffer)[j] -127.5)/128.0+
             (((uint8_t*)iq_buffer)[j+1] -127.5)/128.0 * I;

        //printf("%f, %f, %f\n", crealf(r), cimagf(r), cabsf(r));

        symbol = (cabsf(r) > ON_BIT_THRESHOLD) ? 1 : 0;
        bool edge = symbol != last_symbol;
        if (edge) {
          //printf("edge\n");
          sample_counter = 0;
        }
        if (sample_counter == sample_index) {
          //printf("************** output bit = %d\n", bit_on ? 1 : 0);
          if (scan_mode == MODE_SQUELCH) {
            if (symbol) {
              scan_mode = MODE_PREAMBLE;
            }
          } else if (scan_mode == MODE_PREAMBLE) {
            //printf("%d", symbol);
            sync_acc = (sync_acc << 1) + symbol;
            //printf("\nsync_acc =(%x)\n", sync_acc);
            if (sync_acc == syncword) {
              //printf(" - Sync!\n");
              scan_mode = MODE_PACKET;
              sync_acc = 0;
            }
          } else if (scan_mode == MODE_PACKET) {
            data_acc = (data_acc << 1) + symbol;
            bits_received = (bits_received + 1) % 8;
            if (bits_received == 0) {
              printf("%02x", data_acc);
              packet[packet_len++] = data_acc;
              if (data_acc == 0) {
                packet_len = 0;
                bits_received = 0;
                scan_mode = MODE_SQUELCH;
                printf("\n");
              }
              data_acc = 0;
            }
          }
        }
        last_symbol = symbol;
        sample_counter = (sample_counter + 1) % k;
      }
    } else {
      break;
    }
  }

  fclose(iqfile);
  return 0;
}
