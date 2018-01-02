/*
rtlmm is a software to sniff minimed RF packets using a RTLSDR dongle.

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
#include <liquid/liquid.h>

#include "fourbsixb.h"
#include "ook.h"

// IQ file center frequency
#define IQFREQ 916548000.0

// IQ file sample rate (should match the -s param to rtl_sdr)
// This gets us about 62 samples per symbol
#define IQSR 1048576.0

// Symbol rate
#define BAUDRATE 16384

// Samples per symbol
#define SAMPLES_PER_SYMBOL (IQSR / BAUDRATE)

// Magnitude threshold for 'on' bit
#define ON_BIT_THRESHOLD 0.05

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

  unsigned int fft_size = 4096;

  unsigned int i,j;

  uint8_t* iq_buffer; // 1Byte I, 1Byte Q
  iq_buffer = (uint8_t *)malloc(fft_size*2*sizeof(uint8_t)); // 1Byte I, 1Byte Q

  float *window = (float*)malloc(fft_size*sizeof(float));
  for (i=0; i<fft_size;i++) {
    window[i] = hamming(i,fft_size);
  }

  float complex *input_samples = (float complex*)malloc(fft_size*sizeof(float complex));

  float complex *fft_input = (float complex*)malloc(fft_size*sizeof(float complex));
  float complex *fft_output = (float complex*)malloc(fft_size*sizeof(float complex));

  int flags=0;        // FFT flags (typically ignored)
  fftplan fft = fft_create_plan(fft_size, fft_input, fft_output, LIQUID_FFT_FORWARD, flags);

  DemodOOK demod;
  ook_init(&demod, SAMPLES_PER_SYMBOL, 0xff00ff00, ON_BIT_THRESHOLD);

  FourbSixbDecoderState decoder;
  fourbsixb_init_decoder(&decoder);

  uint8_t packet[PACKET_LEN];
  uint8_t packet_len = 0;
  bool have_data_for_fft;

  while(1) {
    unsigned bytes_read = fread(iq_buffer, 1, fft_size*2, iqfile);
    have_data_for_fft = false;

    if (bytes_read > 0) {
      for(j=0, i=0; j<bytes_read; j+=2, i++)
      {
        float complex r=
             (((uint8_t*)iq_buffer)[j] -127.5)/128.0+
             (((uint8_t*)iq_buffer)[j+1] -127.5)/128.0 * I;

        //printf("%f, %f, %f\n", crealf(r), cimagf(r), cabsf(r));
        input_samples[i] = r;
      }

      if (bytes_read == fft_size*2) {
        have_data_for_fft = true;
      }

      for(i=0; i<bytes_read/2; i++) {
        float complex r = input_samples[i];
        if (ook_demod_sample(&demod, r)) {
          uint8_t data = ook_get_symbol(&demod);
          uint8_t encode_err = fourbsixb_add_encoded_byte(&decoder, data);
          uint8_t decoded;
          while(fourbsixb_next_decoded_byte(&decoder, &decoded)) {
            packet[packet_len++] = decoded;
          }
          // Encoding error happens at normal end of packet as well.
          if (encode_err) {
            float freq = 0.0;
            if (packet_len > 0) {
              // Determine center frequency of this packet
              if (have_data_for_fft) {
                for(j=0;j<fft_size;j++) {
                  fft_input[j] = input_samples[j] * window[j];
                }
                fft_execute(fft);
                unsigned int max_bin = 0;
                float max_val = 0;
                for(j=1; j<fft_size; j++) {
                  float val = cabsf(fft_output[j]);
                  if (val > max_val) {
                    max_val = val;
                    max_bin = j;
                  }
                }
                printf("freq: %0.02f ", (IQFREQ + ((max_bin ^ (fft_size >>1)) * IQSR / fft_size) - (IQSR / 2)) / 1000000.0);
              }
              printf("rx: ");
              for(j=0; j<packet_len;j++) {
                printf("%02x", packet[j]);
              }
            }

            fourbsixb_init_decoder(&decoder);
            ook_end_packet(&demod);
            packet_len = 0;
            printf("\n");
          }
        }
      }
    } else {
      break;
    }
  }

  fclose(iqfile);
  return 0;
}
