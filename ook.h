#ifndef OOK_H
#define OOK_H

#include <stdint.h>
#include <complex.h>

typedef enum {MODE_SQUELCH, MODE_PREAMBLE,MODE_PACKET} OokScanMode;

typedef struct {
  unsigned int k;
  unsigned int sample_counter;
  uint8_t last_level;
  unsigned int sample_index;
  uint32_t syncword;
  uint32_t sync_acc;
  uint8_t data_acc;
  uint8_t output_symbol;
  uint8_t bits_received;
  OokScanMode scan_mode;
  double threshold;
} DemodOOK;

void ook_init(DemodOOK *ook, unsigned int k, uint32_t syncword, double threshold);

// Returns true if a new 8-bit symbol is available.
bool ook_demod_sample(DemodOOK *ook, float complex sample);

uint8_t ook_get_symbol(DemodOOK *ook);

void ook_end_packet(DemodOOK *ook);


#endif //OOK_H
