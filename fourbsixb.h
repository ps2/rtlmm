#ifndef FOURBSIXB_H
#define FOURBSIXB_H

#include <stdint.h>

typedef struct {
  uint16_t acc;
  uint8_t bits_avail;
} FourbSixbEncoderState;

typedef struct {
  uint16_t input_acc;
  uint8_t input_bits_avail;
  uint16_t output_acc;
  uint8_t output_bits_avail;
} FourbSixbDecoderState;

void fourbsixb_init_encoder(FourbSixbEncoderState *state);
void fourbsixb_add_raw_byte(FourbSixbEncoderState *state, uint8_t raw);
uint8_t fourbsixb_next_encoded_byte(FourbSixbEncoderState *state, uint8_t *encoded);
void fourbsixb_init_decoder(FourbSixbDecoderState *state);
uint8_t fourbsixb_add_encoded_byte(FourbSixbDecoderState *state, uint8_t raw);
uint8_t fourbsixb_next_decoded_byte(FourbSixbDecoderState *state, uint8_t *decoded);

#endif //FOURBSIXB_H
