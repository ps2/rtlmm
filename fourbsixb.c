
#include "fourbsixb.h"

static uint8_t codes[] = {21,49,50,35,52,37,38,22,26,25,42,11,44,13,14,28};

void fourbsixb_init_encoder(FourbSixbEncoderState *state) {
  state->acc = 0;
  state->bits_avail = 0;
}

void fourbsixb_add_raw_byte(FourbSixbEncoderState *state, uint8_t raw) {
  uint16_t new_bits = (codes[raw >> 4] << 6) | codes[raw & 0xf];
  state->acc = (state->acc << 12) | new_bits;
  state->bits_avail += 12;
}

uint8_t fourbsixb_next_encoded_byte(FourbSixbEncoderState *state, uint8_t *encoded) {
  if (state->bits_avail < 8) {
    return 0;
  }
  *encoded = state->acc >> (8-state->bits_avail);
  state->bits_avail -= 8;
  return 1;
}

void fourbsixb_init_decoder(FourbSixbDecoderState *state) {
  state->input_acc = 0;
  state->input_bits_avail = 0;
  state->output_acc = 0;
  state->output_bits_avail = 0;
}

uint8_t fourbsixb_add_encoded_byte(FourbSixbDecoderState *state, uint8_t encoded) {
  uint8_t code, i;
  state->input_acc = (state->input_acc << 8) | encoded;
  state->input_bits_avail += 8;
  while (state->input_bits_avail >= 6) {
    code = (state->input_acc >> (state->input_bits_avail - 6)) & 0b111111;
    state->input_bits_avail -= 6;
    for (i=0; i<16; i++) {
      if (codes[i] == code) {
        break;
      }
    }
    if (i == 16) {
      return 1; // Encoding error
    }
    state->output_acc = (state->output_acc << 4) | i;
    state->output_bits_avail += 4;
  }
  return 0;
}

uint8_t fourbsixb_next_decoded_byte(FourbSixbDecoderState *state, uint8_t *decoded) {
  if (state->output_bits_avail < 8) {
    return 0;
  }
  *decoded = state->output_acc >> (state->output_bits_avail - 8);
  state->output_bits_avail -= 8;
  return 1;
}
