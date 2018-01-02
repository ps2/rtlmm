
#include <stdbool.h>
#include "ook.h"

void ook_init(DemodOOK *ook, unsigned int k, uint32_t syncword, double threshold) {
  ook->k = k;
  ook->sample_counter = 0;
  ook->last_level = 0;
  ook->sample_index = k/2;
  ook->syncword = syncword;
  ook->sync_acc = 0;
  ook->data_acc = 0;
  ook->bits_received = 0;
  ook->scan_mode = MODE_SQUELCH;
  ook->output_symbol = 0;
  ook->threshold = threshold;
}

bool ook_demod_sample(DemodOOK *ook, float complex sample) {
  bool symbol_available = false;
  uint8_t level = (cabsf(sample) > ook->threshold) ? 1 : 0;
  bool edge = level != ook->last_level;
  if (edge) {
    ook->sample_counter = 0;
  }
  if (ook->sample_counter == ook->sample_index) {
    if (ook->scan_mode == MODE_SQUELCH) {
      if (level) {
        ook->scan_mode = MODE_PREAMBLE;
      }
    } else if (ook->scan_mode == MODE_PREAMBLE) {
      ook->sync_acc = (ook->sync_acc << 1) + level;
      if (ook->sync_acc == ook->syncword) {
        ook->scan_mode = MODE_PACKET;
        ook->sync_acc = 0;
      }
    } else if (ook->scan_mode == MODE_PACKET) {
      ook->data_acc = (ook->data_acc << 1) + level;
      ook->bits_received = (ook->bits_received + 1) % 8;
      if (ook->bits_received == 0) {
        ook->output_symbol = ook->data_acc;
        symbol_available = true;
        ook->data_acc = 0;
      }
    }
  }
  ook->last_level = level;
  ook->sample_counter = (ook->sample_counter + 1) % ook->k;
  return symbol_available;
}

void ook_end_packet(DemodOOK *ook) {
  ook->bits_received = 0;
  ook->scan_mode = MODE_SQUELCH;
}

uint8_t ook_get_symbol(DemodOOK *ook) {
  return ook->output_symbol;
}
