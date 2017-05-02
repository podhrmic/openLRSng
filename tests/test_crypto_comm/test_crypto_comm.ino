/*
 * Tests crypto communication between two devices to test the comm protocol
 * Uses Arduino Mega (because it has extra serial ports)
 * 
 */

#define COMPILE_TX 1

#if COMPILE_TX
#include "TX.h"
#else
#include "RX.h"
#endif



void setup() {
  Serial.begin(115200);
  Serial.println(F("Crypto openLRSng starting"));

  Serial2.begin(115200);

  crypto_setup();
}


void loop() {
  device_loop();
}

