/**
 * Pseudo-random number generator (RNG)
 */
#include <EEPROM.h>

#define DEBUG 1


/*
 * IV related variables
 */
union InitVector {
  uint64_t num64;
  uint32_t num32[2];
  uint8_t num8[8];
} iv;

int ivAddress = 0;

/*
 * Random data buffer - can be further optimized
 */
uint8_t rand_data[40] = {0x00}; // 32 bytes K_e (or K_e_prime), 8 bytes IV_rand


/**
 * Print IV - only for debugging purposes
 */
void rng_print_iv(){

  Serial.println(F("iv.num8 bytes"));
  for(uint8_t i=0;i<sizeof(iv);i++){
    Serial.print(iv.num8[i],HEX);
  }
  Serial.println(F(";"));
 

  Serial.println(F("iv.num32"));
  Serial.print(iv.num32[0],HEX);
  Serial.print(iv.num32[1],HEX);
  Serial.println(F(";"));
}

/**
 * To be called once upon startup
 * Load IV_eeprom
 * Increment by one
 */
void rng_oneshot_setup(){
  EEPROM.get(ivAddress, iv);
#if DEBUG
    rng_print_iv();  
#endif
  
  iv.num64++;
  
#if DEBUG
    rng_print_iv();  
#endif
  
  //EEPROM.put(ivAddress, iv); DOnt use EEPROM for now
}

/**
 * Call before each communication attempt 
 * to ensure a unique IV
 */
void rng_comm_setup(){
  /* increment first 32 bits before each connection attempt */
  iv.num32[1]++;
#if DEBUG
    rng_print_iv();  
#endif
  
  // EEPROM.put(ivAddress, iv); DOnt use EEPROM for now
}

