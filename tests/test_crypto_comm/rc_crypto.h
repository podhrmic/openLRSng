/**
 * Cyrpto functions and oobjects
 */
#include <Crypto.h>
#include <ChaChaPoly.h>
#include "rng.h"

#define MAX_PLAINTEXT_LEN 32// 21 was too short
#define CRYPTO_OVERHEAD_LEN 32
#define IV_SIZE 8 // must be 8???
#define KEY_SIZE 32
#define TAG_SIZE 12
#define NUM_ROUNDS 12

#define PACKET_IV_POS 0
#define PACKET_DATA_POS 4
#define PACKET_TAG_POS 36
#define PACKET_STS_LEN 48
#define PACKET_ONGOING_LEN 37
#define PACKET_ONGOING_DATA_LEN 21
#define PACKET_ONGOING_TAG_POS 25

#define DEBUG 1

/*
 * Permanent key K_p
 * - has to be identical for both RX and TX
 * - REPLACE WITH YOUR OWN KEY! (use scripts/makeRandKey.m
 * NOTE: this wont work if stored in PROGMEM, because Chachapoly
 * doesn't work in progmem space, only RAM space:-(
 */
const uint8_t k_p[] = {166, 132, 84, 169, 30, 38, 6, 246, 
                               248, 32, 120, 168, 74, 193, 143, 110, 
                               69, 193, 230, 186, 104, 240, 66, 136, 
                               244, 69, 64, 237, 18, 77, 151, 52, 
                              };

/*
 * Main cipher struct
 */
ChaChaPoly chachapoly;

/*
 * Randomly generated variables
 */
uint8_t k_e[KEY_SIZE]; // TX generated
uint8_t iv_rand[8]; // TX generated
uint8_t k_e_prime[KEY_SIZE]; // RX generated
uint8_t iv_tx[IV_SIZE] = {0}; // iv for ongoing com
uint8_t iv_rx[IV_SIZE] = {0}; // iv for ongoing com

/*
 * Buffers - only temporary, to be optimized later
 */
uint8_t buffer[MAX_PLAINTEXT_LEN+CRYPTO_OVERHEAD_LEN] = {0x00};
uint8_t plaintext[MAX_PLAINTEXT_LEN] = {0};
uint8_t ciphertext[MAX_PLAINTEXT_LEN] = {0};
uint8_t tag[TAG_SIZE] = {0};

/**
 * Prints an arbitrary array - only for debugging purposes
 */
void print_array(uint8_t *array, size_t len)
{
  Serial.println(F(" "));
  for(uint8_t i=0;i<len;i++)
  {
    Serial.print(array[i]);
    Serial.print(F(","));
  }
  Serial.println(F(";\n"));
}

/**
 * Setup cryptographic structures
 */
void crypto_setup(){
  /* 
   * initialize rng 
   */
  rng_oneshot_setup();
}

/**
 * Crypto setup - identical for both devicess (RX and TX)
 */
void crypto_session_setup(){
  rng_comm_setup();

  /*
   * set cipher key and iv
   */
  chachapoly.setKey(k_p,KEY_SIZE); // K_p
  chachapoly.setIV(iv.num8, IV_SIZE); // IV
  chachapoly.setNumRounds(NUM_ROUNDS);
  chachapoly.encrypt(rand_data, buffer, sizeof(rand_data));

#if DEBUG
    Serial.print("Random data:");
    print_array(rand_data,sizeof(rand_data));  
#endif
  
  /* 
   * generate ephemeral key K_e 
   */
  memcpy(k_e, rand_data, KEY_SIZE);
#if DEBUG
    Serial.print("K e:");
    print_array(k_e,sizeof(k_e));  
#endif


  /*
   * generate ephemeral key K_e_prime
   * 
   * It doesn't cost us anything and we can reuse the came code 
   * for TX and RX
   * The proper variables are selected later in device specific code
   */
  memcpy(k_e_prime, k_e, sizeof(k_e));
#if DEBUG
    Serial.print("K e':");
    print_array(k_e_prime,sizeof(k_e_prime));
#endif
  
  /* 
   * iv_random - again, use for RX since we are not worries about 
   * saving space here
   */
  memcpy(iv_rand, &rand_data[KEY_SIZE], IV_SIZE/2); // copy only first 4 bytes
#if DEBUG
    Serial.print("IV_random:");
    print_array(iv_rand,sizeof(iv_rand));  
#endif

}

