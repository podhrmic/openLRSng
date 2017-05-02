/**
 * Main Transmitter header file
 */
#include "binary_com.h"
#include "rc_crypto.h"

#define DEBUG 1

bool session_active =  true;
bool connected = false;

enum CommState {
  M1_TX,
  M2_RX,
  M3_TX,
  SECURED
};

enum CommState device_state;


uint32_t iv_tx_tmp = 0; // iv for ongoing comms, for sending messages
uint32_t iv_rx_tmp = 0; // iv for ongoing comms, for received messages

uint32_t cnt_rx = 0;
uint32_t cnt_tx = 1;

/**
 * interval is set to 50Hz to make it as fast as in real life
 */
uint32_t getInterval(){
  uint32_t ret;
  ret = 1000000;
  return ret;
}




/**
 * Decode message 2 and save k_e_prime
 * message bytes:
 * 0-3 IV_0
 * 4-35: k_e_prime
 * 36-47: tag
 */
bool decode_msg2(){
  // get iv
  memset(iv_rx, 0, IV_SIZE);
  memcpy(iv_rx, &buffer[PACKET_IV_POS], IV_SIZE/2);

  // get ciphertext
  memset(plaintext,0,sizeof(plaintext));
  memset(ciphertext,0,sizeof(ciphertext));
  memcpy(ciphertext, &buffer[PACKET_DATA_POS], KEY_SIZE);

  // get tag
  memset(tag,0,TAG_SIZE);
  memcpy(tag, &buffer[PACKET_TAG_POS], TAG_SIZE);

  // set cipher
  chachapoly.clear();
  chachapoly.setKey(k_e,KEY_SIZE); // K_e
  chachapoly.setIV(iv_rx, IV_SIZE);
  chachapoly.setNumRounds(NUM_ROUNDS);

  // decrypt
  chachapoly.decrypt(plaintext, ciphertext, KEY_SIZE);

#if DEBUG
  Serial.println("Msg2 got IV");
  print_array(iv_rx,IV_SIZE);
  Serial.println("Msg2 got ciphertext");
  print_array(ciphertext,KEY_SIZE);
  Serial.println("Msg2 got tag");
  print_array(tag,TAG_SIZE);
  Serial.println("Msg2 got plaintext");
  print_array(plaintext,KEY_SIZE);
#endif

  // authenticate
  if (chachapoly.checkTag(tag, TAG_SIZE)){
    Serial.println("Msg2 authenticated");
    // process message
    memcpy(k_e_prime, plaintext, KEY_SIZE);

#if DEBUG
    Serial.println("Msg1 got k_e_prime");
    print_array(k_e,sizeof(k_e_prime));
#endif

    // set cipher
    chachapoly.clear();
    chachapoly.setKey(k_e_prime, KEY_SIZE); // K_e
    chachapoly.setIV(iv_rx, IV_SIZE); // IV_0
    chachapoly.setNumRounds(NUM_ROUNDS);
    return true;
  }
  else {
    // error
    Serial.println("Msg2 not authenticated");
    return false;
  }
}


/**
 * Decode ongoing message and print what it shows
 *
 *
 * Dummy message
 *
 *  0 -  3 = iv: 4 bytes
 *  4 - 24 = data: 21 bytes
 * 25 - 36 = tag 12 bytes
 * TOTAL: 37
 */
bool decode_msg_ongoing() {
  // get iv
  memset(iv_rx, 0, IV_SIZE);
  memcpy(iv_rx, &buffer[PACKET_IV_POS], IV_SIZE/2);

  // get ciphertext
  memset(plaintext,0,sizeof(plaintext));
  memset(ciphertext,0,sizeof(ciphertext));
  memcpy(ciphertext, &buffer[PACKET_DATA_POS], PACKET_ONGOING_DATA_LEN);

  // get tag
  memset(tag,0,TAG_SIZE);
  memcpy(tag, &buffer[PACKET_ONGOING_TAG_POS], TAG_SIZE);

  // set cipher
  chachapoly.clear();
  chachapoly.setKey(k_e_prime,KEY_SIZE); // K_e
  chachapoly.setIV(iv_rx, IV_SIZE);
  chachapoly.setNumRounds(NUM_ROUNDS);

  // decrypt
  chachapoly.decrypt(plaintext, ciphertext, PACKET_ONGOING_DATA_LEN);


#if DEBUG
  Serial.println("Msg RX got IV");
  print_array(iv_rx,IV_SIZE);
  Serial.println("Msg RX got ciphertext");
  print_array(ciphertext,PACKET_ONGOING_DATA_LEN);
  Serial.println("Msg RX got tag");
  print_array(tag,TAG_SIZE);
  Serial.println("Msg RX got plaintext");
  print_array(plaintext,PACKET_ONGOING_DATA_LEN);
#endif


  // authenticate
  if (chachapoly.checkTag(tag, TAG_SIZE)){
    // increment counter
    memcpy(&iv_rx_tmp, iv_rx, sizeof(iv_rx_tmp));
    uint32_t cnt_tmp = iv_rx_tmp/16-1;
    if (cnt_tmp > cnt_rx){
      cnt_rx = cnt_tmp;
#if DEBUG
      Serial.print("\nMsg RX authenticaed, counter:");
      Serial.println(cnt_rx);
      Serial.print("\nMessage: ");
      Serial.println((char*)plaintext);
#endif
      return true;
    }
    else {
      Serial.println("Msg RX IV_CNT <= CNT_RX");
      return false;
    }
  }
  else {
    // error
    Serial.println("Msg RX not authenticated");
    return false;
  }
}



/**
 * Send MSG_1_TX
 */
void send_msg1(){

  chachapoly.clear();
  chachapoly.setKey(k_p,KEY_SIZE); // K_p
  chachapoly.setIV(iv_rand, IV_SIZE); // IV
  chachapoly.setNumRounds(NUM_ROUNDS);
  /*
   * construct first message
   * 
   * IV_rand- 32bit, use first 4 bytes
   * ChaCha12(K_e), 32bytes
   * Poly1305- 96 bit, 12 bytes
   * 48 bytes total
   */
  PSP_protocol_head(PSP_CRYPTO, PACKET_STS_LEN);
  for (uint8_t i = 0; i < IV_SIZE/2; i++) {
    PSP_serialize_uint8(iv_rand[i]);
  }

  /* encrypt K_e */
  memcpy(plaintext, k_e, sizeof(k_e));
  chachapoly.encrypt(ciphertext, plaintext, KEY_SIZE);
  /* now we should have 32 bytes of encrypted k_e */
  for (uint8_t i = 0; i < KEY_SIZE; i++) {
    PSP_serialize_uint8(ciphertext[i]);
  }

  /* calculate authentication tag */
  chachapoly.computeTag(tag, TAG_SIZE);  
  for (uint8_t i = 0; i < TAG_SIZE; i++) {
    PSP_serialize_uint8(tag[i]);
  }

#if DEBUG
  Serial.println("\nMsg1 IV rand");
  print_array(iv_rand,IV_SIZE);
  Serial.println("\nMsg1 plaintext");
  print_array(plaintext,KEY_SIZE);
  Serial.println("\nMsg1 ciphertext");
  print_array(ciphertext,KEY_SIZE);
  Serial.println("\nMsg1 tag");
  print_array(tag,TAG_SIZE);
#endif

  // send over crc
  PSP_protocol_tail();
}


/**
 * Send MSG_3_TX
 */
void send_msg3(){
#if DEBUG
  Serial.println("Msg3 to be send");
#endif
  /*
   * Construct third (ACK) message
   * IV_0 - 32 bit, 4 bytes
   * "ACK" - 32 bytes
   * tag, 12 bytes
   * 48 bytes total
   */
  PSP_protocol_head(PSP_CRYPTO, PACKET_STS_LEN);
  for (uint8_t i = 0; i < IV_SIZE/2; i++) {
    PSP_serialize_uint8(iv_rx[i]);
  }

  /* encrypt ACK */
  memset(plaintext,0,sizeof(plaintext));
  memset(ciphertext,0,sizeof(ciphertext));

  uint8_t ack_msg[] = "SECURE MESSAGE ACKNOWLEDGED";
  memcpy(plaintext, ack_msg, sizeof(ack_msg));
  chachapoly.encrypt(ciphertext, plaintext, KEY_SIZE);
  for (uint8_t i = 0; i < KEY_SIZE; i++) {
    PSP_serialize_uint8(ciphertext[i]);
  }

  /* calculate authentication tag */
  chachapoly.computeTag(tag, TAG_SIZE);
  for (uint8_t i = 0; i < TAG_SIZE; i++) {
    PSP_serialize_uint8(tag[i]);
  }

#if DEBUG
  Serial.println("\nMsg3 IV");
  print_array(iv_rx,4);
  Serial.println("\nMsg3 plaintext");
  print_array(plaintext,KEY_SIZE);
  Serial.println("\nMsg3 ciphertext");
  print_array(ciphertext,KEY_SIZE);
  Serial.println("\nMsg3 tag");
  print_array(tag,TAG_SIZE);
#endif

  // send over crc
  PSP_protocol_tail();

  // now clean iv_rx and iv_tx
  memset(iv_rx, 0, IV_SIZE);
  memset(iv_tx, 0, IV_SIZE);

}


/**
 * Send dummy mesg i with dummy TX data
 * 
 * use k_e and iv_tx with 16 increments
 */
void send_msg_ongoing(){
  static uint32_t lastSent = 0;
  static uint32_t time = 0;

  // send three messages at 50Hz rate
  time = micros();
  if ( ((time - lastSent) >= getInterval()) && (cnt_tx<3) ) {

    // increment IV
    iv_tx_tmp = (cnt_tx + 1) * 16;
#if DEBUG
    Serial.print("\nSending message ");
    Serial.println(cnt_tx,DEC);
    Serial.print("\nMessage IV: ");
    Serial.println(iv_tx_tmp,DEC);
#endif

    // set cipher
    chachapoly.clear();
    chachapoly.setKey(k_e,KEY_SIZE); // K_e
    memset(iv_tx, 0, IV_SIZE);
    memcpy(iv_tx, &iv_tx_tmp, sizeof(iv_tx_tmp));
    chachapoly.setIV(iv_tx, IV_SIZE); // IV
    chachapoly.setNumRounds(NUM_ROUNDS);

    /*
     * Dummy message
     *
     * iv: 4 bytes
     * data: 21 bytes
     * tag 12 bytes
     * TOTAL: 37
     */
    PSP_protocol_head(PSP_CRYPTO, PACKET_ONGOING_LEN);
    for (uint8_t i = 0; i < IV_SIZE/2; i++) {
      PSP_serialize_uint8(iv_tx[i]);
    }

    /* encrypt ACK */
    memset(plaintext,0,sizeof(plaintext));
    memset(ciphertext,0,sizeof(ciphertext));
    uint8_t data_msg[] = "TRANSMITTER SAYS HI\0";
    memcpy(plaintext, data_msg, sizeof(data_msg));
    chachapoly.encrypt(ciphertext, plaintext, PACKET_ONGOING_DATA_LEN);
    for (uint8_t i = 0; i < PACKET_ONGOING_DATA_LEN; i++) {
      PSP_serialize_uint8(ciphertext[i]);
    }

    /* calculate authentication tag */
    chachapoly.computeTag(tag, TAG_SIZE);
    for (uint8_t i = 0; i < TAG_SIZE; i++) {
      PSP_serialize_uint8(tag[i]);
    }

#if DEBUG
    Serial.println("\nMsg TX IV");
    print_array(iv_tx,IV_SIZE);
    Serial.println("\nMsg TX plaintext");
    print_array(plaintext,PACKET_ONGOING_DATA_LEN);
    Serial.println("\nMsg TX ciphertext");
    print_array(ciphertext,PACKET_ONGOING_DATA_LEN);
    Serial.println("\nMsg TX tag");
    print_array(tag,TAG_SIZE);
#endif

    // send over crc
    PSP_protocol_tail();

    // increment message counter
    cnt_tx++;

    lastSent = time;
  }
}


/**
 * Incoming messages handler
 */
void process_message(){
  /* first make a copy of data */
  memcpy(buffer, data_buffer, data_len_available);

  switch (device_state){
    case M1_TX:
      // do nothing, we are not supposed to receive a message here
      break;
    case M2_RX:
      Serial.println("Decoding Msg2.");
      // decode using Ke, IV_0
      if (decode_msg2()) {
        device_state = M3_TX;  
      }
      break;
    case M3_TX:
      // do nothing, we are not supposed to receive a message here
      break;
    case SECURED:
      // process incoming message
      decode_msg_ongoing();
      break;
    default:
      break;
  }
}


/**
 * Main TX loop
 */
void device_loop(){
  Serial.println(F("Trasnmitter device loop"));
  device_state = M1_TX;

  /* get random variables for given comm session */
  crypto_session_setup();

  /* activate session */
  session_active = true;

  while (session_active) {
    /* process inputs*/
    while (Serial2.available()) {
      uint8_t c = Serial2.read();
      PSP_read(c);
      if (msg_available){
        Serial.println("Processing new message");
        process_message();
        msg_available = false;
      }
    }

    /* run communication */
    switch(device_state){
      case M1_TX:
        send_msg1();
        Serial.println("Sending Msg1.");
        device_state = M2_RX;
        break;
      case M2_RX:
        // waiting for response, do nothing
        break;
      case M3_TX:
        Serial.println("Sending Msg3.");
        send_msg3();
        device_state = SECURED;
        Serial.println("Moving to secured state.");
        break;
      case SECURED:
        // send data here
        send_msg_ongoing();
        break;
      default:
        break;
    }
  }

}

