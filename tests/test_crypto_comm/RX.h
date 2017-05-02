/**
 * Main Receiver header file
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
 * Decode message 1 and save k_e
 * message bytes:
 * 0-3 IV_rand (unused)
 * 4-35: k_e
 * 36-47: tag
 */
bool decode_msg1(){
  // get iv
  memset(iv_rx, 0, sizeof(iv_rx));
  memcpy(iv_rx, &buffer[PACKET_IV_POS], IV_SIZE/2);

  // get ciphertext
  memset(plaintext,0,sizeof(plaintext));
  memset(ciphertext,0,sizeof(ciphertext));
  memcpy(ciphertext, &buffer[PACKET_DATA_POS], KEY_SIZE);

  // get tag
  memset(tag,0,TAG_SIZE);
  memcpy(tag, &buffer[PACKET_TAG_POS], TAG_SIZE);

  // clear cipher
  chachapoly.clear();

  // set cipher
  chachapoly.setKey(k_p, KEY_SIZE); // K_p
  chachapoly.setIV(iv_rx, IV_SIZE); // IV_rand
  chachapoly.setNumRounds(NUM_ROUNDS);

  // decrypt
  chachapoly.decrypt(plaintext, ciphertext, KEY_SIZE);

#if DEBUG
  Serial.println("Msg1 got IV");
  print_array(iv_rx,IV_SIZE);
  Serial.println("Msg1 got ciphertext");
  print_array(ciphertext,KEY_SIZE);
  Serial.println("Msg1 got tag");
  print_array(tag,TAG_SIZE);
  Serial.println("Msg1 got plaintext");
  print_array(plaintext,KEY_SIZE);
#endif

  // authenticate
  if (chachapoly.checkTag(tag, TAG_SIZE)){
    Serial.println("Msg1 authenticated");
    // process message
    memcpy(k_e, plaintext, KEY_SIZE);

#if DEBUG
    Serial.println("received k_e");
    print_array(k_e,KEY_SIZE);
#endif

    // set cipher
    chachapoly.clear();
    memset(iv_rx, 0, IV_SIZE); // set IV_0
    chachapoly.setKey(k_e,KEY_SIZE); // K_e
    chachapoly.setIV(iv_rx, IV_SIZE); // IV_0
    chachapoly.setNumRounds(NUM_ROUNDS);
    return true;
  }
  else {
    // error
    Serial.println("Msg1 not authenticated");
    return false;
  }

}



/**
 * Decode message 3 and if all goes well, move on to ongoing comm
 * message bytes:
 * 0-3 IV_0
 * 4-35: ACK message
 * 36-47: tag
 */
bool decode_msg3(){
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
  chachapoly.setKey(k_e_prime,KEY_SIZE); // K_e
  chachapoly.setIV(iv_rx, IV_SIZE);
  chachapoly.setNumRounds(NUM_ROUNDS);

  // decrypt
  chachapoly.decrypt(plaintext, ciphertext, KEY_SIZE);

#if DEBUG
  Serial.println("Msg3 got IV");
  print_array(iv_rx,IV_SIZE);
  Serial.println("Msg3 got ciphertext");
  print_array(ciphertext,KEY_SIZE);
  Serial.println("Msg3 got tag");
  print_array(tag,TAG_SIZE);
  Serial.println("Msg3 got plaintext");
  print_array(plaintext,KEY_SIZE);
#endif

  // authenticate
  if (chachapoly.checkTag(tag, TAG_SIZE)){
    // process message
    device_state = SECURED;
#if DEBUG
    Serial.println("Msg3 authenticaed, device secured");
#endif
    return true;
  }
  else {
    // error
    Serial.println("Msg3 not authenticated");
    return false;
  }
}

/**
 * Decode ongoing message and print what it shows
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
  chachapoly.setKey(k_e,KEY_SIZE); // K_e
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
#if DEBUG
      Serial.print("\nMsg RX authenticaed, counter:");
      Serial.println(cnt_rx);
      Serial.print("\nMessage: ");
      Serial.println((char*)plaintext);
#endif
      return true;
      cnt_rx = cnt_tmp;
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
 * Send MSG_2_RX
 * construct reply message
 *
 * IV_zero - 32bit, use first 4 bytes
 * ChaCha12(K_e_prime), 32bytes
 * Poly1305- 96 bit, 12 bytes
 * 48 bytes total
 */
void send_msg2(){

#if DEBUG
  Serial.println("Msg2 to be send");
#endif

  PSP_protocol_head(PSP_CRYPTO, 48);
  for (uint8_t i = 0; i < 4; i++) {
    PSP_serialize_uint8(iv_tx[i]);
  }

  /* encrypt K_e_prime */
  memset(plaintext, 0, sizeof(plaintext));
  memset(ciphertext, 0, sizeof(ciphertext));
  memcpy(plaintext, k_e_prime, sizeof(k_e_prime));
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
  Serial.println("\nMsg2 IV");
  print_array(iv_tx,4);
  Serial.println("\nMsg2 plaintext");
  print_array(plaintext,KEY_SIZE);
  Serial.println("\nMsg2 ciphertext");
  print_array(ciphertext,KEY_SIZE);
  Serial.println("\nMsg2 tag");
  print_array(tag,TAG_SIZE);
#endif  

  // send over crc
  PSP_protocol_tail();
}


/**
 * Send dummy mesg i with dummy TX data
 *
 * use k_e_prime and iv_tx with 16 increments
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
    chachapoly.setKey(k_e_prime,KEY_SIZE); // K_e_prime
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
    for (uint8_t i = 0; i < 4; i++) {
      PSP_serialize_uint8(iv_tx[i]);
    }

    /* encrypt ACK */
    memset(plaintext,0,sizeof(plaintext));
    memset(ciphertext,0,sizeof(ciphertext));

    uint8_t data_msg[] = "RECEIVER SAYS HELLO\0";
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
    print_array(plaintext,KEY_SIZE);
    Serial.println("\nMsg TX ciphertext");
    print_array(ciphertext,KEY_SIZE);
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
      // decode using K_p, IV_rand (received)
      Serial.println("Decoding Msg1.");
      if (decode_msg1()){
        device_state = M2_RX;  
      }
      break;
    case M2_RX:
      // do nothing, we are not supposed to receive a message here
      break;
    case M3_TX:
      Serial.println("Decoding Msg3.");
      // decode using K_e_prime, IV_0 (received)
      if (decode_msg3()){
        device_state = SECURED;  
      }
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
  Serial.println(F("Receiver device loop"));
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
        // do nothing, waiting for first message
        break;
      case M2_RX:
        // send reply
        send_msg2();
        Serial.println("Sending Msg2.");
        device_state = M3_TX;
        break;
      case M3_TX:
        // waiting for response
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



