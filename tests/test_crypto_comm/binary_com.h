/*
    Implementation of PSP (Phoenix Serial Protocol)

    Protocol data structure:
    [SYNC1][SYNC2][CODE][LENGTH][DATA/DATA ARRAY][CRC]
*/

#define DEBUG 1

#define PSP_SYNC1 0xB5
#define PSP_SYNC2 0x62

#define PSP_REQ_BIND_DATA               1
#define PSP_REQ_RX_CONFIG               2
#define PSP_REQ_RX_JOIN_CONFIGURATION   3
#define PSP_REQ_SCANNER_MODE            4
#define PSP_REQ_SPECIAL_PINS            5
#define PSP_REQ_FW_VERSION              6
#define PSP_REQ_NUMBER_OF_RX_OUTPUTS    7
#define PSP_REQ_ACTIVE_PROFILE          8
#define PSP_REQ_RX_FAILSAFE             9
#define PSP_REQ_TX_CONFIG               10
#define PSP_REQ_PPM_IN                  11
#define PSP_REQ_DEFAULT_PROFILE         12

#define PSP_SET_BIND_DATA               101
#define PSP_SET_RX_CONFIG               102
#define PSP_SET_TX_SAVE_EEPROM          103
#define PSP_SET_RX_SAVE_EEPROM          104
#define PSP_SET_TX_RESTORE_DEFAULT      105
#define PSP_SET_RX_RESTORE_DEFAULT      106
#define PSP_SET_ACTIVE_PROFILE          107
#define PSP_SET_RX_FAILSAFE             108
#define PSP_SET_TX_CONFIG               109
#define PSP_SET_DEFAULT_PROFILE         110

#define PSP_SET_EXIT                    199

#define PSP_INF_ACK                     201
#define PSP_INF_REFUSED                 202
#define PSP_INF_CRC_FAIL                203
#define PSP_INF_DATA_TOO_LONG           204

#define PSP_CRYPTO                      205


uint8_t PSP_crc;
uint16_t crc_err;

uint8_t data_buffer[100];
bool msg_available;
uint8_t data_len_available;


void PSP_serialize_uint8(uint8_t data)
{
  Serial2.write(data);
  /*
  Serial.print('#');
  Serial.print(data,DEC);
  Serial.print(',');
  */
  PSP_crc ^= data;
}


void PSP_protocol_head(uint8_t code, uint8_t length)
{
  PSP_crc = 0; // reset crc

  Serial2.write(PSP_SYNC1);
  Serial2.write(PSP_SYNC2);

  PSP_serialize_uint8(code);
  PSP_serialize_uint8(length);
}


void PSP_protocol_tail()
{
  Serial2.write(PSP_crc);
}


void PSP_ACK()
{
  PSP_protocol_head(PSP_INF_ACK, 1);

  PSP_serialize_uint8(0x01);
}


/**
 * Prints an arbitrary array - only for debugging purposes
 */
void PSP_print_array(uint8_t *array, size_t len)
{
  Serial.println(F(" "));
  for(uint8_t i=0;i<len;i++)
  {
    Serial.print(array[i]);
    Serial.print(F(","));
  }
  Serial.println(F(";\n"));
}


void PSP_process_data(uint8_t code, uint8_t payload_length_received)
{
#if DEBUG
  Serial.println("new message received");
  Serial.print("payload_len: ");
  Serial.println(payload_length_received, DEC);
  Serial.println("data buffer");
  PSP_print_array(data_buffer,sizeof(data_buffer));
#endif
  msg_available = true;
  data_len_available = payload_length_received;
}

void PSP_read(uint8_t data)
{
  static uint8_t state;
  static uint8_t code;
  static uint8_t message_crc;
  static uint8_t payload_length_expected;
  static uint8_t payload_length_received;

  switch(state) {
    case 0: // SYNC
      if (data == PSP_SYNC1) {
       state++; 
      }
      break;
    case 1: // SYNC
      if (data == PSP_SYNC2) {
        state++;
      } else {
        state = 0; // Restart and try again
      }
      break;
    case 2: // CODE
      code = data;
      message_crc = data;
      state++;
      break;
    case 3: // LENGTH LSB
      payload_length_expected = data;
      message_crc ^= data;
      memset(data_buffer, 0, sizeof(data_buffer)); // reset the buffer
      state++;

      if (payload_length_expected > sizeof(data_buffer)) {
        // Message too long, we won't accept
        state = 0; // Restart
      }
      break;
    case 4: // DATA
      data_buffer[payload_length_received] = data;
      message_crc ^= data;
      payload_length_received++;

      if (payload_length_received >= payload_length_expected) {
        state++;
      }
      break;
    case 5:// PROCESS DATA
      if (message_crc == data) {
        // CRC is ok, process data
        PSP_process_data(code, payload_length_received);
      } else {
        Serial.println("Crc failed");
        // respond that CRC failed
        crc_err++;
      }

      // reset variables
      
      payload_length_received = 0;
      state = 0;
      break;
    default:
      break;
  }
  
}

