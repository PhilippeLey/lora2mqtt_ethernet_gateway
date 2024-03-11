

/****** WiFi and network settings ******/

// UDP logging settings if enabled in setup(); Port used for UDP logging
const word UDP_LOG_PORT = 6666;
// IP address of the computer receiving UDP log messages
const byte UDP_LOG_PC_IP_BYTES[4] = {192, 168, 130, 160};
// optional (access with UDP_logger.local)
const char *NET_MDNSNAME = "ESP_Ethernet_Lora_2_MQTT_Gateway";
// optional hostname
const char *NET_HOSTNAME = "ESP_Ethernet_Lora_2_MQTT_Gateway";
// only if you use a static address (uncomment //#define STATIC in ino file)
const byte NET_LOCAL_IP_BYTES[4] = {192, 168, 130, 140};
const byte NET_GATEWAY_BYTES[4] = {192, 168, 128, 1};
const byte NET_MASK_BYTES[4] = {255,255,252,0};
const byte NET_DNS_BYTES[4] = {192, 168, 1, 20}; 
const byte NET_SEC_DNS_BYTES[4] = {8, 8, 8, 8}; //  second dns (first = gateway), 8.8.8.8 = google
// only if you use ethernet (uncomment //#define ETHERNET in ino file)
byte NET_MAC[6] = {0xDE, 0xA2, 0xBE, 0x5F, 0x5E, 0x53};  // for ethernet (e.g. Funduino board with W5100)

/****** OTA settings ******/
// only if you use OTA (uncomment //#define OTA in ino file)
const char *MY_OTA_NAME = "lora_2_mqtt_gateway"; // optional (access with esp_with_ota.local)
// Linux Create Hasgh with: echo -n 'P@ssword1' | md5sum
const char *MY_OTA_PASS_HASH = "";
static bool eth_connected = false;

/****** NTP settings ******/
const char *NTP_SERVER = "0.lu.pool.ntp.org";
// your time zone (https://remotemonitoringsystems.ca/time-zone-abbreviations.php)
const char *TZ_INFO    = "CET-1CEST-2,M3.5.0/02:00:00,M10.5.0/03:00:00";
time_t now = 0;
tm timeinfo;                      // time structure
struct My_Timeinfo {
  byte second;
  byte minute;
  byte hour;
  byte day;
  byte month;
  unsigned int year;
  byte weekday;
  unsigned int yearday;
  bool daylight_saving_flag;
  String name_of_day;
  String name_of_month;
  String date;
  String time;
  String datetime;
} my;

/****** MQTT settings ******/
#ifdef USE_MQTT_SECURITY
  const char *MQTT_SERVER_IP = "192.168.130.160";
#else
  const char *MQTT_SERVER_IP = "192.168.128.82";
#endif  //USE_MQTT_SECURITY
const long PUBLISH_ALIVE_TIME = 60000; //Publishes every in milliseconds
const int MQTT_MAXIMUM_PACKET_SIZE = 1024; // look in setup()
// we use a Prefix! "Relip24-"
const char *MQTT_CLIENT_ID = "Relip24-1252594"; // this must be unique!!!
const String MQTT_TOPIC_OUT = "lora_2_mqtt_gateway";
const String MQTT_TOPIC_ALL = "/all_lora_messages";
const String MQTT_TOPIC_GW = "/gateway_lora_messages";
const String MQTT_TOPIC_GW_D = "/gateway_lora_messages_decrypted";
const String MQTT_TOPIC_KEY = "/key_data";
const String MQTT_TOPIC_ALARM = "/ALARM";
const String MQTT_TOPIC_OPEN_DOOR = "/open_door";
const String MQTT_TOPIC_RSSI_DATA = "/rssi_data";
const String MQTT_TOPIC_IN = "mqtt_test/command";
const short MQTT_PORT = 1883; // or 8883
const short MQTT_PORT_SECU = 8883; // or 8883
// only if you use MQTTPASSWORD (uncomment //#define MQTTPASSWORD in ino file)
const char *MQTT_USER = "relip";
const char *MQTT_PASS = "relip24!";
const char *MQTT_PSK_IDENTITY = "btsiot";
const char *MQTT_PSK_KEY = "abbabebededefafa2024"; // hex string without 0x

/****** LoRa settings ******/
// RFM95W (SX1276) connections to UEXT connector Olimex POE
const byte PIN_MISO = 16; // do not use GPIO2!!
const byte PIN_MOSI = 13;
const byte PIN_SCK = 14;
const byte PIN_SS = 15; //NSS
const byte PIN_RST = NOT_A_PIN;
const byte PIN_IRQ = 5 ; //DIO0

const byte GATEWAY_ADDR = 0xFE;              // address of this device
const unsigned long send_delay = 6000;       // delay in ms between sends

const byte E_HEADER = 25; //IV+ciphertext_length(1 byte)+tag
const byte MAX_BYTE_MSG_IN = 100;
byte msg_in[MAX_BYTE_MSG_IN+E_HEADER]; // even for encrypted message 
const byte STARTBYTE_OF_KEY_RSSI_DATA = 10;
byte key_rssi_counter = STARTBYTE_OF_KEY_RSSI_DATA;

byte key_addr, door_addr, msg_in_byte_counter;
short rssi_k2door, rssi_d2gateway;
volatile bool flag_lora_message_received = false; // flag set by callback


/****** AES128-GCM settings ******/
const unsigned int MAX_PLAINTEXT_LEN = MAX_BYTE_MSG_IN;

char mytext[MAX_PLAINTEXT_LEN] = "";
const char myvname[] = "AES-128 GCM";                 // vector name
char mykey[] = "AEBD21B769A6D13C0DF064E383682EFF";    // Key (16 byte)
char myAAD[] = "3000112233445566778899AABBCCDDEEFF";  // 17 byte (in Hex 34 character)
char myIV[] = "4E757273696E672100000000";             // "Nursing!" + 4 byte counter

struct Vector_GCM {
  const char *name;
  static const byte keysize = 16;    
  unsigned int datasize;
  static const byte authsize = 17;
  static const byte ivsize = 12;
  static const byte tagsize = 12;    
  byte key[keysize];    
  byte plaintext[MAX_PLAINTEXT_LEN];
  byte ciphertext[MAX_PLAINTEXT_LEN];
  byte authdata[authsize];
  byte iv[ivsize];
  byte tag[tagsize];    
};

unsigned long gcm_counter = 0;
unsigned long gcm_counter_high, gcm_counter_low;
