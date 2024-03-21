/*
  lora_2_mqtt_gateway_SX1276_olimex_esp32_poe.ino 

  v1.0 2024-02-24
  v1.1 2024-03-11 // new protokoll for Nursing; all msg + encryted visible 

  ---------------------------------------------------------------------------
  Copyright (C) 2024 Guy WEILER www.weigu.lu
  
  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 o, SS = 15f the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <https://www.gnu.org/licenses/>.
  ---------------------------------------------------------------------------

  Lora with an Olimex POE board
  OTA and logging over UDP (Ethernet)
  and publish the data with mqtt
  
  ESP32 Olimex POE-ISO with SX1276 (RFM95W-V2.0)
  CS(SS)=15, RST=4, DIO0(IRQ)=5, freq = 868MHz
  SPI: MOSI=13, MISO=16, SCK=14 

  UEXT connector:

         3.3V * * GND
  RESET GPIO4 * * GPIO36 (input only)
  MISO GPIO16 * * GPIO13 MOSI
  NSS  GPIO15 * * GPIO2  
  SCK  GPIO14 * * GPIO5  DIO0

*/

/****** Defines to costumize the gateway ******/
//#define USE_SECRETS            // if secrets config in lib folder
#define SHOW_ALL_LORA_MESSAGES // normally only msgs 1 byte = GATEWAY_ADDR
#define DEBUG_SERIAL
#define DEBUG_UDP
//#define USE_AES128_GCM
//#define USE_MQTT_SECURITY
#define NURSING                  // BTS-IoT student real live project

// Important to be defined BEFORE including ETH.h for ETH.begin() to work.
// Example RMII LAN8720 (Olimex, etc.)
#define ETH_PHY_TYPE        ETH_PHY_LAN8720
#define ETH_PHY_ADDR        0
#define ETH_PHY_MDC         23
#define ETH_PHY_MDIO        18
#define ETH_PHY_POWER       12
#define ETH_CLK_MODE        ETH_CLOCK_GPIO17_OUT

#include <ETH.h>
#ifdef USE_MQTT_SECURITY
  #include <WiFiClientSecure.h>
#else  
  #include <WiFiClient.h>
#endif  
#include <ESPmDNS.h>
#include <WiFiUdp.h>
#include <ArduinoOTA.h>
#include <PubSubClient.h>
#include <SPI.h>
#include <LoRa.h>
#include <ArduinoJson.h>
#include <WiFi.h>
#include <time.h>

#ifdef USE_SECRETS
  // The file "secrets_xxx.h" has to be placed in a sketchbook libraries
  // folder. Create a folder named "Secrets" in sketchbook/libraries and copy
  // the config.h file there. Rename it to secrets_xxx.h
  #include <secrets_lora_2_mqtt_gateway.h> // things you need to change are here or
#else
  #include "config.h"  // things you need to change are here    
#endif

#ifdef USE_AES128_GCM
  #include <Crypto.h>
  #include <AES.h>
  #include <GCM.h>
  Vector_GCM my_vector;  
#endif // USE_AES128_GCM

IPAddress NET_LOCAL_IP(NET_LOCAL_IP_BYTES);  // 3x optional for static IP
IPAddress NET_GATEWAY(NET_GATEWAY_BYTES);    // look in config.h
IPAddress NET_MASK(NET_MASK_BYTES);
IPAddress NET_DNS(NET_DNS_BYTES);
IPAddress NET_SEC_DNS(NET_SEC_DNS_BYTES);
IPAddress UDP_PC_IP(UDP_LOG_PC_IP_BYTES); // in secrets_xxx.h or config.h

#ifdef USE_MQTT_SECURITY
  WiFiClientSecure ESP32_SEC_Client;
  PubSubClient MQTT_Client(ESP32_SEC_Client);
#else
  WiFiClient ESP32_Client;
  PubSubClient MQTT_Client(ESP32_Client);
#endif // USE_MQTT_SECURITY  

WiFiUDP Eth_Udp;

#ifdef NURSING
  byte nursing_flag = false;
#endif // NURSING

void setup() {
  init_ntp_time();     
  #ifdef DEBUG_SERIAL
    Serial.begin(115200);
    delay(2000);
    Serial.println("LoRa 2 MQTT Gateway\n");
  #endif // DEBUG_SERIAL
  WiFi.onEvent(wifi_event);
  ETH.begin();
  ETH.config(NET_LOCAL_IP, NET_GATEWAY, NET_MASK, NET_DNS, NET_SEC_DNS);
  delay(2000);
  Eth_Udp.begin(UDP_LOG_PORT);
  delay(1000);  
  init_lora();
  init_ota();  
  delay(1000);
  MQTT_Client.setBufferSize(MQTT_MAXIMUM_PACKET_SIZE);  
  #ifdef USE_MQTT_SECURITY
    ESP32_SEC_Client.setPreSharedKey(MQTT_PSK_IDENTITY, MQTT_PSK_KEY);
    MQTT_Client.setServer(MQTT_SERVER_IP, MQTT_PORT_SECU);
  #else
    MQTT_Client.setServer(MQTT_SERVER_IP, MQTT_PORT);
  #endif // USE_MQTT_SECURITY
  #ifdef USE_AES128_GCM
    // initialise the vector 
    if (init_vector_GCM_encryption(my_vector, myvname, mykey, mytext, myAAD, myIV) != 0) {
      log("Error while initialising vector!\n");      
    }    
    print_vector(my_vector);    
  #endif // USE_AES128_GCM
  
  delay(1000);  
  get_time();
  log("\nConnected with IP " + ETH.localIP().toString());
  log("\nEpoch time: " + String(now) + "\nSetup done!");  
  log("Setup done\n");
}

void loop() {    
  if (flag_lora_message_received) { // if receive flag is set by callback
    read_all_lora_message();
    #ifdef SHOW_ALL_LORA_MESSAGES      
      if (msg_in_byte_counter != 0) {
        mqtt_publish_lora_message(MQTT_TOPIC_OUT + MQTT_TOPIC_ALL);
      }      
    #endif // SHOW_ALL_LORA_MESSAGES
    handle_gw_lora_message();
    if (msg_in_byte_counter != 0) {
      mqtt_publish_lora_message(MQTT_TOPIC_OUT + MQTT_TOPIC_GW);
      #ifdef USE_AES128_GCM
        if (decrypt_gw_lora_message() != -1) {
          mqtt_publish_lora_message(MQTT_TOPIC_OUT + MQTT_TOPIC_GW_D);
        }
        else {
          log("Decryption went wrong or not nursing project!\n");
          nursing_flag = false;
        }
      #endif // USE_AES128_GCM        
      #ifdef NURSING
        if (nursing_flag == true) { // nursing
          handle_nursing_lora_message();
          memset(msg_in, 0, sizeof(msg_in)); // clear buffer
          nursing_flag = false;
        }
      #endif // NURSING
    }
    
    flag_lora_message_received = false;           // set flag back to false
  }    
  ArduinoOTA.handle();  
  if (non_blocking_delay(PUBLISH_ALIVE_TIME)) {    
    publish_alive_message();
  }  
  eth_mqtt_reconnect();
  delay(1); //needed!
}

/****** LoRa *****************************************************************/
// LoRa callback function (DIO0)
IRAM_ATTR void on_receive(int packetSize) { 
  if (packetSize == 0) { // if there's no packet, return    
    return;
  }
  flag_lora_message_received = true;     //Set flag to perform read in main loop  
}

void init_lora() {
  SPI.begin(PIN_SCK, PIN_MISO, PIN_MOSI, PIN_SS);   //SPI LoRa pins
  LoRa.setPins(PIN_SS, PIN_RST, PIN_IRQ);  // setup LoRa transceiver module  
  if (!LoRa.begin(868E6)) {
    log("Error starting LoRa!\n");
    while (true);                           // endless loop
  }
  LoRa.onReceive(on_receive);                 // init the callback function
  LoRa.receive();                            // start receive mode  
  log("LoRa initialised!\n");
}

void read_all_lora_message() {
  byte counter = 0;
  while (LoRa.available()) {        
    msg_in[counter] = LoRa.read();   
    counter++;
    yield();
  }   
  msg_in_byte_counter = counter;
}

// check if valid for the gateway and omit first byte (2 byte for nursing)
void handle_gw_lora_message() {
  if (msg_in[0] != GATEWAY_ADDR) {         // not for us! 
    msg_in_byte_counter = 0;
    return;
  }      
  for (byte i = 0; i<msg_in_byte_counter; i++) {
    msg_in[i] = msg_in[i+1];        
  }
  msg_in_byte_counter -= 1;      
  #ifdef NURSING        
    if (msg_in[0] == 99) {
      nursing_flag = true;      
      for (byte i = 0; i<msg_in_byte_counter; i++) {
        msg_in[i] = msg_in[i+1];        
      }
      msg_in_byte_counter -= 1;
    }  
  #endif // NURSING  
}

/*void read_gw_lora_message() {
  byte counter = 0;
  byte start = LoRa.read();            // get startbyte  
  if (start != GATEWAY_ADDR) {         // not for us! 
    msg_in_byte_counter = 0;
    return;
  }  
  #ifdef NURSING    
    byte nursing = LoRa.read();        // get second byte;        
    if (nursing == 99) {
      nursing_flag = true;    
    }
    else {
      msg_in[0] = ;
      counter++;
    }
  #endif // NURSING
  //log(String(start,HEX));
  while (LoRa.available()) {        
    msg_in[counter] = LoRa.read();   
    counter++;
    yield();
  }  
  msg_in_byte_counter = counter;
}*/


#ifdef USE_AES128_GCM
  int decrypt_gw_lora_message() {
    String system_title = "";  // get system title (iv_text first 8 Byte)  
    for (byte i = 0; i<8; i++) { 
      system_title += String(char(msg_in[i]));
    }    
    log("\nSystem_title: " + String(system_title) + "\n");
    #ifdef NURSING
      if (system_title != "Nursing!") { // nursing    
      return -1;
      }
    #endif // NURSING
    for (byte i = 0; i<my_vector.ivsize; i++) { // copy iv from msg
      my_vector.iv[i] = msg_in[i];
    }    
    for (byte i = 0; i<my_vector.ivsize; i++) { // copy iv from msg
      my_vector.iv[i] = msg_in[i];
    }    
    my_vector.datasize  = msg_in[my_vector.ivsize];; // copy ciphertxt length
    // copy cipher to vector 
    for (byte i = 0; i<my_vector.datasize; i++) { 
      my_vector.ciphertext[i] = msg_in[my_vector.ivsize+1+i];      
    }    
    for (byte i = 0; i<my_vector.tagsize; i++) { // copy tag to msg
      my_vector.tag[i] = msg_in[i+my_vector.ivsize+1+my_vector.datasize];
    }
    decrypt_text(my_vector); 
    //print_vector(my_vector);
    memset(msg_in, 0, sizeof(msg_in)); // clear buffer
    for (byte i = 0; i<my_vector.datasize; i++) { 
      msg_in[i] = my_vector.plaintext[i];
    }
    msg_in_byte_counter = my_vector.datasize;
    return 0;
  }
#endif //USE_AES128_GCM
/****** MQTT *****************************************************************/

void publish_alive_message() {
  String message = "{\"alive\":\"" + my.datetime + "\"}";  
  MQTT_Client.publish(MQTT_TOPIC_OUT.c_str(),message.c_str());
  log(String(message) + "\n");   
}

void mqtt_reconnect() {
  while (!MQTT_Client.connected()) {
    log("Attempting MQTT connection...");
    #ifdef USE_MQTT_SECURITY
      if (MQTT_Client.connect(MQTT_CLIENT_ID,MQTT_USER,MQTT_PASS)) {      
        log("connected\n");
        //MQTT_Client.subscribe("random/test");
      } else {
        log("failed, rc=" + String(MQTT_Client.state()) + " try again in 5 seconds");
        delay(5000);
      }
    #else
      if (MQTT_Client.connect(MQTT_CLIENT_ID)) {      
         log("connected\n");
         //MQTT_Client.subscribe("random/test");
      } else {
        log("failed, rc=" + String(MQTT_Client.state()) + " try again in 5 seconds");
        delay(5000);
      }
    #endif // USE_MQTT_SECURITY    
  }
}

void mqtt_publish_lora_message(String topic) {  
  int message_length = 100 + msg_in_byte_counter*3;
  DynamicJsonDocument doc(message_length);
  String mqtt_msg = "";    
  String bytes_hex = ""; 
  get_time();
  doc["datetime"] = my.datetime;
  doc["RSSI"] = String(LoRa.packetRssi());
  doc["SNR"] = String(LoRa.packetSnr());
  for (byte i = 0; i<msg_in_byte_counter; i++) {    
    if (msg_in[i]<16) {
      bytes_hex += "0";
    }
    bytes_hex += (String(msg_in[i],HEX) + " ");
    yield();
  }
  doc["message_hex"] = bytes_hex;  
  serializeJson(doc, mqtt_msg);  
  MQTT_Client.publish(topic.c_str(),mqtt_msg.c_str());
  log(String(mqtt_msg) + "\n");   
}

/****** WiFi & OTA ***********************************************************/
/*void init_wifi() {
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  while (WiFi.status() != WL_CONNECTED) {
    delay(200);
    #ifdef   DEBUG
      Serial.print ( "." );
    #endif  
  }
}  */

void eth_mqtt_reconnect() {
  if (eth_connected) {  // global var in in config   
    if (!MQTT_Client.connected()) {
      mqtt_reconnect();
    } else {
      MQTT_Client.loop();      
    }
  }
}  

void wifi_event(WiFiEvent_t event) {
  switch (event) {
    case ARDUINO_EVENT_ETH_START:
      log("ETH Started\n");
      //set eth hostname here
      ETH.setHostname("esp32-ethernet");
      break;
    case ARDUINO_EVENT_ETH_CONNECTED:
      log("ETH Connected\n");
      break;
    case ARDUINO_EVENT_ETH_GOT_IP:
      log("ETH MAC: " + String(ETH.macAddress()) + ", IPv4: " +
              ETH.localIP().toString());      
      if (ETH.fullDuplex()) {
        log(", FULL_DUPLEX");
      }
      log(", " + String(ETH.linkSpeed()) +"Mbps\n");
      eth_connected = true;
      break;
    case ARDUINO_EVENT_ETH_DISCONNECTED:
      log("ETH Disconnected\n");
      eth_connected = false;
      break;
    case ARDUINO_EVENT_ETH_STOP:
      log("ETH Stopped\n");
      eth_connected = false;
      break;
    default:
      break;
  }
}

void init_ota() {
  log("\ninit OTA\n");
  ArduinoOTA.setHostname(MY_OTA_NAME);
  ArduinoOTA.setPasswordHash(MY_OTA_PASS_HASH);
  ArduinoOTA
    .onStart([]() {
      String type;
      if (ArduinoOTA.getCommand() == U_FLASH)
        type = "sketch";
      else // U_SPIFFS
        type = "filesystem";
      // NOTE: if updating SPIFFS this would be the place to unmount SPIFFS using SPIFFS.end()
      log("Start updating \n" + type);
    })
    .onEnd([]() {
      log("\nEnd\n");
    })
    .onProgress([](unsigned int progress, unsigned int total) {
      log("Progress: " + String(progress / (total / 100)) + "\n");
    })
    .onError([](ota_error_t error) {
      log("Error: " + String(error));
      if (error == OTA_AUTH_ERROR) log("Auth Failed\n");
      else if (error == OTA_BEGIN_ERROR) log("Begin Failed\n");
      else if (error == OTA_CONNECT_ERROR) log("Connect Failed\n");
      else if (error == OTA_RECEIVE_ERROR) log("Receive Failed\n");
      else if (error == OTA_END_ERROR) log("End Failed\n");
    });
  ArduinoOTA.begin();
}

/****** Helper *************************************************************/
void log(String message) {
  #ifdef DEBUG_SERIAL
    Serial.print(message);
  #endif  // DEBUG_SERIAL
  #ifdef DEBUG_UDP
    Eth_Udp.beginPacket(UDP_PC_IP,UDP_LOG_PORT);
    Eth_Udp.print(message);
    Eth_Udp.endPacket();
  #endif  // DEBUG_UDP
}  

 // non blocking delay using millis(), returns true if time is up
bool non_blocking_delay(unsigned long milliseconds) {
  static unsigned long nb_delay_prev_time = 0;
  if(millis() >= nb_delay_prev_time + milliseconds) {
    nb_delay_prev_time += milliseconds;
    return true;
  }
  return false;
}

// convert a c-string with hexbytes to real bytes
int c_string_hexbytes_2_bytes(char c_string[], byte byte_array[]) {   
  byte tmp_array_size = strlen(c_string);
  byte tmp_array[tmp_array_size]; 
  for (byte i=0; i<tmp_array_size; i++) {    
    if ((c_string[i]>='A') && (c_string[i]<='F')) tmp_array[i] = byte(c_string[i]-55);       
    else if ((c_string[i]>='a') && (c_string[i]<='f')) tmp_array[i] = byte(c_string[i]-87);
    else if ((c_string[i]>='0') && (c_string[i]<='9')) tmp_array[i] = byte(c_string[i]-48);
    else {
      log("Error: no Hex bytes in string\n"); 
      return -1;    
    }
    if (i%2==1) {                                  // i odd (every second character)
      byte_array[(i-1)/2] = byte((tmp_array[i-1]*16)+tmp_array[i]);
    }
  }           
  return 0;
}

// init NTP time: call this before the WiFi connect!
void init_ntp_time() { 
  configTime(0, 0, NTP_SERVER); // 0, 0 because we will use TZ in the next line
  setenv("TZ", TZ_INFO, 1);     // set environment variable with your time zone
  tzset();
}

// epoch to tm structure and update global struct
void get_time() {
  time(&now);                     // this function calls the NTP server only every hour
  localtime_r(&now, &timeinfo);   // converts epoch time to tm structure
  my.second  = timeinfo.tm_sec;
  my.minute  = timeinfo.tm_min;
  my.hour  = timeinfo.tm_hour;
  my.day  = timeinfo.tm_mday;
  my.month  = timeinfo.tm_mon + 1;    // beer (Andreas video)
  my.year  = timeinfo.tm_year + 1900; // beer
  my.weekday = timeinfo.tm_wday; 
  if (my.weekday == 0) {              // beer
    my.weekday = 7;
  }
  my.yearday = timeinfo.tm_yday + 1;  // beer
  my.daylight_saving_flag  = timeinfo.tm_isdst;
  char buffer[25];  
  strftime(buffer, 25, "%A", localtime(&now));
  my.name_of_day = String(buffer);
  strftime(buffer, 25, "%B", localtime(&now));
  my.name_of_month = String(buffer);
  strftime(buffer, 25, "20%y-%m-%d", localtime(&now));
  my.date = String(buffer);
  strftime(buffer, 25, "%H:%M:%S", localtime(&now));
  my.time = String(buffer);  
  strftime(buffer, 25, "20%y-%m-%dT%H:%M:%S", localtime(&now));
  my.datetime = String(buffer);  
}

void print_vector(Vector_GCM &vect) {
  const byte MAX_SCREEN_LINE_LENGTH = 25;
  log("-----------------------------------\nPrint Vector: ");
  log("\nVector_Name: " + String(vect.name));
  log("\nKey Size: " + String(vect.keysize));  
  log("\nData Size: " + String(vect.datasize));
  log("\nAuth_Data Size: " + String(vect.authsize));
  log("\nInit_Vect Size: " + String(vect.ivsize));
  log("\nAuth_Tag Size: " + String(vect.tagsize));
  log("\nKey: ");
  for(byte i=0; i<vect.keysize; i++) {
    log(String(vect.key[i],HEX) + ' ');    
  }
  log("\nPlaintext: ");
  byte more_lines = (vect.datasize/MAX_SCREEN_LINE_LENGTH);
  if (more_lines) {
    for(byte i=0; i<more_lines; i++) {
      for(byte j=0; j<MAX_SCREEN_LINE_LENGTH;j++) {
        log(String(vect.plaintext[i*MAX_SCREEN_LINE_LENGTH+j],HEX) + ' '); 
        yield();     
      }
      log("\n");
    }
  }
  for(byte j=0; j<(vect.datasize%MAX_SCREEN_LINE_LENGTH);j++) {
    log(String(vect.plaintext[more_lines*MAX_SCREEN_LINE_LENGTH+j],HEX) + ' ');
    yield();    
  }
  log("\nCyphertext: ");  
  if (more_lines) {
    for(byte i=0; i<more_lines; i++) {
      for(byte j=0; j<MAX_SCREEN_LINE_LENGTH;j++) {
        log(String(vect.ciphertext[i*MAX_SCREEN_LINE_LENGTH+j],HEX) + ' ');      
        yield();
      }
      log("\n");
    }
  }
  for(byte j=0; j<(vect.datasize%MAX_SCREEN_LINE_LENGTH);j++) {
    log(String(vect.ciphertext[more_lines*MAX_SCREEN_LINE_LENGTH+j],HEX) + ' '); 
    yield();   
  }
  log("\nAuth_Data: ");
  for(byte i=0; i<vect.authsize; i++) {
    log(String(vect.authdata[i],HEX) + ' ');    
  }
  log("\nInit_Vect: ");
  for(byte i=0; i<vect.ivsize; i++) {
    log(String(vect.iv[i],HEX) + ' ');    
  }
  log("\nAuth_Tag: ");
  for(byte i=0; i<vect.tagsize; i++) {
    log(String(vect.tag[i],HEX) + ' ');    
  }  
  log("\n-----------------------------------\n");
}

/****** NURSING *************************************************************/
// these functions are only needed for BTS-IoT student real live project

void handle_nursing_lora_message() {  
  log("msg_in[0] " + String(msg_in[0]) + "\n");  
  if (msg_in[0] & 0x40 != 0x40) { //no doorplate address
    return;
  }
  key_addr = msg_in[0] & 0x3F;
  log("key_addr = " + String(key_addr) + "\n");  
  //byte door_addr = msg_in[0] & 0x7F;
  // get rssi from key to door (reconvert from abs value)
  rssi_k2door = short((-1)*msg_in[2]); // key to door  
  log(" RSSI: " + String(rssi_k2door)+ "\n");  
  if ((rssi_k2door>0) || (rssi_k2door<-180)) { // check if valable rssi
    return;
  }  
  rssi_d2gateway = LoRa.packetRssi();
  log("message counter = " + String(msg_in_byte_counter) + " RSSI: " + String(rssi_d2gateway)+ "\n");  
  // check if Alarm!!
  if (msg_in_byte_counter == 3) { // Alarm or open door  
    if ((msg_in[0] & 0x80) == 0x80) { //Alarm          
      log("!!!Alarm!!! from key nr: " + String(key_addr) + "\n");
      publish_alarm_message(); 
    }
    if ((msg_in[1] & 0x01) == 0x01) { // open door      
      log("Open door nr:" + String(key_addr) + "\n");
      publish_open_door_message(); 
    }
  } 
  else {
    log("Normal message from key: " + String(key_addr) + "\n");
    publish_normal_message();
    publish_key_rssi_data_message();    
  }  
  msg_in_byte_counter = 0;
}

void publish_alarm_message() {
  DynamicJsonDocument doc(256);
  String mqtt_msg;    
  get_time();
  doc["datetime"] = my.datetime;
  doc["alarm_key_nr"] = key_addr;  
  doc["alarm_key_rssi_to_door_dBm"] = rssi_k2door;
  doc["door_rssi_to_gateway_dBm"] = rssi_d2gateway;  
  mqtt_msg = "";
  serializeJson(doc, mqtt_msg);  
  String topic = MQTT_TOPIC_OUT + MQTT_TOPIC_ALARM + "_key_" + String(key_addr);
  MQTT_Client.publish(topic.c_str(),mqtt_msg.c_str());
  log(String(mqtt_msg) + "\n");  
}

void publish_open_door_message() {
  DynamicJsonDocument doc(256);
  String mqtt_msg;    
  doc["datetime"] = my.datetime;  
  doc["open_door_nr"] = key_addr;  
  doc["key_rssi_to_door_dBm"] = rssi_k2door;
  doc["door_rssi_to_gateway_dBm"] = rssi_d2gateway;  
  mqtt_msg = "";
  serializeJson(doc, mqtt_msg);  
  String topic = MQTT_TOPIC_OUT + MQTT_TOPIC_OPEN_DOOR + "/door_" + String(key_addr);
  MQTT_Client.publish(topic.c_str(),mqtt_msg.c_str());
  log(String(mqtt_msg) + "\n");   
}

void publish_normal_message() {
  DynamicJsonDocument doc(256);
  String mqtt_msg = "";
  get_time();
  short key_voltage = short(msg_in[3]*256 + msg_in[4]);   
  if ((key_voltage>3400) || (key_voltage<1700)) { // one last check
    return;
  }       
  short doorplate_voltage = short(msg_in[5]*256 + msg_in[6]);
  doc["datetime"] = my.datetime;  
  doc["key_voltage_mV"] = key_voltage;
  doc["key_rssi_to_door_dBm"] = rssi_k2door;
  doc["doorplate_voltage_mV"] = doorplate_voltage;  
  doc["door_rssi_to_gateway_dBm"] = rssi_d2gateway;    
  serializeJson(doc, mqtt_msg);  
  String topic = MQTT_TOPIC_OUT + MQTT_TOPIC_KEY + "/key_" + String(key_addr);
  MQTT_Client.publish(topic.c_str(),mqtt_msg.c_str());
  log(String(mqtt_msg) + "\n");  
}

/*void publish_key_rssi_data_message() {
  DynamicJsonDocument doc(1024);
  String mqtt_msg = "";
  short rssi;  
  const String KEY = "_key_";
  String key_nr ="";
  get_time();
  doc["datetime"] = my.datetime;  
  for (byte i = STARTBYTE_OF_KEY_RSSI_DATA; i<MAX_BYTE_MSG_IN; i=i+2) {
    if (msg_in[i] != 0) {      
      key_nr = String(((i-STARTBYTE_OF_KEY_RSSI_DATA)/2)+1) + KEY + String(msg_in[i]);
      rssi = short((-1)*msg_in[i+1]); // key to door
      doc[key_nr] = rssi;
    }      
  }  
  serializeJson(doc, mqtt_msg);  
  String topic = MQTT_TOPIC_OUT + MQTT_TOPIC_RSSI_DATA + "/door_" + String(key_addr);
  MQTT_Client.publish(topic.c_str(),mqtt_msg.c_str());
  log(String(mqtt_msg) + "\n");  
}*/

void publish_key_rssi_data_message() {
  DynamicJsonDocument doc(1024);
  String mqtt_msg = "";
  short rssi;  
  const String KEY = "_key_";
  String key_nr ="";
  get_time();
  doc["datetime"] = my.datetime;  
  JsonArray keysArray = doc.createNestedArray("keys");
  for (byte i = STARTBYTE_OF_KEY_RSSI_DATA; i<MAX_BYTE_MSG_IN; i=i+2) {
    if (msg_in[i] != 0) {      
      JsonObject keyObject = keysArray.createNestedObject();
      keyObject["key"] = msg_in[i];
      keyObject["rssi"] = short((-1)*msg_in[i+1]);
    }      
  }  
  serializeJson(doc, mqtt_msg);  
  String topic = MQTT_TOPIC_OUT + MQTT_TOPIC_RSSI_DATA + "/door_" + String(key_addr);
  MQTT_Client.publish(topic.c_str(),mqtt_msg.c_str());
  log(String(mqtt_msg) + "\n");  
}

// /******* Decryption AES128_GCM ***********************************************/
#ifdef USE_AES128_GCM

// initialize the vector_structure from c-strings
int init_vector_GCM_encryption(Vector_GCM &vect, const char *vect_name, char *key,
                                const char *plaintext, char *aad, char *iv) {
  if (strlen(key) != (vect.keysize*2)) {
    log("Key must have " + String(vect.keysize) + " bytes\n");
    return -1;
  }
  if (strlen(aad) != (vect.authsize*2)) {
    log("AAD must have " + String(vect.authsize) + " bytes\n");
    return -1;                 
  }
  if (strlen(iv) != (vect.ivsize*2)) {
    log("IV must have " + String(vect.ivsize) + " bytes\n");
    return -1;                       
  }  
  vect.name = vect_name;  // init vector name  
  c_string_hexbytes_2_bytes(key, vect.key);   // array passed by ref  
  vect.datasize = strlen(plaintext);          // init plaintext
  for (unsigned int i=0; i<vect.datasize; i++) {   
    vect.plaintext[i] = mytext[i];
    yield();
  } 
  c_string_hexbytes_2_bytes(aad, vect.authdata); // array passed by ref  
  c_string_hexbytes_2_bytes(iv, vect.iv); // array passed by ref    
  return 0;
}

void decrypt_text(Vector_GCM &vect) { 
  GCM<AES128> *gcmaes128 = 0; 
  gcmaes128 = new GCM<AES128>();
  gcmaes128->setKey(vect.key, gcmaes128->keySize());
  gcmaes128->setIV(vect.iv, vect.ivsize);
  gcmaes128->decrypt(vect.plaintext, vect.ciphertext, vect.datasize);
  delete gcmaes128;
}
#endif // USE_AES128_GCM
