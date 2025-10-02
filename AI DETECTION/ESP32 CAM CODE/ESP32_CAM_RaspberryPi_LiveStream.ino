/*
  ESP32-CAM AI Thinker - Live Streaming + Configurable Snapshot to Raspberry Pi

  Features:
  1. Live MJPEG Streaming: http://<ESP32_IP>/
  2. Configurable snapshot interval via Serial Monitor
  3. Raspberry Pi ON/OFF simulation mode
  4. Safe handling to prevent consecutive snapshot failures
*/

#include "esp_camera.h"
#include <WiFi.h>
#include <HTTPClient.h>
#include "esp_http_server.h"
#include "soc/soc.h"
#include "soc/rtc_cntl_reg.h"

// ---------------- User settings ----------------
const char* ssid = "cam";               
const char* password = "12345678";     
const char* raspberryPiServer = "http://<RPI_IP>:5000/upload";

#define PART_BOUNDARY "123456789000000000000987654321"
#define CAMERA_MODEL_AI_THINKER

// ---------------- Camera pin definitions ----------------
#define PWDN_GPIO_NUM     32
#define RESET_GPIO_NUM    -1
#define XCLK_GPIO_NUM      0
#define SIOD_GPIO_NUM     26
#define SIOC_GPIO_NUM     27
#define Y9_GPIO_NUM       35
#define Y8_GPIO_NUM       34
#define Y7_GPIO_NUM       39
#define Y6_GPIO_NUM       36
#define Y5_GPIO_NUM       21
#define Y4_GPIO_NUM       19
#define Y3_GPIO_NUM       18
#define Y2_GPIO_NUM        5
#define VSYNC_GPIO_NUM    25
#define HREF_GPIO_NUM     23
#define PCLK_GPIO_NUM     22

// ---------------- MJPEG stream definitions ----------------
static const char* _STREAM_CONTENT_TYPE = "multipart/x-mixed-replace;boundary=" PART_BOUNDARY;
static const char* _STREAM_BOUNDARY = "\r\n--" PART_BOUNDARY "\r\n";
static const char* _STREAM_PART = "Content-Type: image/jpeg\r\nContent-Length: %u\r\n\r\n";

httpd_handle_t stream_httpd = NULL; // HTTP server handle

// ---------------- Global variables ----------------
bool sendToPi = true;                    
unsigned long previousMillis = 0;
unsigned long snapshotInterval = 120000; // Default 2 minutes in milliseconds
bool snapshotBusy = false;                // Prevent overlapping snapshots

// ---------------- Function to send image to Raspberry Pi ----------------
void sendToRaspberryPi(uint8_t *img_buf, size_t len){
  if(WiFi.status() == WL_CONNECTED){
    HTTPClient http;
    http.begin(raspberryPiServer);           
    http.addHeader("Content-Type", "image/jpeg"); 

    int httpResponseCode = http.POST(img_buf, len); 
    if(httpResponseCode == 200){
      Serial.println("Image received by Raspberry Pi ✅"); 
    } else {
      Serial.printf("Failed to send image. Response code: %d\n", httpResponseCode);
    }

    http.end(); 
  } else {
    Serial.println("WiFi disconnected!");
  }
}

// ---------------- Handler for single snapshot via HTTP GET /capture ----------------
static esp_err_t capture_handler(httpd_req_t *req){
    camera_fb_t * fb = esp_camera_fb_get(); 
    if(!fb){
        httpd_resp_send_500(req); 
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "image/jpeg");
    httpd_resp_set_hdr(req, "Content-Disposition", "inline; filename=capture.jpg");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    httpd_resp_send(req, (const char *)fb->buf, fb->len);
    esp_camera_fb_return(fb); 
    return ESP_OK;
}

// ---------------- Handler for live MJPEG stream at / ----------------
static esp_err_t stream_handler(httpd_req_t *req){
  camera_fb_t * fb = NULL;
  esp_err_t res = ESP_OK;
  char part_buf[64];

  res = httpd_resp_set_type(req, _STREAM_CONTENT_TYPE); 
  if(res != ESP_OK) return res;

  while(true){
    fb = esp_camera_fb_get(); 
    if (!fb) {
      Serial.println("Camera capture failed");
      res = ESP_FAIL;
    } else {
      size_t fb_len = fb->len;
      size_t hlen = snprintf(part_buf, 64, _STREAM_PART, fb_len); 
      res = httpd_resp_send_chunk(req, part_buf, hlen);            
      if(res == ESP_OK) res = httpd_resp_send_chunk(req, (const char *)fb->buf, fb_len); 
      if(res == ESP_OK) res = httpd_resp_send_chunk(req, _STREAM_BOUNDARY, strlen(_STREAM_BOUNDARY)); 
      esp_camera_fb_return(fb); 
      fb = NULL;
    }
    if(res != ESP_OK) break; 
  }
  return res;
}

// ---------------- Start camera HTTP server ----------------
void startCameraServer(){
  httpd_config_t config = HTTPD_DEFAULT_CONFIG();
  config.server_port = 80;

  httpd_uri_t index_uri = {"/", HTTP_GET, stream_handler, NULL};     
  httpd_uri_t capture_uri = {"/capture", HTTP_GET, capture_handler, NULL}; 

  if (httpd_start(&stream_httpd, &config) == ESP_OK) {
      httpd_register_uri_handler(stream_httpd, &index_uri);
      httpd_register_uri_handler(stream_httpd, &capture_uri);
  }
}

// ---------------- Setup ----------------
void setup() {
  WRITE_PERI_REG(RTC_CNTL_BROWN_OUT_REG, 0); 
  Serial.begin(115200);

  // Camera configuration
  camera_config_t config;
  config.ledc_channel = LEDC_CHANNEL_0;
  config.ledc_timer = LEDC_TIMER_0;
  config.pin_d0 = Y2_GPIO_NUM;
  config.pin_d1 = Y3_GPIO_NUM;
  config.pin_d2 = Y4_GPIO_NUM;
  config.pin_d3 = Y5_GPIO_NUM;
  config.pin_d4 = Y6_GPIO_NUM;
  config.pin_d5 = Y7_GPIO_NUM;
  config.pin_d6 = Y8_GPIO_NUM;
  config.pin_d7 = Y9_GPIO_NUM;
  config.pin_xclk = XCLK_GPIO_NUM;
  config.pin_pclk = PCLK_GPIO_NUM;
  config.pin_vsync = VSYNC_GPIO_NUM;
  config.pin_href = HREF_GPIO_NUM;
  config.pin_sscb_sda = SIOD_GPIO_NUM;
  config.pin_sscb_scl = SIOC_GPIO_NUM;
  config.pin_pwdn = PWDN_GPIO_NUM;
  config.pin_reset = RESET_GPIO_NUM;
  config.xclk_freq_hz = 20000000;
  config.pixel_format = PIXFORMAT_JPEG; 

  if(psramFound()){
    config.frame_size = FRAMESIZE_VGA;
    config.jpeg_quality = 15;
    config.fb_count = 2;
  } else {
    config.frame_size = FRAMESIZE_VGA;
    config.jpeg_quality = 20;
    config.fb_count = 1;
  }

  if(esp_camera_init(&config) != ESP_OK){
    Serial.println("Camera init failed!");
    ESP.restart();
  }

  // Connect to Wi-Fi
  WiFi.begin(ssid, password);
  while(WiFi.status() != WL_CONNECTED){
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nWiFi connected!");
  Serial.printf("ESP32-CAM IP: %s\n", WiFi.localIP().toString().c_str());

  startCameraServer(); 
}

// ---------------- Loop ----------------
void loop() {
  unsigned long currentMillis = millis();

  // --------- Serial commands: ON / OFF / TIME <seconds> ---------
  if(Serial.available() > 0){
    String command = Serial.readStringUntil('\n');
    command.trim();

    if(command.equalsIgnoreCase("OFF")){ 
      sendToPi = false;
      Serial.println("✅ Raspberry Pi sending DISABLED");
    } 
    else if(command.equalsIgnoreCase("ON")){ 
      sendToPi = true;
      Serial.println("✅ Raspberry Pi sending ENABLED");
    } 
    else if(command.startsWith("TIME ")){
      String value = command.substring(5);
      int seconds = value.toInt();
      if(seconds > 0){
        snapshotInterval = (unsigned long)seconds * 1000;
        Serial.printf("⏱ Snapshot interval changed to %d seconds\n", seconds);
      } else {
        Serial.println("⚠ Invalid time. Use TIME <seconds>");
      }
    }
    else {
      Serial.println("⚠ Invalid command. Type ON, OFF, or TIME <seconds>");
    }
  }

  // --------- Capture snapshot based on interval ---------
  if(!snapshotBusy && currentMillis - previousMillis >= snapshotInterval){
    snapshotBusy = true;
    previousMillis = currentMillis;

    camera_fb_t * fb = esp_camera_fb_get(); 
    if(fb){
      if(sendToPi){
        sendToRaspberryPi(fb->buf, fb->len); 
      } else {
        Serial.println("Snapshot captured ✅ (Raspberry Pi OFF)");
      }
      esp_camera_fb_return(fb); 
      delay(100); // Small delay to prevent consecutive frame failure
    } else {
      Serial.println("Failed to capture frame.");
    }

    snapshotBusy = false;
  }

  delay(1); // Keep loop responsive
}