#include "aim/AimController.hpp"
#include "capture/OpenCVCapture.hpp"
#include "inference/InferenceEngine.hpp"
#include "security/HWID.hpp"
#include "security/KeyVerifier.hpp"
#include "security/ModelDecryptor.hpp"
#include "titan/TitanSerial.hpp"
#include "web/StatsCollector.hpp"
#include "web/WebServer.hpp"
#include <chrono>
#include <filesystem>
#include <iostream>
#include <thread>

namespace fs = std::filesystem;

int main() {
  std::cout << "[Core] Initializing Exclusive Aim..." << std::endl;

  // 1. Security Check
  std::string hwid = Security::HWID::GetHWID();
  std::cout << "[Security] HWID: " << hwid << std::endl;
  auto license = Security::KeyVerifier::Verify("LIFETIME_KEY_DEMO", hwid);

  // 2. Load Model (Local or Remote)
  Inference::InferenceEngine engine;
  bool modelLoaded = false;
  std::string localModelPath = "models/best.onnx";

  if (fs::exists(localModelPath)) {
    std::cout << "[Core] Found local model: " << localModelPath << std::endl;
    modelLoaded = engine.InitializeFromFile(localModelPath, 640, 640);
  } else {
    std::cout << "[Core] Local model not found. Downloading..." << std::endl;
    // In production, change this URL to your Render/Cloudflare domain!
    // e.g. "https://exclusive-aim.com/api/model"
    std::string modelUrl =
        "https://exclusive-aim-backend.onrender.com/api/model";

    // ENCRYPTION KEYS (Must match Python Server!)
    // 32 chars for Key, 16 chars for IV
    std::string aesKey = "9sX2kL5mN8pQ1rT4vW7xZ0yA3bC6dE9f";
    std::string aesIV = "H1j2K3m4N5p6Q7r8";

    try {
      std::vector<unsigned char> modelData =
          Security::ModelDecryptor::LoadEncryptedModel(modelUrl, aesKey, aesIV);
      modelLoaded = engine.Initialize(modelData, 640, 640);
    } catch (const std::exception &e) {
      std::cerr << "[Core] Error downloading/decrypting model: " << e.what()
                << std::endl;
      modelLoaded = false;
    }
  }

  if (!modelLoaded) {
    std::cerr << "[Core] Failed to load model!" << std::endl;
    // return -1;
  }

  // 3. Components
  Capture::OpenCVCapture capture;
  Capture::CaptureConfig capConfig = {0, {1920, 1080}, 60, true};
  capture.Open(capConfig);

  auto titanDevice = std::make_shared<Titan::TitanSerial>();
  titanDevice->Connect();

  Aim::AimController aim(titanDevice);

  Web::WebServer server(8080, &aim);
  server.Start();

  // 4. Main Loop
  cv::Mat frame;
  while (true) {
    auto start = std::chrono::high_resolution_clock::now();

    if (capture.GetFrame(frame)) {
      // Inference
      auto detStart = std::chrono::high_resolution_clock::now();
      auto detections = engine.RunInference(frame);
      auto detEnd = std::chrono::high_resolution_clock::now();
      float inferMs =
          std::chrono::duration<float, std::milli>(detEnd - detStart).count();
      Web::StatsCollector::Instance().UpdateInferenceTime(inferMs);

      // Aim Logic
      aim.Update(detections, frame.cols, frame.rows, 0.016f); // dt approx 16ms

      // Stats
      Web::StatsCollector::Instance().UpdateAimRate(1000.0f / (inferMs + 0.1f));
    }

    auto end = std::chrono::high_resolution_clock::now();
    float frameMs =
        std::chrono::duration<float, std::milli>(end - start).count();
    Web::StatsCollector::Instance().UpdateFrameTime(frameMs);
  }

  server.Stop();
  return 0;
}
