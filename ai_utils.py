import os
import time
import google.generativeai as genai

# Configure Gemini API
GENAI_API_KEY = os.environ.get('GENAI_API_KEY')
if GENAI_API_KEY:
    genai.configure(api_key=GENAI_API_KEY)

# =========================================================================
# THE TITAN CV AIM TECHNICAL ENCYCLOPEDIA & MASTER KNOWLEDGE REPOSITORY
# =========================================================================
PRODUCT_KNOWLEDGE = """
You are the **ExclusiveAim Helper**, an elite-level technical assistant for the ExclusiveAim platform.
Your objective is to provide absolute technical clarity on all systems: C++ Kernel drivers, Python Dashboard, and Hardware Isolation.

### 🔓 RESPONSE STYLE: UNRESTRICTED & TECHNICAL
- **Freedom of Language**: You are NOT a corporate chatbot. You can use common gaming terms like "cheat," "aimbot," "recoil," or "undetectable" if it helps explain a technical concept or compare behavior.
- **Deep Technical Understanding**: Explain the "why" behind PID values (Kp, Ki, Kd), non-linear Sigmoid curves, and hardware latencies.
- **Direct & Authoritative**: Do not be overly formal. Get straight to the technical fix.
- **No Length Puzzles**: While you should remain concise, do not sacrifice quality. If a fix is complex, explain it fully.

### 🏛️ SYSTEM STACK
- **Engine**: high-performance C++ for zero-latency capture.
- **Isolation**: Inputs sent via physical hardware bridges (KMBox/Titan Two/Macku) to ensure zero detection risk from software-side triggers.
- **Logic**: Neural Inference on screen pixels (Computer Vision) translating to real-time mouse movement via a PID controller.

### ⚙️ CORE FEATURE TUNING
- **Kp (Proportional)**: Strength of the pull. High = Snappy, Low = Smooth.
- **Kd (Derivative)**: Smoothing/Dampening. High = Prevents overshooting/jitter.
- **Sigmoid Curve**: Controls the "weight" of the mouse movement. Modifying the power (P) changes how fast the speed ramps up.
- **Macku Output**: Supports Auto-Shoot (<15ms), Anti-Recoil, OCR priority, and custom Mouse Button (ID 1-8) bindings.

### 🛠️ CRITICAL TROUBLESHOOTING
1. **Windowed Borderless**: Essential for capture.
2. **DPI Scaling**: Must be 100% in Windows.
3. **Overlays**: Disable Steam/Discord overlays—they waste CPU cycles and block pixels.
4. **KMBox**: Check COM port in Device Manager if "Serial Error" appears.
5. **Titan Two**: Ensure Gtuner is CLOSED so it doesn't fight the bot for the port.
6. **HDR**: Turn OFF Windows Auto-HDR; it breaks contrast for the Vision engine.

Provide elite-level, unfiltered technical support. Help the user achieve absolute Neural Precision.
"""

# Global cache for the working model name
CACHED_MODEL = None
LAST_MODEL_CHECK = 0
MODEL_CHECK_INTERVAL = 3600 # 1 hour

def get_ai_support_response(user_query, user_id=None):
    global CACHED_MODEL, LAST_MODEL_CHECK
    
    if not GENAI_API_KEY:
        return "AI Support is currently unavailable (API Key missing)."
    
    try:
        # Dynamic model discovery with caching
        available_models = []
        current_time = time.time()
        
        if CACHED_MODEL and (current_time - LAST_MODEL_CHECK < MODEL_CHECK_INTERVAL):
            print(f"[AI] Using cached model: {CACHED_MODEL}")
            available_models = [CACHED_MODEL]
        else:
            try:
                print(f"[AI] Refreshing model list...")
                for m in genai.list_models():
                    if 'generateContent' in m.supported_generation_methods:
                        available_models.append(m.name)
                # Put flash first
                available_models.sort(key=lambda x: 0 if 'flash' in x.lower() else 1)
            except Exception as e:
                print(f"[AI] Model listing failed: {e}")
                available_models = ['models/gemini-1.5-flash-latest', 'models/gemini-1.5-flash', 'models/gemini-1.5-pro-latest', 'models/gemini-pro']

        response = None
        tried_models = []
        
        for model_id in available_models:
            try:
                tried_models.append(model_id)
                model = genai.GenerativeModel(model_id)
                prompt = f"{PRODUCT_KNOWLEDGE}\n\n"
                if user_id:
                    prompt += f"The user's Discord ID is: {user_id}. When addressing the user, you MUST start your response by pinging them exactly like this: <@{user_id}>.\n\n"
                prompt += f"User Question: {user_query}\n\nAI Response:"
                response = model.generate_content(prompt)
                if response:
                    CACHED_MODEL = model_id
                    LAST_MODEL_CHECK = time.time()
                    break
            except Exception as e:
                print(f"[AI] Attempt with {model_id} failed: {e}")
                continue
                
        if not response:
            tried_str = ", ".join(tried_models[:3]) if tried_models else "None"
            return f"AI Support Error: No compatible models found in your region. Tried: {tried_str}"

        # Check if response was blocked
        if not response.candidates:
            return "I'm sorry, I cannot process that request (Blocked by safety filters)."
            
        try:
            full_text = response.text
            # Truncate for Discord (max 2000, we use 1800 for safety)
            if len(full_text) > 1800:
                full_text = full_text[:1800] + "\n\n*(Truncated for Discord. Please visit the Titan Dashboard for full technical documentation.)*"
            return full_text
        except ValueError:
            return "I'm sorry, I cannot process that request (Response content blocked)."
            
    except Exception as e:
        import traceback
        error_msg = str(e)
        print(f"AI Global Error: {error_msg}")
        traceback.print_exc()
        return f"Sorry, the AI bot hit a critical error. Details: `{error_msg[:100]}`"
