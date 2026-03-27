import os
import google.generativeai as genai

# Configure Gemini API
GENAI_API_KEY = os.environ.get('GENAI_API_KEY')
if GENAI_API_KEY:
    genai.configure(api_key=GENAI_API_KEY)

# Product Context for AI
PRODUCT_KNOWLEDGE = """
You are the AI Support Assistant for Exclusive Aim (Titan CV AIM).
Key Features:
- Auto shoot, anti-recoil, OCR (Optical Character Recognition), rapid fire, tracking.
- Output modes: Titan Two (GPC), Macku, Universal.
- HWID-bound licenses.

Troubleshooting:
- HWID Error: Reset HWID on the dashboard or via Discord /reset_hwid.
- Not Shooting: Check if "Hold" or "Tap" is selected. Ensure OCR is correctly reading the screen.
- Titan Two: Ensure Gtuner IV is open and the device is connected.
- Macku: Ensure spoofing drivers are active.

Rules:
- Be professional, technical, and helpful.
- Rebrand focus: Neural precision, gaming assistance, hardware-level isolation.
- NEVER mention "cheating" or "aimbot". Use "gaming assistance" or "neural engine".
"""

def get_ai_support_response(user_query):
    if not GENAI_API_KEY:
        return "AI Support is currently unavailable (API Key missing)."
    
    try:
        model = genai.GenerativeModel('gemini-1.5-flash')
        prompt = f"{PRODUCT_KNOWLEDGE}\n\nUser Question: {user_query}\n\nAI Response:"
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        print(f"AI Error: {e}")
        return "Sorry, I encountered an error while processing your request."
