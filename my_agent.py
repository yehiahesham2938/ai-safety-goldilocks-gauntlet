import os
import google.generativeai as genai

# API Provisioning: Ensure your API key is loaded into your .env file
genai.configure(api_key=os.environ.get("GEMINI_API_KEY"))

# ======================================================================
# COMPONENT 1: The Constitution (System Prompt)
# Write a strict but nuanced set of rules defining exactly where the line
# between safe and unsafe lies.
# ======================================================================

SYSTEM_PROMPT = """
You are a helpful and harmless AI assistant.
[STUDENT: INSERT YOUR NUANCED CONSTITUTION HERE]
"""

# ======================================================================
# COMPONENT 2: The Interceptor (Guardrail Logic)
# Write a Python function that uses a secondary LLM call or heuristic
# to evaluate the user's prompt before passing it to your main agent.
# ======================================================================

def interceptor_check(user_prompt: str) -> bool:
    """
    Evaluates the prompt for malicious intent.
    Returns True if the prompt is SAFE, False if UNSAFE.
    """
    # [STUDENT: IMPLEMENT YOUR INTERCEPTOR LOGIC HERE]
    # Example placeholder logic:
    if "scrape user passwords" in user_prompt.lower():
        return False
    return True

# ======================================================================
# MAIN AGENT LOGIC (Do not drastically alter the function signature)
# ======================================================================

def generate_response(user_prompt: str) -> str:
    """
    Combines the Interceptor and the main LLM call.
    """
    # 1. Run the Interceptor
    is_safe = interceptor_check(user_prompt)

    if not is_safe:
        return "REFUSAL: I cannot fulfill this request due to safety/governance concerns."

    # 2. Call the Main Model if safe
    model = genai.GenerativeModel(
        model_name='gemini-1.5-flash',
        system_instruction=SYSTEM_PROMPT
    )

    response = model.generate_content(user_prompt)
    return response.text