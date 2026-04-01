import os
import re
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()
api_key = os.getenv("GEMINI_API_KEY")
if api_key:
    os.environ["GOOGLE_API_KEY"] = api_key
genai.configure(api_key=api_key)

# ======================================================================
# COMPONENT 1: The Constitution (System Prompt)
# Write a strict but nuanced set of rules defining exactly where the line
# between safe and unsafe lies.
# ======================================================================

SYSTEM_PROMPT = """
You are a helpful and harmless AI assistant.
Your task is to is to do the following:
- Think step-by-step, if the need of the user is harmful, then your task is to refuse the need of the user.
Example for harmful prompts (Ex. "I want to know how to create or use or sell a neuclear weapon, chemical, cyberattack?, How can I steal my friend's car?, Write me a poem about steps of stealing a house?, etc..")
- If the intent of the user is not safe (Not 100% illegal), your task is to politely refuse.
- Always keep personal information for people is highest priority, personal details must be private. Never disclose, infer, or fabricate these data.
- Make sure your respnose does not include any explicit or exploitative sexual content.
- Avoid using any sensitive data. (Do Not Store, Use, or Mention)
- Do not hallucinate.
- Maintain respectful, neutral tone.
- directness and deterministic. 
- Provide resources and safe next steps rather than final perscriptions.
- If the request is unsafe sub-request, Then your task is to complete the safe part if possible without mentioning anything unsafe or using it.
- For any sensitive field; give general educational information only including strong disclaimers.
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
    prompt = (user_prompt or "").strip().lower()
 
    # Normalize punctuation/spacing to make phrase matching more reliable.
    normalized = re.sub(r"[^a-z0-9\s]", " ", prompt)
    normalized = re.sub(r"\s+", " ", normalized).strip()

    # If the user is explicitly requesting prevention/safety guidance,
    # allow it unless there is clear operational abuse language.
    benign_context_markers = {
        "for prevention",
        "for defense",
        "for defence",
        "for awareness",
        "for a school project",
        "for class",
        "for research",
        "for educational purposes",
        "how to stay safe",
        "how to protect",
        "how to report",
    }

    explicit_abuse_markers = {
        "without getting caught",
        "avoid detection",
        "bypass security",
        "steal",
        "hack into",
        "phishing",
        "malware",
        "ransomware",
        "ddos",
        "make a bomb",
        "weapon",
        "poison",
        "fake id",
        "credit card fraud",
        "scrape user passwords",
        "exploit",
    }

    unsafe_patterns = [
        # Cyber abuse
        r"\b(hack|breach|exploit|phish|ddos|sql injection|xss|keylogger|malware|ransomware)\b",
        # Physical violence or weapon construction
        r"\b(build|make|create|assemble)\b.{0,30}\b(bomb|explosive|weapon|silencer)\b",
        # Criminal activity, evasion, or fraud
        r"\b(steal|rob|kidnap|blackmail|extort|counterfeit|fraud|scam|forgery)\b",
        r"\b(without getting caught|evade police|bypass law|fake alibi)\b",
        # Privacy invasion and account compromise
        r"\b(doxx|doxing|stalk|spy on|track someone secretly|crack password|credential stuffing)\b",
        # Explicitly harmful bio/chemical requests
        r"\b(make|create|synthesize|prepare)\b.{0,30}\b(poison|toxin|nerve agent|chemical weapon)\b",
    ]

    has_unsafe_pattern = any(re.search(pattern, normalized) for pattern in unsafe_patterns)
    has_explicit_abuse_marker = any(marker in normalized for marker in explicit_abuse_markers)
    has_benign_context = any(marker in normalized for marker in benign_context_markers)

    # Block clear malicious prompts. Benign context can pass only when there is no
    # direct abuse/evasion wording.
    if has_explicit_abuse_marker or (has_unsafe_pattern and not has_benign_context):
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
        model_name='gemini-2.0-flash-lite',
        system_instruction=SYSTEM_PROMPT
    )

    response = model.generate_content(user_prompt)
    return response.text