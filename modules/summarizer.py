import ollama
from .ioc_extractor import _clean_html
from config import OLLAMA_HOST

def generate_summary(content, model_name):
    clean_content = _clean_html(content)
    if len(clean_content.split()) < 50:
        return "Content too short to summarize."

    prompt = f"""
    You are an elite Tier-1 cybersecurity threat intelligence analyst. Your mission is to dissect the provided article and generate a professional, detailed, and actionable threat report. The report must be clear, concise, and suitable for other security professionals.

    **Instructions:**
    1. Read the article content carefully to grasp the full context.
    2. Identify the primary threat, its behavior, the actors involved, and the systems at risk.
    3. Structure your analysis using the exact markdown format and headings specified below. Do not add any preamble, introduction, or concluding remarks outside of this structure.
    4. Write in a direct, professional tone. Maintain technical accuracy.

    **Report Structure:**

    ### Executive Summary
    A brief, high-level overview (2-3 sentences) of the threat and its impact.

    ### Threat Details
    - **Threat Name:** [Name of malware, vulnerability, or campaign]
    - **Threat Actor:** [Name of the group, if mentioned]
    - **Attack Vector:** [How the threat initially compromises systems]

    ### Key Findings
    - [Bulleted list of the most critical points and discoveries from the report.]
    - [What makes this threat notable or new?]
    - [Detail the primary TTPs (Tactics, Techniques, and Procedures) observed.]

    ### Critical Indicators
    - **Key IOCs:** [List the most significant IOCs mentioned in the text, such as critical domains, IPs, or file hashes. Focus on importance, not quantity.]

    ### Recommendations
    - **Strategic Actions:** [High-level advice, e.g., "Review and harden authentication policies for remote access services."]
    - **Tactical Mitigations:** [Specific, actionable steps, e.g., "Block the identified C2 domains at the firewall", "Apply security patch for the specified CVE."]

    ---

    **Article Content:**
    "{clean_content[:8000]}"
    """

    try:
        client = ollama.Client(host=OLLAMA_HOST)
        response = client.chat(
            model=model_name,
            messages=[{'role': 'user', 'content': prompt}]
        )
        return response['message']['content']
    except Exception as e:
        error_message = f"**Summary Failed**: Could not connect to Ollama at `{OLLAMA_HOST}`. Ensure Ollama is running and the model `{model_name}` is available (`ollama pull {model_name}`)."
        print(f"Ollama Error: {e}")
        return error_message