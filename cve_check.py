import asyncio
from decimal import Decimal
import json
from langchain_openai import ChatOpenAI

from get_cve import get_filtered_cves
from on_the_moon import extract_advisory_links, scrape_urls

import google.generativeai as genai
import os
from datetime import datetime

genai.configure(api_key=os.environ["API_KEY"])
model = genai.GenerativeModel("gemini-1.5-flash")




def create_prompt_for_exploitability_metrics(cve):
    cvss_vector_v3 = cve.get('cvss_vector_v3')
    if not cvss_vector_v3:
        print(f"No CVSS vector available for CVE ID {cve['cve_id']}. Skipping.")
        return None  # No CVSS vector available

    prompt = f"""
You are a cybersecurity analyst with expertise in CVSS scoring and vulnerability assessment. Your task is to analyze the following CVE, focusing on the exploitability metrics in its CVSS vector.

**CVE Details:**

- **CVE ID:** {cve['cve_id']}
- **Description:** {cve['description']}
- **CVSS Vector V3:** {cvss_vector_v3}

**Advisory Contents:**
"""
    # Include advisory contents if available
    for advisory in cve.get('advisory_contents', []):
        prompt += f"\n- **URL:** {advisory['url']}\n**Content:**\n{advisory['content']}\n"

    prompt += """

**Instructions:**

1. **Extract the exploitability metrics from the provided CVSS vector. The exploitability metrics are:**

    - **Attack Vector (AV)**
    - **Attack Complexity (AC)**
    - **Privileges Required (PR)**
    - **User Interaction (UI)**
    - **Scope (S)**

2. **For each metric:**

    - **Provide the value from the CVSS vector.**
    - **Explain what this value indicates about the exploitability of the vulnerability.**
    - **Assess whether the value is appropriate given the description of the CVE. If there is any discrepancy, explain it.**

3. **Provide an overall assessment of the exploitability of the vulnerability based on the metrics and the CVE description.**

**Output Format:**

Provide your response in valid JSON format as follows (do not include any code block delimiters or language specifiers):

{{
  "cve_id": "{cve['cve_id']}",
  "exploitability_metrics": {{
    "AV": {{
      "value": "Value from CVSS vector",
      "description": "Explanation of AV",
      "assessment": "Appropriate/Inappropriate",
      "remarks": "Any additional remarks if needed"
    }},
    "AC": {{
      "value": "Value from CVSS vector",
      "description": "Explanation of AC",
      "assessment": "Appropriate/Inappropriate",
      "remarks": "Any additional remarks if needed"
    }},
    "PR": {{
      "value": "Value from CVSS vector",
      "description": "Explanation of PR",
      "assessment": "Appropriate/Inappropriate",
      "remarks": "Any additional remarks if needed"
    }},
    "UI": {{
      "value": "Value from CVSS vector",
      "description": "Explanation of UI",
      "assessment": "Appropriate/Inappropriate",
      "remarks": "Any additional remarks if needed"
    }},
    "S": {{
      "value": "Value from CVSS vector",
      "description": "Explanation of S",
      "assessment": "Appropriate/Inappropriate",
      "remarks": "Any additional remarks if needed"
    }}
  }},
  "overall_assessment": "Overall assessment of exploitability",
  "remarks": "Any additional remarks or conclusions"
}}

**Important Guidelines:**

- **Do not include** any explanations or text outside the JSON object.
- **Provide only** the JSON object.
- **Ensure** the JSON is properly formatted and parsable.
"""
    return prompt


def default_serializer(obj):
    """ Custom serializer to handle non-serializable objects like datetime and Decimal """
    if isinstance(obj, datetime):
        return obj.isoformat()  # Convert datetime to ISO format
    elif isinstance(obj, Decimal):
        return float(obj)  # Convert Decimal to float for JSON serialization
    raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")

def process_cve_exploitability_metrics(cve):
    print(f"Processing CVE ID: {cve['cve_id']}")
    
    # Extract advisory links
    references = extract_advisory_links(cve)
    # Scrape the advisory contents
    try:
        cve['advisory_contents'] = asyncio.run(scrape_urls(references))
    except Exception as e:
        print(f"Error during advisory scraping: {e}")
        cve['advisory_contents'] = []

    # Create the prompt
    prompt = create_prompt_for_exploitability_metrics(cve)
    if not prompt:
        return None  # Skip if no prompt (e.g., CVSS vector missing)

    # Call the LLM
    try:
        # Initialize the LLM
        """ llm = ChatOpenAI(
            model_name='gpt-4o',
            temperature=0.0,
        )

        # Get the response from the LLM
        response = llm.invoke(prompt) """
        response = model.generate_content(prompt)
        # output_text = response.content.strip()
        output_text = response.text.strip()
        # Clean the output_text by removing code block delimiters and language specifiers
        output_text = output_text.strip()
        if output_text.startswith('```'):
            output_text = output_text.strip('`')
            # Remove the language specifier if present
            if output_text.startswith('json'):
                output_text = output_text[4:].strip()

        # Parse the JSON output
        try:
            output_text = output_text.replace('{{', '{').replace('}}', '}')
            result = json.loads(output_text)
            # Update the CVE with new attributes
            cve['exploitability_metrics'] = result.get('exploitability_metrics')
            cve['overall_assessment'] = result.get('overall_assessment')
            cve['remarks'] = result.get('remarks')
            print(f"Exploitability Metrics for CVE ID {cve['cve_id']}:")
            print(json.dumps(result['exploitability_metrics'], indent=2, default=default_serializer))
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON response for CVE ID {cve['cve_id']}: {e}")
            print("LLM Output:")
            print(output_text)
            return None  # Skip further processing if parsing fails

        return cve  # Return the augmented CVE

    except Exception as e:
        print(f"Error during LLM processing for CVE ID {cve['cve_id']}: {e}")
        return None


def main():
    cves_with_exploitability = []
    cves = get_filtered_cves(2024, 2024, 20)  # Adjust the parameters as needed
    n = 5  # Number of CVEs to skip
    cves = cves[n:]  # Remove the first n CVEs
    print(cves.count)
    for cve in cves:
        augmented_cve = process_cve_exploitability_metrics(cve)
        if augmented_cve:
            cves_with_exploitability.append(augmented_cve)

    # Optionally, save the augmented CVEs to a file or database
    with open('cves_with_exploitability_1.json', 'w') as f:
        json.dump(cves_with_exploitability, f, indent=2, default=default_serializer)

    print("Completed processing CVEs for exploitability metrics.")



if __name__ == "__main__":
    main()
