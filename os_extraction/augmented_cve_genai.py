import asyncio
from decimal import Decimal
import random
import time
import aiohttp
import os
import json
from bs4 import BeautifulSoup
from langchain_openai import ChatOpenAI

from get_cve import get_filtered_cves
from on_the_moon import extract_advisory_links, scrape_urls
import google.generativeai as genai
import os
from datetime import datetime



genai.configure(api_key=os.environ["API_KEY"])
model = genai.GenerativeModel("gemini-1.5-flash")


def default_serializer(obj):
    """ Custom serializer to handle non-serializable objects like datetime and Decimal """
    if isinstance(obj, datetime):
        return obj.isoformat()  # Convert datetime to ISO format
    elif isinstance(obj, Decimal):
        return float(obj)  # Convert Decimal to float for JSON serialization
    raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")



def create_prompt_for_cve_augmentation(cve):
    prompt = f"""
You are a cybersecurity analyst with expertise in vulnerability assessment. Your task is to analyze the following CVE details and advisory contents to extract specific information.

**CVE Details:**
"""
# Iterate over all key-value pairs in the cve dictionary
    for key, value in cve.items():
        if key != 'advisory_contents':  # Exclude advisory_contents to avoid duplication
            # Format the key to have spaces and capitalize words (e.g., 'cve_id' -> 'CVE ID')
            formatted_key = ' '.join(word.capitalize() for word in key.split('_'))
            # Handle values that are dictionaries or lists
            if isinstance(value, (dict, list)):
                value_str = json.dumps(value, indent=2)
                prompt += f"- **{formatted_key}:**\n```\n{value_str}\n```\n"
            else:
                prompt += f"- **{formatted_key}:** {value}\n"

    prompt += """
    **Advisory Contents:**
    """
    # Include advisory contents if available
    for advisory in cve.get('advisory_contents', []):
        prompt += f"\n- **URL:** {advisory['url']}\n**Content:**\n{advisory['content']}\n"

    prompt += """
**Instructions:**

From the provided information, extract the following attributes:

1. **Operating System Name (os_name):**
   - The name of the operating system affected by the vulnerability.
   - If multiple operating systems are affected, list them as an array.
   - If not applicable or not specified, set to `null`.

2. **Operating System Version(s) (os_version):**
   - The version(s) of the operating system affected.
   - List them as an array.
   - If not applicable or not specified, set to `null`.

3. **Affected Component Name (component_name):**
   - The specific software, library, or component that is vulnerable.
   - If multiple components are affected, list them as an array.
   - If not applicable or not specified, set to `null`.

4. **Affected Component Version(s) (component_version):**
   - The version(s) of the affected component.
   - List them as an array.
   - If not applicable or not specified, set to `null`.

5. **Side (side):**
   - Indicate whether the vulnerability affects the **client** side or **server** side.
   - Possible values: `"client"`, `"server"`, or `"both"`.

**Output Format:**

Provide your response in valid JSON format with the following structure:

```json
{
  "os_name": ["Operating System Name(s)"] or null,
  "os_version": ["Operating System Version(s)"] or null,
  "component_name": ["Affected Component Name(s)"] or null,
  "component_version": ["Affected Component Version(s)"] or null,
  "side": "client" | "server" | "both"
}
Important Guidelines:

Do not include any explanations, introductions, or conclusions.

Provide only the JSON object.

Do not include any code block delimiters or language specifiers.

Ensure the JSON is properly formatted and parsable. """

    return prompt

def process_cve_augmentation(cve):
    print(f"Processing CVE ID: {cve['cve_id']}")
    references = extract_advisory_links(cve)

    # Scrape the advisory contents
    try:
        cve['advisory_contents'] = asyncio.run(scrape_urls(references))
    except Exception as e:
        print(f"Error during advisory scraping: {e}")
        cve['advisory_contents'] = []

    # Create the prompt
    prompt = create_prompt_for_cve_augmentation(cve)

    # Call the LLM
    try:
        """ # Initialize the LLM
        llm = ChatOpenAI(
            model_name='gpt-4o',  # Or 'gpt-3.5-turbo'
            temperature=0.0,
        )

        # Get the response from the LLM
        response = llm.invoke(prompt)
        output_text = response.content.strip() """

        response = model.generate_content(prompt)
        # output_text = response.content.strip()
        output_text = response.text.strip()
        # Clean the output_text by removing code block delimiters and language specifiers
        #output_text = response.content.strip()

        # Clean the output_text by removing code block delimiters and language specifiers
        output_text = output_text.strip()
        if output_text.startswith('```'):
            output_text = output_text.strip('`')
            # Remove the language specifier if present
            if output_text.startswith('json'):
                output_text = output_text[4:].strip()  # Remove 'json' and any whitespace

        # Parse the JSON output
        try:
            result = json.loads(output_text)
            # Update the CVE with new attributes
            cve['os_name'] = result.get('os_name')
            cve['os_version'] = result.get('os_version')
            cve['component_name'] = result.get('component_name')
            cve['component_version'] = result.get('component_version')
            cve['side'] = result.get('side')
            print(f"Augmented CVE Data:")
            print(f"  OS Name: {cve['os_name']}")
            print(f"  OS Version: {cve['os_version']}")
            print(f"  Component Name: {cve['component_name']}")
            print(f"  Component Version: {cve['component_version']}")
            print(f"  Side: {cve['side']}")
            cve['advisory_contents'] = ' '
            return cve
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON response for CVE ID {cve['cve_id']}: {e}")
            print("LLM Output:")
            print(output_text)
    except Exception as e:
        print(f"Error during LLM processing for CVE ID {cve['cve_id']}: {e}")

    print("-" * 60)

def main():
    cves_augmented = []
    # Retrieve CVEs (replace this with your actual data retrieval method)
    cves = get_filtered_cves(2024, 2024, 1000)  # Adjust the parameters as needed

    for cve in cves:

        augmented_cve = process_cve_augmentation(cve)
        if augmented_cve:
            cves_augmented.append(augmented_cve)
            # Rate limiting: sleep for a random period between requests to avoid hitting the API rate limit
            time.sleep(random.uniform(3, 5))  # Sleep between 1 and 3 seconds
        # Optionally, save the augmented CVEs to a file or database
        with open('cves_augmented_1000.json', 'w') as f:
             json.dump(cves_augmented, f, indent=2, default=default_serializer)

        print("Completed processing CVEs for os and affected component with versions extracted.")



if __name__ == "__main__":
    main()
