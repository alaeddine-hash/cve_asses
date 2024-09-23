import asyncio
from datetime import datetime
from decimal import Decimal
import aiohttp
import os
import json
from bs4 import BeautifulSoup
from langchain_openai import ChatOpenAI

from get_cve import get_filtered_cves


def default_serializer(obj):
    """ Custom serializer to handle non-serializable objects like datetime and Decimal """
    if isinstance(obj, datetime):
        return obj.isoformat()  # Convert datetime to ISO format
    elif isinstance(obj, Decimal):
        return float(obj)  # Convert Decimal to float for JSON serialization
    raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")



def extract_advisory_links(cve):
    advisory_links = []
    references_field = cve.get('references', '[]')  # Get the 'references' field, default to empty list string
    try:
        # Parse the 'references' field as JSON
        references = json.loads(references_field)
        # Extract URLs from the references
        for ref in references:
            url = ref.get('url')
            if url:
                advisory_links.append(url)
    except json.JSONDecodeError as e:
        print(f"Error parsing references for CVE ID {cve['cve_id']}: {e}")
    return advisory_links

async def scrape_urls(urls):
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_url(session, url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results

async def fetch_url(session, url):
    try:
        async with session.get(url, timeout=15) as response:
            if response.status == 200:
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                text_content = soup.get_text(separator='\n', strip=True)
                return {'url': url, 'content': text_content}
            else:
                return {'url': url, 'content': f'Failed to fetch: {response.status}'}
    except Exception as e:
        return {'url': url, 'content': str(e)}



def create_prompt_for_cve_augmentation(cve):
    prompt = f"""
You are a cybersecurity analyst with expertise in vulnerability assessment. Your task is to analyze the following CVE details and advisory contents to extract specific information.
Identify the operating systems affected directly or indirectly by this vulnerability.(if it is component that affect a library or a framework you put the os whoes can hundle (run) it )

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
   - The name of the operating system affected by the vulnerability.((if it is component that affect a library or a framework you put the os whoes can hundle (run) it )Please ensure you specify a known OS. Be certain about this.)
   - If multiple operating systems are affected, list them as an array.
   - If not applicable or not specified, set to `null`.

2. **Operating System Version(s) (os_version):**
   - The version(s) of the operating system affected.(Note: Do not mistake this for the component version.)
   - List them as an array.
   - If not applicable or not specified, set to `null`.


**Output Format:**

Provide your response in valid JSON format with the following structure:

```json
{
  "os_name": ["Operating System Name(s)"] or null,
  "os_version": ["Operating System Version(s)"] or null
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
        # Initialize the LLM
        llm = ChatOpenAI(
            model_name='gpt-4o-mini',  # Or 'gpt-3.5-turbo'
            temperature=0.0,
        )

        # Get the response from the LLM
        response = llm.invoke(prompt)
        output_text = response.content.strip()

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
            cve['advisory_contents'] = ' '
            print(f"Augmented CVE Data:")
            print(f"  OS Name: {cve['os_name']}")
            print(f"  OS Version: {cve['os_version']}")
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
    cves = get_filtered_cves(2024, 2024, 100)  # Adjust the parameters as needed
    n = 90  # Number of CVEs to skip
    cves = cves[n:]  # Remove the first n CVEs
    
    for cve in cves:
        augmented_cve = process_cve_augmentation(cve)
        if augmented_cve:
            cves_augmented.append(augmented_cve)
            # Rate limiting: sleep for a random period between requests to avoid hitting the API rate limit
        # Optionally, save the augmented CVEs to a file or database
        with open('cves_augmented_gpt_2024_10.json', 'w') as f:
             json.dump(cves_augmented, f, indent=2, default=default_serializer)

        print("Completed processing CVEs for os and affected component with versions extracted.")

    # Optionally, save the augmented CVEs to a file or database
    # with open('augmented_cves.json', 'w') as f:
    #     json.dump(cves, f, indent=2)


if __name__ == "__main__" :
    main()