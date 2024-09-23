import asyncio
import aiohttp
from langchain_openai import ChatOpenAI
import os
import json
from bs4 import BeautifulSoup

def create_prompt_cve_analyst_uploaded_config(cve):
    # Build the prompt with instructions to output in the specified format
    prompt = f"""using your browser tools
As a cybersecurity expert specializing in vulnerability assessment and familiar with the Common Vulnerability Scoring System (CVSS) version 3.1, your task is to reassess the provided CVE based on its details and advisory links. You will perform a deep analysis of the vulnerability and determine the correct CVSS v3.1 base score and vector, ensuring accuracy in each metric according to the CVSS v3.1 specification.

CVE Details:
CVE ID: {cve['cve_id']}
Description: {cve['description']}

Advisory Contents:
"""
    # Include advisory contents if available
    for advisory in cve.get('advisory_contents', []):
        prompt += f"\nURL: {advisory['url']}\nContent: {advisory['content']}\n"

    prompt += """
Instructions:

Read and Comprehend the CVE Details:

- Carefully read the CVE description and all advisory links provided.
- Understand the nature of the vulnerability, including:
  - How it occurs.
  - How it can be exploited.
  - The potential impact on confidentiality, integrity, and availability.

Analyze Each CVSS v3.1 Metric:

For each of the following base metrics, determine the most appropriate value based on your analysis:

- **Attack Vector (AV)**: Network (N), Adjacent (A), Local (L), Physical (P)
- **Attack Complexity (AC)**: Low (L), High (H)
- **Privileges Required (PR)**: None (N), Low (L), High (H)
- **User Interaction (UI)**: None (N), Required (R)
- **Scope (S)**: Unchanged (U), Changed (C)
- **Confidentiality Impact (C)**: None (N), Low (L), High (H)
- **Integrity Impact (I)**: None (N), Low (L), High (H)
- **Availability Impact (A)**: None (N), Low (L), High (H)

Justify Your Selection for Each Metric:

- Provide a clear and concise justification for each metric value.
- Base your reasoning on specific details from the CVE and advisories.

Calculate the CVSS Base Score:

To calculate the CVSS Base Score, first determine the Impact and Exploitability sub-scores. The Impact score is calculated using the formula:
Impact=1−((1−C)×(1−I)×(1−A))
where C, I, and A represent the confidentiality, integrity, and availability impacts.

Then, calculate the Exploitability sub-score:

Exploitability=8.22×AV×AC×PR×UI

where AV is Attack Vector, AC is Attack Complexity, PR is Privileges Required, and UI is User Interaction. 

Finally, if the Scope (S) is Unchanged (S), use the formula:

Base Score=min(Impact+Exploitability,10)

If the Scope is Changed (S), adjust the score with a multiplier:

Base Score=min(1.08×(Impact+Exploitability),10)

- Determine the severity rating (None, Low, Medium, High, Critical) based on the base score.

Prepare Your Report:

Present your findings in the following structured format:

CVE ID: [Insert CVE ID]

Summary:
[Brief description of the vulnerability]

Metric Analysis:
Attack Vector (AV): Value - Justification
Attack Complexity (AC): Value - Justification
Privileges Required (PR): Value - Justification
User Interaction (UI): Value - Justification
Scope (S): Value - Justification
Confidentiality Impact (C): Value - Justification
Integrity Impact (I): Value - Justification
Availability Impact (A): Value - Justification

CVSS v3.1 Vector String: [Generated vector string]

CVSS Base Score: [Score] (Severity)

References:
[List of advisory links and resources used]

Additional Guidelines:

- **Accuracy is crucial.** Ensure each metric value aligns with the CVSS v3.1 specifications.
- **Be objective.** Base your analysis solely on the information provided in the CVE and advisories.
- **Clarity and conciseness.** Keep justifications clear and to the point.
- **Do not include any unrelated information or personal opinions.**

Ensure the output is in valid JSON format as per the structure above.
"""
    return prompt
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

def process_cve_augmented(cve):
    """
    Process a single CVE entry.
    """
    print(f"Processing CVE ID: {cve['cve_id']}")
    references = extract_advisory_links(cve)

    # Scrape the advisory links asynchronously
    try:
        scraped_data = asyncio.run(scrape_urls(references))  # Use asyncio.run instead of new_event_loop
    except Exception as e:
        print(f"Error during advisory scraping: {e}")
        return

    # Add the scraped data to the cve dictionary
    cve['advisory_contents'] = scraped_data

    # Hide CVSS attributes before passing to the LLM
    cve_without_cvss = cve.copy()
    cvss_fields = ['cvss_score_v3', 'cvss_vector_v3', 'cvss_score_v2', 'cvss_vector_v2']
    for field in cvss_fields:
        cve_without_cvss.pop(field, None)  # Remove the field if it exists

    # Create the prompt
    prompt = create_prompt_cve_analyst_uploaded_config(cve_without_cvss)

    # Initialize the LLM
    llm = ChatOpenAI(
        model_name='gpt-4o-mini',
        temperature=0.0,
    )

    # Get the response from the LLM
    try:
        response = llm.invoke(prompt)
        output_text = response.content.strip()

        # Parse the LLM's output as JSON
        json_start = output_text.find('{')
        json_end = output_text.rfind('}') + 1
        json_text = output_text[json_start:json_end]

        result_vulnerabilities = json.loads(json_text)  # Parse as dictionary
        
        # Print the result for debugging
        if 'CVSS v3.1 Vector String' in result_vulnerabilities and 'CVSS Base Score' in result_vulnerabilities:
            print(f"Updated CVSS v3.1 Vector: {result_vulnerabilities['CVSS v3.1 Vector String']}")
            print(f"Updated CVSS Base Score: {result_vulnerabilities['CVSS Base Score']}")
            return result_vulnerabilities
        else:
            print("Updated CVSS information not available.")
        print('--------------------------')

    except json.JSONDecodeError as e:
        print(f"Error parsing LLM output as JSON: {e}")
        print("LLM Output:")
        print(output_text)
    except Exception as e:
        print(f"Error during LLM processing: {e}")

    print("-" * 40)