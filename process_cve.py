import asyncio
import aiohttp
from langchain_openai import ChatOpenAI
import os
import json
from bs4 import BeautifulSoup



def create_prompt_cve_analyst_uploaded_config(cve):
    # Define the absolute path to the prompt file
    base_dir = os.path.dirname(os.path.realpath(__file__))  # Gets the directory of the current file
    file_path = os.path.join(base_dir, 'prompt.txt')

    # Load the prompt from the text file
    with open(file_path, 'r') as file:
        template = file.read()

    # Insert CVE and description into the template
    prompt = template.format(cve=cve)
    return prompt


# Function to extract advisory links from a CVE entry
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
        async with session.get(url) as response:
            if response.status == 200:
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                text_content = soup.get_text(separator='\n', strip=True)
                return {'url': url, 'content': text_content}
            else:
                return {'url': url, 'content': f'Failed to fetch: {response.status}'}
    except Exception as e:
        return {'url': url, 'content': str(e)}

def process_cve(cve):
    """
    Process a single CVE entry.
    Add your custom processing logic here.
    """
    print(f"Processing CVE ID: {cve['cve_id']}")
    references = extract_advisory_links(cve)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    scraped_data = loop.run_until_complete(scrape_urls(references))

    # Add the scraped data to the cve dictionary
    cve['advisory_contents'] = scraped_data


    cve_without_cvss = cve.copy()
    cvss_fields = ['cvss_score_v3', 'cvss_vector_v3', 'cvss_score_v2', 'cvss_vector_v2']
    for field in cvss_fields:
        cve_without_cvss.pop(field, None)  # Remove the field if it exists
    
    #print('cve without cvss field : ', cve_without_cvss)


    # Example: Check CVSS score and categorize severity
    if cve['cvss_score_v3'] is not None:
        score = float(cve['cvss_score_v3'])
        prompt = create_prompt_cve_analyst_uploaded_config(cve)
        llm = ChatOpenAI( model_name='gpt-4o-mini', temperature=0.0, )
        response = llm.invoke(prompt)
        print(response.content)
        #result_vulnerabilities = json.loads(response.content.replace("```", "").replace("json", ""))

        if score >= 9.0:
            severity = 'Critical'
        elif score >= 7.0:
            severity = 'High'
        elif score >= 4.0:
            severity = 'Medium'
        else:
            severity = 'Low'
        print(f"Severity Level: {severity}")
    else:
        print("CVSS Score v3 is not available.")

    # Additional processing can be added here.
    print("-" * 40)
    
   
