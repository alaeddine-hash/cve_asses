import logging
from llama_index.core import Document, VectorStoreIndex, SimpleDirectoryReader, Settings, Prompt
from dotenv import load_dotenv
from llama_index.llms.openai import OpenAI
from augmented_cve import process_cve_augmentation
from get_cve import get_filtered_cves
from llama_index.embeddings.openai import OpenAIEmbedding


# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


load_dotenv()


def create_cve_documents(cve_data):
    documents = []
    for cve in cve_data:
        # Create a text representation of the CVE
        cve_text = (
            f"CVE ID: {cve['cve_id']}\n"
            f"Description: {cve['description']}\n"
            f"CVSS Score V3: {cve.get('cvss_score_v3')}\n"
            f"CVSS Vector V3: {cve.get('cvss_vector_v3')}\n"
            f"Published: {cve.get('published')}\n"
            f"Last Modified: {cve.get('last_modified')}\n"
            f"References: {cve.get('references')}\n"
            f"Operating System: {cve.get('os')}\n"
            f"Affected Component: {cve.get('component')}\n"
            f"Side: {cve.get('side')}\n"
        )
        # Create a Document object
        doc = Document(
            text=cve_text,
            metadata={
                'cve_id': cve['cve_id'],
                'os_name': cve.get('os_name'),
                'os_version': cve.get('os_version'),
                'component_name': cve.get('component_name'),
                'component_version': cve.get('component_version'),
                'side': cve.get('side'),
            }
        )
        documents.append(doc)
    return documents


cves_augmeted = []
# Retrieve CVEs (replace this with your actual data retrieval method)
cves = get_filtered_cves(2024, 2024, 1000)  # Adjust the parameters as needed

for cve in cves:
    augmented_cve = process_cve_augmentation(cve)
    if augmented_cve:
        cves_augmeted.append(augmented_cve)



# Initialize the OpenAI LLM with the API key
llm = OpenAI()
Settings.llm = llm

Settings.embed_model = OpenAIEmbedding()

try:
    logger.info("Loading documents and creating index...")
    # Create Document objects for the augmented CVEs
    documents = create_cve_documents(cves_augmeted)    
    index = VectorStoreIndex.from_documents(documents)
    query_engine = index.as_query_engine()
    logger.info("Index created successfully")
except Exception as e:
    index = None
    query_engine = None
    logger.error(f"Failed to initialize document index: {e}")


try :
    
    result = (
        "You are a cybersecurity assistant. "
        "Based on the context information below, identify CVEs that affect the given system configuration.\n"
        "-------------------\n"
        "{context_str}\n"
        "-------------------\n"
        "System Configuration: {query_str}\n"
        "Provide a list of relevant CVEs with the affected component for each time ."
    )

    
    qa_template = Prompt(result)
    query_engine = index.as_query_engine(text_qa_template=qa_template)
        
    # Log the retrieved nodes before generating the response
    retrieved_nodes = query_engine.retrieve('''- device_id: node1
  device_type: WINDOWS HOST
  installed_applications:
  - app_name: IIS
    ports:
    - 80
    - 443
    version: '10.0'
  - app_name: SMB
    ports:
    - 445
    version: '3.0'
  - app_name: RDP
    ports:
    - 3389
    version: '10.0'
  - app_name: Microsoft SQL Server
    ports:
    - 1433
    version: '15.0'
  - app_name: Exchange Server
    ports:
    - 25
    - 587
    version: '2019'
  network_settings:
    default_gateway: 10.10.10.10
    ip_address: 10.10.10.101
    subnet_mask: 255.255.255.0
  operating_system:
    name: Windows Server 2022
    version: 21H2
  security_settings:
    default_password_changed: false
    encryption_enabled: true
    firewall_enabled: true
    remote_access_enabled: true''')
    logger.info("Retrieved nodes:")
    for node in retrieved_nodes:
        logger.info(f"Node content: {node.node.text}")
        logger.info(f"Node score: {node.score}")

    response = query_engine.query('''- device_id: node1
  device_type: WINDOWS HOST
  installed_applications:
  - app_name: IIS
    ports:
    - 80
    - 443
    version: '10.0'
  - app_name: SMB
    ports:
    - 445
    version: '3.0'
  - app_name: RDP
    ports:
    - 3389
    version: '10.0'
  - app_name: Microsoft SQL Server
    ports:
    - 1433
    version: '15.0'
  - app_name: Exchange Server
    ports:
    - 25
    - 587
    version: '2019'
  network_settings:
    default_gateway: 10.10.10.10
    ip_address: 10.10.10.101
    subnet_mask: 255.255.255.0
  operating_system:
    name: Windows Server 2022
    version: 21H2
  security_settings:
    default_password_changed: false
    encryption_enabled: true
    firewall_enabled: true
    remote_access_enabled: true''')
    logger.info(f"Generated response: {response}")
except Exception as e:
        logger.error(f"Failed to initialize document index: {e}")
