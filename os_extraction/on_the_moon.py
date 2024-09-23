import json
import streamlit as st
import pandas as pd
import re

from cve_check_gpt import process_cve_exploitability_metrics
from get_cve import get_cve_by_id
from augmented_cve_gpt import process_cve_augmentation
from exploitation_context import process_cve_exploitation_context

# Set page configuration
st.set_page_config(
    page_title="CVE Analyst Application",
    page_icon="🔍",
    layout="wide",
)

# Sidebar with information about the application and the enterprise
with st.sidebar:
    st.title("APAIA-TECHNOLOGY")
    st.markdown("""
    ### CVE Analyst Application

    Welcome to the **CVE Analyst Application**. This tool allows you to analyze CVE IDs and retrieve detailed information about vulnerabilities, including affected systems, exploitability metrics, and potential impacts.

    ### About Us

    We specialize in cybersecurity solutions, providing state-of-the-art tools to help organizations stay secure and informed about the latest threats.
    """)

# Title and description of the application
st.title("🔍 CVE Analyst Application")
st.markdown("""
Enter a CVE ID below to retrieve detailed information about the vulnerability, including affected systems, exploitability metrics, and more.
""")

# Validate CVE ID format
cve_pattern = r'^CVE-\d{4}-\d{4,7}$'

# Input field for CVE ID with placeholder
cve_id = st.text_input("Enter the CVE ID (e.g., CVE-2021-34527):", value="")

# Button to trigger analysis
if st.button("Analyze"):
    if cve_id:
        if not re.match(cve_pattern, cve_id):
            st.error("❌ Invalid CVE ID format. Please enter a valid CVE ID in the format 'CVE-YYYY-NNNN'.")
        else:
            # Placeholder for LLM processing
            with st.spinner("Processing..."):
                cve_entry = get_cve_by_id(cve_id)
                if cve_entry:
                    cve_entry = process_cve_augmentation(cve_entry)
                    cve_entry = process_cve_exploitation_context(cve_entry)
                    cve_entry = process_cve_exploitability_metrics(cve_entry)
                    # Extract data from cve_entry
                    os_list = cve_entry.get('os_name', [])
                    os_versions = cve_entry.get('os_version', [])
                    description = cve_entry.get('description', '')
                    cvss_score_v3 = cve_entry.get('cvss_score_v3', '')
                    cvss_vector_v3 = cve_entry.get('cvss_vector_v3', '')
                    weaknesses = cve_entry.get('weaknesses', [])
                    configurations = cve_entry.get('configurations', [])
                    references = cve_entry.get('references', [])
                    exploitation_context = cve_entry.get('exploitation_context', {})
                    contexts = exploitation_context.get('contexts', [])
                    side = cve_entry.get('Side', '')
                    exploitability_metrics = cve_entry.get('exploitability_metrics', {})
                    overall_assessment = cve_entry.get('overall_assessment', '')
                    remarks = cve_entry.get('remarks', '')

                    # Parse JSON strings into Python objects if necessary
                    def parse_json(data):
                        if isinstance(data, str):
                            try:
                                return json.loads(data)
                            except json.JSONDecodeError:
                                return []
                        return data

                    os_list = parse_json(os_list)
                    os_versions = parse_json(os_versions)
                    weaknesses_list = parse_json(weaknesses)
                    configurations_list = parse_json(configurations)
                    references_list = parse_json(references)

                    # Create tabs for organized display
                    tab_overview, tab_weaknesses, tab_systems, tab_references, tab_exploitability, tab_remarks = st.tabs([
                        "Overview", "Weaknesses", "Affected Systems", "References", "Exploitability Metrics", "Context Exploitation"
                    ])

                    # Overview Tab
                    with tab_overview:
                        st.subheader(f"CVE ID: {cve_entry.get('cve_id', 'N/A')}")
                        # Use st.markdown with unsafe_allow_html=True to render HTML content
                        st.markdown(f"**Description:** {description}", unsafe_allow_html=True)
                        st.write(f"**CVSS Score v3:** {cvss_score_v3}")
                        st.write(f"**CVSS Vector v3:** {cvss_vector_v3}")
                        if overall_assessment:
                            st.write("**Overall Assessment:**")
                            st.write(overall_assessment)
                        else:
                            st.write("**Overall Assessment:** None provided.")

                    # Weaknesses Tab
                    with tab_weaknesses:
                        if weaknesses_list:
                            st.write("**Weaknesses:**")
                            for weakness in weaknesses_list:
                                if isinstance(weakness, dict):
                                    description = weakness.get('description', [])
                                    if description:
                                        for desc in description:
                                            value = desc.get('value', '')
                                            if value:
                                                st.write(f"  - {value}")
                                            else:
                                                st.write("  - No description available.")
                                    else:
                                        st.write("  - No description available.")
                                else:
                                    st.write(f"- {weakness}")
                        else:
                            st.write("**Weaknesses:** None listed.")

                    # Affected Systems Tab
                    with tab_systems:
                        if os_list:
                            if not os_versions:
                                os_versions = ['N/A'] * len(os_list)
                            if len(os_list) == 1 and len(os_versions) > 1:
                                os_list = os_list * len(os_versions)
                            elif len(os_versions) != len(os_list):
                                os_versions = ['N/A'] * len(os_list)
                            data = {
                                "Operating System": os_list,
                                "OS Version": os_versions,
                            }
                            df = pd.DataFrame(data)
                            st.write("**Affected Operating Systems and Versions:**")
                            st.dataframe(df)
                        else:
                            st.write("**Affected Operating Systems and Versions:** None listed.")

                    # References Tab
                    with tab_references:
                        if references_list:
                            st.write("**References:**")
                            for ref in references_list:
                                if isinstance(ref, dict):
                                    url = ref.get('url', '')
                                    source = ref.get('source', 'Reference')
                                    if url:
                                        st.write(f"- [{source}]({url})")
                                    else:
                                        st.write(f"- {source}")
                                else:
                                    st.write(f"- {ref}")
                        else:
                            st.write("**References:** None listed.")

                    # Exploitability Metrics Tab
                    with tab_exploitability:
                        if exploitability_metrics:
                            st.write("**Exploitability Metrics:**")
                            metrics_data = []
                            for metric, details in exploitability_metrics.items():
                                if isinstance(details, dict):
                                    metric_name = metric
                                    value = details.get('value', '')
                                    assessment = details.get('assessment', '')
                                    remarks_metric = details.get('remarks', '')
                                    metrics_data.append({
                                        'Metric': metric_name,
                                        'Value': value,
                                        'Assessment': assessment,
                                        'Remarks': remarks_metric
                                    })
                            if metrics_data:
                                metrics_df = pd.DataFrame(metrics_data)
                                st.dataframe(metrics_df)
                            else:
                                st.write("No exploitability metrics available.")
                        else:
                            st.write("**Exploitability Metrics:** None available.")

                    # Remarks Tab
                    with tab_remarks:
                        # Exploitation Context
                        if exploitation_context:
                            general_explanation = exploitation_context.get('general_explanation', '')

                            if general_explanation:
                                st.write("**General Explanation:**")
                                st.write(general_explanation)

                            if contexts:
                                st.write("**Specific Contexts:**")
                                for idx, context in enumerate(contexts, start=1):
                                    st.write(f"**Context {idx}:**")
                                    environment = context.get('environment', '')
                                    explanation = context.get('explanation', '')
                                    if environment:
                                        st.write(f"- **Environment:** {environment}")
                                    if explanation:
                                        st.write(f"- **Explanation:** {explanation}")
                                    if not environment and not explanation:
                                        st.write("- No details provided.")
                            else:
                                st.write("No specific contexts provided.")
                        else:
                            st.write("**Exploitation Context:** None available.")

                        # Side
                        if side:
                            st.write(f"**Side:** {side}")
                        else:
                            st.write("**Side:** Not specified.")

                        # Remarks
                        if remarks:
                            st.write("**Additional Remarks:**")
                            st.write(remarks)
                        else:
                            st.write("**Remarks:** None provided.")

                    st.success("✅ Analysis Complete!")
                else:
                    st.error(f"❌ No data found for CVE ID {cve_id}.")
    else:
        st.error("❌ Please enter a CVE ID.")
