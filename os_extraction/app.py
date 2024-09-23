import json
import streamlit as st
import pandas as pd

from cve_check_gpt import process_cve_exploitability_metrics
from get_cve import get_cve_by_id
from augmented_cve_gpt import process_cve_augmentation
import re

from exploitation_context import process_cve_exploitation_context

# Validate CVE ID format
cve_pattern = r'^CVE-\d{4}-\d{4,7}$'

# Title of the application
st.title("CVE Analyst Application")

# Input field for CVE ID
cve_id = st.text_input("Enter the CVE ID:")

# Button to trigger analysis
if st.button("Analyze"):
    if cve_id:
        if not re.match(cve_pattern, cve_id):
            st.error("Invalid CVE ID format. Please enter a valid CVE ID in the format 'CVE-YYYY-NNNN'.")
        else : 
            # Placeholder for LLM processing (replace this with your logic)
            with st.spinner("Processing..."):
                cve_entry    = get_cve_by_id(cve_id)
                cve_entry = process_cve_augmentation(cve_entry)
                cve_entry = process_cve_exploitation_context(cve_entry)  # Add this line
                cve_entry = process_cve_exploitability_metrics(cve_entry)
                if cve_entry:
                    # Extract data from cve_entry
                    os_list = cve_entry.get('os_name', [])
                    os_versions = cve_entry.get('os_version', [])
                    description = cve_entry.get('description', '')
                    cvss_score_v3 = cve_entry.get('cvss_score_v3', '')
                    cvss_vector_v3 = cve_entry.get('cvss_vector_v3', '')
                    weaknesses = cve_entry.get('weaknesses', '[]')
                    configurations = cve_entry.get('configurations', '[]')
                    references = cve_entry.get('references', '[]')
                    # Extract the new fields
                    # Extract the new fields
                    exploitation_context = cve_entry.get('exploitation_context', {})
                    contexts = exploitation_context.get('contexts', [])
                    side = cve_entry.get('Side', '')
                    # Extract the new fields
                    exploitability_metrics = cve_entry.get('exploitability_metrics', {})
                    overall_assessment = cve_entry.get('overall_assessment', '')
                    remarks = cve_entry.get('remarks', '')
                    # Parse JSON strings into Python objects
                    try:
                        os_list = json.loads(os_list) if isinstance(os_list, str) else os_list
                    except json.JSONDecodeError:
                        os_list = []

                    try:
                        os_versions = json.loads(os_versions) if isinstance(os_versions, str) else os_versions
                    except json.JSONDecodeError:
                        os_versions = []

                    try:
                        weaknesses_list = json.loads(weaknesses)
                    except json.JSONDecodeError:
                        weaknesses_list = []

                    try:
                        configurations_list = json.loads(configurations)
                    except json.JSONDecodeError:
                        configurations_list = []

                    try:
                        references_list = json.loads(references)
                    except json.JSONDecodeError:
                        references_list = []

                    # Display the information
                    st.subheader(f"CVE ID: {cve_entry['cve_id']}")
                    st.write(f"**Description:** {description}")
                    st.write(f"**CVSS Score v3:** {cvss_score_v3}")
                    st.write(f"**CVSS Vector v3:** {cvss_vector_v3}")

                    # Display weaknesses and configurations if available
                    if weaknesses_list:
                        st.write("**Weaknesses:**")
                        for weakness in weaknesses_list:
                            description = weakness.get('description', [])
                            if description:
                                for desc in description:
                                    value = desc.get('value', '')
                                    if value:
                                        st.write(f"- {value}")
                            else:
                                st.write(f"- {weakness}")
                    else:
                        st.write("**Weaknesses:** None listed.")

                    if configurations_list:
                        st.write("**Configurations:**")
                        for config in configurations_list:
                            st.write(f"- {config}")
                    else:
                        st.write("**Configurations:** None listed.")

                    # Display OS and versions
                    # Display OS and versions
                    if os_list:
                        # If os_versions is empty
                        if not os_versions:
                            os_versions = ['N/A'] * len(os_list)
                        # If os_list has length 1 and os_versions has more than 1 version
                        if len(os_list) == 1 and len(os_versions) > 1:
                            os_list = os_list * len(os_versions)  # Repeat OS name
                        elif len(os_versions) != len(os_list):
                            # If lengths still don't match, fill os_versions with 'N/A'
                            os_versions = ['N/A'] * len(os_list)
                        data = {
                            "Operating System": os_list,
                            "OS Version": os_versions,
                        }
                        df = pd.DataFrame(data)
                        st.write("**Affected Operating Systems and Versions:**")
                        st.write(df)
                    else:
                        st.write("**Affected Operating Systems and Versions:** None listed.")

                    # Display References
                    if references_list:
                        st.write("**References:**")
                        for ref in references_list:
                            url = ref.get('url', '')
                            source = ref.get('source', '')
                            if url:
                                st.write(f"- [{source or 'Reference'}]({url})")
                            else:
                                st.write(f"- {source}")
                    else:
                        st.write("**References:** None listed.")
                    # Display Exploitability Metrics
                    if exploitation_context:
                        st.write("**Exploitation Context:**")
                        general_explanation = exploitation_context.get('general_explanation', '')

                        # Display General Explanation
                        if general_explanation:
                            st.write("**General Explanation:**")
                            st.write(general_explanation)

                        # Display Contexts
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
                        else:
                            st.write("No specific contexts provided.")
                    else:
                        st.write("**Exploitation Context:** None available.")

                    # Display Side
                    if side:
                        st.write(f"**Side:** {side}")
                    else:
                        st.write("**Side:** Not specified.")

                    # Display Exploitability Metrics
                    if exploitability_metrics:
                        st.write("**Exploitability Metrics:**")
                        metrics_data = []
                        for metric, details in exploitability_metrics.items():
                            metric_name = metric  # AV, AC, PR, etc.
                            value = details.get('value', '')
                            assessment = details.get('assessment', '')
                            remarks_metric = details.get('remarks', '')
                            metrics_data.append({
                                'Metric': metric_name,
                                'Value': value,
                                'Assessment': assessment,
                                'Remarks': remarks_metric
                            })
                        metrics_df = pd.DataFrame(metrics_data)
                        st.write(metrics_df)
                    else:
                        st.write("**Exploitability Metrics:** None available.")

                    # Display Overall Assessment
                    if overall_assessment:
                        st.write("**Overall Assessment:**")
                        st.write(overall_assessment)
                    else:
                        st.write("**Overall Assessment:** None provided.")

                    # Display Remarks
                    if remarks:
                        st.write("**Remarks:**")
                        st.write(remarks)
                    else:
                        st.write("**Remarks:** None provided.")

                    st.success("Analysis Complete!")
                else:
                    st.error(f"No data found for CVE ID {cve_id}.")
    else:
        st.error("Please enter a CVE ID.")