from get_cve import get_filtered_cves
from process_cve import process_cve
#from augmented_process import process_cve_augmented
from on_the_moon import process_cve_augmented

cves = get_filtered_cves(2024,2024,10)
count_of_modified_cvss = 0
for cve in cves :
    #print(cve)
    #print('*********************')
    # Check if the CVSS fields exist before processing
    # Store original CVSS score and vector for comparison later
    original_cvss_score = cve.get('cvss_score_v3', None)
    original_cvss_vector = cve.get('cvss_vector_v3', None)

    if 'cvss_score_v3' in cve and 'cvss_vector_v3' in cve:
        print(f"Original CVSS v3.1 Score: {cve['cvss_score_v3']}")
        print(f"Original CVSS v3.1 Vector: {cve['cvss_vector_v3']}")
    else:
        print("CVSS v3.1 information not available.")
        
    print('--------------------------')
    #process_cve(cve=cve)
    augmented_cve = process_cve_augmented(cve=cve)

    try :
        # Check if the CVSS fields exist after processing
        new_cvss_score = augmented_cve.get('CVSS Base Score', None)
        new_cvss_vector = augmented_cve.get('CVSS v3.1 Vector String', None)
        if new_cvss_score != None and new_cvss_vector != None:
            count_of_modified_cvss += 1
    except :
        continue
    # Get the updated CVSS score and vector from LLM response
    updated_cvss_score = augmented_cve.get('CVSS Base Score', original_cvss_score)
    updated_cvss_vector = augmented_cve.get('CVSS v3.1 Vector String', original_cvss_vector)

    # Compare original and updated CVSS score and vector
    score_is_same = original_cvss_score == updated_cvss_score
    vector_is_same = original_cvss_vector == updated_cvss_vector
            
    print(f"Is CVSS Score the same? {score_is_same}")
    print(f"Is CVSS Vector the same? {vector_is_same}")
    
print(f'''count of modified cvss :: {count_of_modified_cvss}''')




""" for i in range(100) :
    for cve in cves :
        #print(cve)
        #print('*********************')
        # Check if the CVSS fields exist before processing
        if 'cvss_score_v3' in cve and 'cvss_vector_v3' in cve:
            print(f"Original CVSS v3.1 Score: {cve['cvss_score_v3']}")
            print(f"Original CVSS v3.1 Vector: {cve['cvss_vector_v3']}")
        else:
            print("CVSS v3.1 information not available.")
        
        print('--------------------------')
        #process_cve(cve=cve)
        process_cve_augmented(cve=cve) """