import requests
import csv
from datetime import datetime, timedelta

def fetch_cve_data():
    print("Fetching CVE data from the NVD API...")
    # Define the API endpoint and parameters
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    yesterday = datetime.now() - timedelta(1)
    params = {
        "resultsPerPage": 10,
        "pubStartDate": yesterday.strftime(('%Y-%m-%dT%H:%M:%S.%f'))[:-3] + 'Z',  # Yesterday's date in ISO 8601 format
        "pubEndDate": datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',  # Today's date in ISO 8601 format
    }

    response = requests.get(url, params=params)
    response.raise_for_status() # Raise an error for bad status codes
    print("CVE data fetched successfully.")
    return response.json()

def extract_cve_info(data):
    print("Extrcting CVE information...")
    cve_info_list = []

    for item in data.get("vulnerabilities", []):
        cve_data = item.get("cve", {})
        cve_id = cve_data.get("id", "N/A")
        descriptions = cve_data.get("descriptions", [])
        vendor_name = "N/A"
        if descriptions:
            vendor_name = descriptions[0].get("value", "N/A")
        impact_data = cve_data.get("metrics", {})
        cvss_score = "N/A"
        if "cvssMetricV31" in impact_data:
            cvss_score = impact_data["cvssMetricV31"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV30" in impact_data:
            cvss_score = impact_data["cvssMetricV30"][0]["cvssData"]["baseScore"]
        
        cve_info_list.append({
            "CVE_ID": cve_id,
            "Vendor": vendor_name,
            "CVSS Score": cvss_score
        })
    
    print(f"Extracted {len(cve_info_list)} CVE entries.")
    return cve_info_list

def save_to_csv(cve_info_list, filename="cve_data.csv"):
    print(f"Saving CVE data to {filename}...")
    keys = cve_info_list[0].keys()
    with open(filename, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=keys)
        writer.writeheader()
        writer.writerows(cve_info_list)
    print(f"CVE data saved to {filename} successfully.")


def main():
    print("Starting the CVE download and extraction tool...")
    data = fetch_cve_data()
    cve_info_list = extract_cve_info(data)
    if cve_info_list:   # Check if the list is not empty before saving to CVS
        save_to_csv(cve_info_list)
    else:
        print("No new CVE data found.")
    print("Process completed.")

if __name__ == "__main__":
    main()
