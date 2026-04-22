import json

from azerg_pipeline import extract_stix_from_report

# Read from a file in CTI/reports/
with open("CTI/reports/smb_remote.txt", "r") as file:
    cti_report_text = file.read()

result = extract_stix_from_report(
    report_text=cti_report_text,
    model_name="devstral-small-2",
    provider="ollama",
)

stix_output = result["stix_output"]
# Save the full STIX output to a file
with open("CTI/stix_output/smb_remote_stix.json", "w") as stix_file:
    json.dump(stix_output, stix_file, indent=2)

# Print the full STIX output
print(json.dumps(stix_output, indent=2))