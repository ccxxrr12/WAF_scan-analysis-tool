#!/usr/bin/env python3
# Python script to test API file upload

import requests
import os

def test_api_upload(file_path, output_dir):
    """
    Test API file upload
    
    Args:
        file_path (str): Path to the rule file
        output_dir (str): Directory to save the result
    """
    api_url = "http://localhost:8000/api/analyze-rules"
    
    # Prepare output file name
    file_name = os.path.basename(file_path)
    output_file = os.path.join(output_dir, f"{os.path.splitext(file_name)[0]}.result.json")
    
    try:
        # Open the file for upload
        with open(file_path, 'rb') as f:
            # Prepare the form data
            files = {
                'file': (file_name, f, 'text/plain')
            }
            
            print(f"Uploading file: {file_name}")
            print(f"API URL: {api_url}")
            print(f"Output file: {output_file}")
            
            # Send the POST request
            response = requests.post(api_url, files=files)
            
            # Check the response
            if response.status_code == 200:
                # Save the result to a file
                with open(output_file, 'w', encoding='utf-8') as out_f:
                    out_f.write(response.text)
                
                print(f"✅ Test successful!")
                print(f"   Status code: {response.status_code}")
                print(f"   Result saved to: {output_file}")
                print(f"   Response: {response.text}")
                return True
            else:
                print(f"❌ Test failed!")
                print(f"   Status code: {response.status_code}")
                print(f"   Response: {response.text}")
                return False
    
    except Exception as e:
        print(f"❌ Test failed with exception!")
        print(f"   Exception: {str(e)}")
        return False

if __name__ == "__main__":
    # Test a single rule file
    rule_file = "../rules/REQUEST-901-INITIALIZATION.conf"
    output_directory = "test_results"
    
    # Ensure output directory exists
    os.makedirs(output_directory, exist_ok=True)
    
    # Run the test
    test_api_upload(rule_file, output_directory)
