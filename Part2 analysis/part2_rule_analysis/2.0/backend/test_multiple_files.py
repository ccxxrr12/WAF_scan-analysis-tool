#!/usr/bin/env python3
# Python script to test API file upload with multiple rule files

import requests
import os
import glob

def test_api_upload(file_path, output_dir):
    """
    Test API file upload for a single file
    
    Args:
        file_path (str): Path to the rule file
        output_dir (str): Directory to save the result
    
    Returns:
        bool: True if test successful, False otherwise
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
            
            # Send the POST request
            response = requests.post(api_url, files=files)
            
            # Check the response
            if response.status_code == 200:
                # Save the result to a file
                with open(output_file, 'w', encoding='utf-8') as out_f:
                    out_f.write(response.text)
                
                print(f"✅ {file_name}: Success")
                print(f"   Rule count: {response.json().get('data', {}).get('rule_count', 0)}")
                return True, response.json().get('data', {})
            else:
                print(f"❌ {file_name}: Failed with status {response.status_code}")
                print(f"   Response: {response.text}")
                return False, {}
    
    except Exception as e:
        print(f"❌ {file_name}: Exception - {str(e)}")
        return False, {}

def main():
    """
    Main function to test multiple rule files
    """
    # Directory containing the rule files
    rules_dir = "../rules"
    # Directory to save the results
    output_dir = "test_results"
    
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    # Get all rule files with .conf extension
    rule_files = glob.glob(os.path.join(rules_dir, "*.conf"))
    
    print(f"Found {len(rule_files)} rule files to test")
    print(f"Rules directory: {rules_dir}")
    print(f"Output directory: {output_dir}")
    print("=" * 60)
    
    # Test results summary
    summary = {
        "total_files": len(rule_files),
        "success_files": 0,
        "failed_files": 0,
        "total_rules": 0,
        "results": []
    }
    
    # Test each file
    for file_path in rule_files:
        print(f"\nTesting: {os.path.basename(file_path)}")
        success, data = test_api_upload(file_path, output_dir)
        
        # Update summary
        if success:
            summary["success_files"] += 1
            summary["total_rules"] += data.get("rule_count", 0)
        else:
            summary["failed_files"] += 1
        
        # Add to results list
        summary["results"].append({
            "file_name": os.path.basename(file_path),
            "success": success,
            "rule_count": data.get("rule_count", 0),
            "processed_time": data.get("processed_time", "")
        })
    
    # Save summary to file
    summary_file = os.path.join(output_dir, "test_summary.json")
    with open(summary_file, 'w', encoding='utf-8') as f:
        import json
        json.dump(summary, f, indent=2, ensure_ascii=False)
    
    # Print summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print(f"Total files tested: {summary['total_files']}")
    print(f"Successful files: {summary['success_files']}")
    print(f"Failed files: {summary['failed_files']}")
    print(f"Total rules processed: {summary['total_rules']}")
    print(f"\nSummary saved to: {summary_file}")
    print("=" * 60)
    
    return summary

if __name__ == "__main__":
    main()
