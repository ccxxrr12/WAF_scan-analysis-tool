# PowerShell script to test API file upload

$filePath = "../rules/REQUEST-901-INITIALIZATION.conf"
$apiUrl = "http://localhost:8000/api/analyze-rules"
$outputFile = "test_results/REQUEST-901-INITIALIZATION.result.json"

# Upload file using HttpClient
$httpClient = New-Object System.Net.Http.HttpClient
$content = New-Object System.Net.Http.MultipartFormDataContent

# Read file content
$fileBytes = [System.IO.File]::ReadAllBytes($filePath)
$fileContent = New-Object System.Net.Http.ByteArrayContent($fileBytes)
$fileContent.Headers.ContentType = New-Object System.Net.Http.Headers.MediaTypeHeaderValue("text/plain")
$content.Add($fileContent, "file", [System.IO.Path]::GetFileName($filePath))

try {
    # Send request
    $response = $httpClient.PostAsync($apiUrl, $content).Result
    
    # Check response status
    if ($response.IsSuccessStatusCode) {
        # Read response content
        $result = $response.Content.ReadAsStringAsync().Result
        
        # Save result to file
        $result | Out-File -FilePath $outputFile -Encoding utf8
        
        Write-Host "Test successful! Result saved to: $outputFile"
        Write-Host "Response status: $($response.StatusCode)"
        Write-Host "Response content: $result"
    } else {
        Write-Host "Test failed!"
        Write-Host "Response status: $($response.StatusCode)"
        Write-Host "Response content: $($response.Content.ReadAsStringAsync().Result)"
    }
} catch [System.Exception] {
    Write-Host "Test failed! Exception occurred: $($_.Exception.Message)"
} finally {
    # Dispose resources
    $httpClient.Dispose()
    $content.Dispose()
    $fileContent.Dispose()
}