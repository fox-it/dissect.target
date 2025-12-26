# output of bitsadmin /list on collected machine
"""
{70B45DD7-2A8B-4476-B67E-393821BFE542} 'Basic Download Test' TRANSFERRED 1 / 1 1024 / 1024
{7318A4AB-866F-48E0-A411-F485D786EA30} 'RangeDownload_20251226_071948' ERROR 0 / 3 0 / 84988
{06F4EDF0-4FC9-47DD-97FD-1A873CCB6FF6} 'Credentials Test' TRANSFERRED 1 / 1 51 / 51
{1FB879DC-0A45-4AA5-9246-9F8AEF9AB065} 'Failed Download - DNS Error' CONNECTING 0 / 1 0 / UNKNOWN
{DA426582-2868-48D8-8389-956D783BC71A} 'Failed Download - 404 Error' ERROR 0 / 1 0 / UNKNOWN
{4BCDD8AC-9910-4E80-94F7-8F7BE0B937CB} 'Failed Download - 500 Error' CONNECTING 0 / 1 0 / UNKNOWN
{896BC393-B278-4166-98A1-DCBC9903B090} 'CallbackDownload_20251226_072002' TRANSFERRED 1 / 1 2048 / 2048
{A46A6C5E-6606-442C-A63C-C6C54FF9EA2D} 'CallbackUpload_20251226_072002' TRANSFERRED 1 / 1 106 / 106
{283C8E6B-CC77-473A-8607-19C4880F09DA} 'CallbackMulti_20251226_072003' TRANSFERRED 3 / 3 3501 / 3501
"""

# Powershell script used to generate datas
"""
<#
.SYNOPSIS
    Comprehensive BITS (Background Intelligent Transfer Service) Testing Script
.DESCRIPTION
    Tests multiple BITS features including downloads, uploads, range downloads,
    credentials, custom headers, priority levels, and callbacks.
    ALL JOBS ARE PRESERVED FOR INSPECTION - NOT DELETED
.NOTES
    Server Address: 10.0.2.2:8080
    Requires: PowerShell 3.0+, BITS PowerShell module
#>

# Configuration
$ServerAddress = "10.0.2.2:8080"
$TestDirectory = "C:\\BITSTest"
$LogFile = "$TestDirectory\\BITSTest.log"
$JobsLogFile = "$TestDirectory\\BITSJobs.log"

# Global job tracking
$global:CreatedJobs = @()

# Create test directory
if (!(Test-Path $TestDirectory)) {
    New-Item -ItemType Directory -Path $TestDirectory -Force
}

# Logging function
function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] $Message"
    Write-Host $logMessage
    Add-Content -Path $LogFile -Value $logMessage
}

# Job tracking function
function Add-JobToTracking {
    param($Job, $TestName)
    $jobInfo = @{
        JobId = $Job.JobId
        DisplayName = $Job.DisplayName
        TestName = $TestName
        CreationTime = $Job.CreationTime
        JobType = $Job.JobType
        Priority = $Job.Priority
    }
    $global:CreatedJobs += $jobInfo

    $logEntry = "Job Created - Test: $TestName, ID: $($Job.JobId), Name: $($Job.DisplayName)"
    Write-Log $logEntry
    Add-Content -Path $JobsLogFile -Value "[$((Get-Date).ToString())] $logEntry"
}

# Create test files for upload
function Create-TestFiles {
    Write-Log "Creating test files..."

    # Small text file
    "This is a small test file for BITS upload testing.`nCreated at: $(Get-Date)" | Out-File "$TestDirectory\\small_test.txt"

    # Medium file (1MB)
    $content = "A" * 1024
    1..1024 | ForEach-Object { $content } | Out-File "$TestDirectory\\medium_test.txt"

    # Large file (5MB) - reduced size for faster testing
    $largeContent = "B" * (5 * 1024 * 1024)
    [System.IO.File]::WriteAllText("$TestDirectory\\large_test.txt", $largeContent)

    # Binary test file
    $binaryData = 1..1024 | ForEach-Object { [byte]($_ % 256) }
    [System.IO.File]::WriteAllBytes("$TestDirectory\binary_test.bin", $binaryData)

    Write-Log "Test files created successfully"
}

# Test 1: Basic Download Job
function Test-BasicDownload {
    Write-Log "=== Test 1: Basic Download Job ==="
    try {
        $job = Start-BitsTransfer -Source "http://httpbin.org/bytes/1024" -Destination "$TestDirectory\basic_download.bin" -DisplayName "Basic Download Test" -Asynchronous
        Add-JobToTracking -Job $job -TestName "BasicDownload"

        Write-Log "Job ID: $($job.JobId)"
        Write-Log "Job State: $($job.JobState)"

        # Wait for completion but don't delete
        $timeout = 60
        $elapsed = 0
        while (($job.JobState -eq "Transferring" -or $job.JobState -eq "Queued") -and $elapsed -lt $timeout) {
            Start-Sleep -Seconds 2
            $elapsed += 2
            $job = Get-BitsTransfer -JobId $job.JobId
            Write-Log "Job State: $($job.JobState), Progress: $($job.BytesTransferred)/$($job.BytesTotal)"
        }

        if ($job.JobState -eq "Transferred") {
            Complete-BitsTransfer -BitsJob $job
            Write-Log "Basic download completed successfully - JOB PRESERVED"
        } else {
            Write-Log "Basic download job state: $($job.JobState) - JOB PRESERVED"
        }
    }
    catch {
        Write-Log "Basic download failed: $($_.Exception.Message)"
    }
}

# Test 2: Download with Different Priority Levels
function Test-PriorityLevels {
    Write-Log "=== Test 2: Priority Levels Test ==="

    $priorities = @("Foreground", "High", "Normal", "Low")

    foreach ($priority in $priorities) {
        try {
            Write-Log "Testing priority: $priority"
            $job = Start-BitsTransfer -Source "http://httpbin.org/bytes/2048" -Destination "$TestDirectory\\priority_$priority.bin" -Priority $priority -DisplayName "Priority Test - $priority" -Asynchronous
            Add-JobToTracking -Job $job -TestName "PriorityLevels"

            Write-Log "Job created with priority $priority, ID: $($job.JobId)"

            # Monitor briefly but don't delete
            Start-Sleep -Seconds 5
            $job = Get-BitsTransfer -JobId $job.JobId
            Write-Log "Priority $priority job state: $($job.JobState) - JOB PRESERVED"

            if ($job.JobState -eq "Transferred") {
                Complete-BitsTransfer -BitsJob $job
            }
        }
        catch {
            Write-Log "Priority test failed for $priority`: $($_.Exception.Message)"
        }
    }
}

# Test 3: Range Download using Add-BitsFile with ranges
function Test-RangeDownload {
    Write-Log "=== Test 3: Range Download Test (Using Add-BitsFile with Ranges) ==="
    try {
        # Create an empty BITS job first
        $job = New-Object -ComObject Microsoft.BackgroundIntelligentTransfer.Manager
        $bitsJob = $job.CreateJob("Range Download Test", 0) # 0 = BG_JOB_TYPE_DOWNLOAD

        # Add file with specific byte ranges
        $sourceUrl = "http://httpbin.org/bytes/10240"  # 10KB file
        $destPath = "$TestDirectory\range_download_1.bin"

        # Add first range: bytes 0-1023 (first 1KB)
        $bitsJob.AddFileWithRanges($sourceUrl, $destPath, "0:1023")
        Write-Log "Added range 0:1023 to job"

        # Get the PowerShell BITS job object
        $psJob = Get-BitsTransfer | Where-Object { $_.JobId -eq $bitsJob.Id }
        if ($psJob) {
            Add-JobToTracking -Job $psJob -TestName "RangeDownload"

            # Resume the job
            $bitsJob.Resume()
            Write-Log "Range download job started, ID: $($bitsJob.Id)"

            # Monitor the job
            $timeout = 60
            $elapsed = 0
            do {
                Start-Sleep -Seconds 2
                $elapsed += 2
                $state = $bitsJob.GetState()
                $progress = $bitsJob.GetProgress()
                Write-Log "Range job state: $state, Progress: $($progress.BytesTransferred)/$($progress.BytesTotal)"
            } while ($state -eq 4 -and $elapsed -lt $timeout) # 4 = BG_JOB_STATE_TRANSFERRING

            if ($state -eq 5) { # 5 = BG_JOB_STATE_TRANSFERRED
                $bitsJob.Complete()
                Write-Log "Range download completed successfully - JOB PRESERVED"
            } else {
                Write-Log "Range download final state: $state - JOB PRESERVED"
            }
        }

        # Test multiple ranges
        Write-Log "Testing multiple ranges..."
        $bitsJob2 = $job.CreateJob("Multiple Range Download Test", 0)
        $destPath2 = "$TestDirectory\range_download_multi.bin"

        # Add multiple ranges: bytes 1024-2047 and 4096-5119
        $bitsJob2.AddFileWithRanges($sourceUrl, $destPath2, "1024:2047,4096:5119")
        Write-Log "Added multiple ranges 1024:2047,4096:5119 to job"

        $psJob2 = Get-BitsTransfer | Where-Object { $_.JobId -eq $bitsJob2.Id }
        if ($psJob2) {
            Add-JobToTracking -Job $psJob2 -TestName "RangeDownloadMultiple"
            $bitsJob2.Resume()

            $timeout = 60
            $elapsed = 0
            do {
                Start-Sleep -Seconds 2
                $elapsed += 2
                $state = $bitsJob2.GetState()
                $progress = $bitsJob2.GetProgress()
                Write-Log "Multiple range job state: $state, Progress: $($progress.BytesTransferred)/$($progress.BytesTotal)"
            } while ($state -eq 4 -and $elapsed -lt $timeout)

            if ($state -eq 5) {
                $bitsJob2.Complete()
                Write-Log "Multiple range download completed successfully - JOB PRESERVED"
            } else {
                Write-Log "Multiple range download final state: $state - JOB PRESERVED"
            }
        }

    }
    catch {
        Write-Log "Range download failed: $($_.Exception.Message)"
        Write-Log "Stack trace: $($_.ScriptStackTrace)"
    }
}

# Test 4: Upload Jobs to Test Server
function Test-UploadJobs {
    Write-Log "=== Test 4: Upload Jobs Test ==="

    $testFiles = @("small_test.txt", "medium_test.txt", "binary_test.bin")

    foreach ($file in $testFiles) {
        try {
            $sourcePath = "$TestDirectory\\$file"
            if (!(Test-Path $sourcePath)) {
                Write-Log "Source file $sourcePath not found, skipping"
                continue
            }

            $uploadUrl = "http://$ServerAddress/upload/$file"

            Write-Log "Uploading $file to $uploadUrl"

            $job = Start-BitsTransfer -Source $sourcePath -Destination $uploadUrl -TransferType Upload -DisplayName "Upload Test - $file" -Asynchronous
            Add-JobToTracking -Job $job -TestName "UploadJobs"

            Write-Log "Upload job created, ID: $($job.JobId)"

            # Monitor upload progress but don't delete
            $timeout = 120
            $elapsed = 0
            while (($job.JobState -eq "Transferring" -or $job.JobState -eq "Queued") -and $elapsed -lt $timeout) {
                Start-Sleep -Seconds 3
                $elapsed += 3
                $job = Get-BitsTransfer -JobId $job.JobId
                $progress = if ($job.BytesTotal -gt 0) { [math]::Round(($job.BytesTransferred / $job.BytesTotal) * 100, 2) } else { 0 }
                Write-Log "Upload progress for $file`: $($job.JobState), $($job.BytesTransferred)/$($job.BytesTotal) ($progress%)"
            }

            if ($job.JobState -eq "Transferred") {
                Complete-BitsTransfer -BitsJob $job
                Write-Log "Upload of $file completed successfully - JOB PRESERVED"
            } else {
                Write-Log "Upload of $file final state: $($job.JobState) - JOB PRESERVED"
                if ($job.ErrorDescription) {
                    Write-Log "Upload error: $($job.ErrorDescription)"
                }
            }
        }
        catch {
            Write-Log "Upload failed for $file`: $($_.Exception.Message)"
        }
    }
}

# Test 5: Custom Headers and Authentication Headers
function Test-CustomHeaders {
    Write-Log "=== Test 5: Custom Headers Test ==="
    try {
        # Using COM interface for more control over headers
        $job = New-Object -ComObject Microsoft.BackgroundIntelligentTransfer.Manager
        $bitsJob = $job.CreateJob("Custom Headers Test", 0)

        # Add file
        $sourceUrl = "http://httpbin.org/headers"
        $destPath = "$TestDirectory\\headers_test.json"
        $bitsJob.AddFile($sourceUrl, $destPath)

        # Set custom headers using IBackgroundCopyJobHttpOptions
        try {
            $httpOptions = $bitsJob.QueryInterface([System.Runtime.InteropServices.Marshal]::GenerateGuidForType([type]"IBackgroundCopyJobHttpOptions"))
            if ($httpOptions) {
                # Set custom headers
                $customHeaders = "X-Custom-Header: TestValue`r`nX-Test-Client: PowerShell-BITS`r`nX-Session-ID: 12345"
                $httpOptions.SetCustomHeaders($customHeaders)
                Write-Log "Custom headers set: $customHeaders"
            }
        }
        catch {
            Write-Log "Could not set custom headers (may not be supported): $($_.Exception.Message)"
        }

        $psJob = Get-BitsTransfer | Where-Object { $_.JobId -eq $bitsJob.Id }
        if ($psJob) {
            Add-JobToTracking -Job $psJob -TestName "CustomHeaders"
            $bitsJob.Resume()

            $timeout = 60
            $elapsed = 0
            do {
                Start-Sleep -Seconds 2
                $elapsed += 2
                $state = $bitsJob.GetState()
            } while ($state -eq 4 -and $elapsed -lt $timeout)

            if ($state -eq 5) {
                $bitsJob.Complete()
                Write-Log "Custom headers test completed - JOB PRESERVED"

                # Display received headers
                if (Test-Path $destPath) {
                    $headers = Get-Content $destPath | ConvertFrom-Json
                    Write-Log "User-Agent header: $($headers.headers.'User-Agent')"
                    Write-Log "Custom headers in response: $($headers.headers | ConvertTo-Json -Compress)"
                }
            } else {
                Write-Log "Custom headers test final state: $state - JOB PRESERVED"
            }
        }
    }
    catch {
        Write-Log "Custom headers test failed: $($_.Exception.Message)"
    }
}


# Test 6: Credentials Test
function Test-Credentials {
    Write-Log "=== Test 6: Credentials Test ==="
    try {
        # Create credentials for demonstration
        $username = "testuser"
        $password = "testpass"
        $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($username, $securePassword)

        # Test with httpbin basic auth endpoint
        $job = Start-BitsTransfer -Source "http://httpbin.org/basic-auth/testuser/testpass" -Destination "$TestDirectory\auth_test.json" -Credential $credential -DisplayName "Credentials Test" -Asynchronous
        Add-JobToTracking -Job $job -TestName "Credentials"

        Write-Log "Credentials test job created, ID: $($job.JobId)"

        $timeout = 60
        $elapsed = 0
        while (($job.JobState -eq "Transferring" -or $job.JobState -eq "Queued") -and $elapsed -lt $timeout) {
            Start-Sleep -Seconds 2
            $elapsed += 2
            $job = Get-BitsTransfer -JobId $job.JobId
        }

        if ($job.JobState -eq "Transferred") {
            Complete-BitsTransfer -BitsJob $job
            Write-Log "Credentials test completed successfully - JOB PRESERVED"
        } else {
            Write-Log "Credentials test final state: $($job.JobState) - JOB PRESERVED"
            if ($job.ErrorDescription) {
                Write-Log "Credentials error: $($job.ErrorDescription)"
            }
        }
    }
    catch {
        Write-Log "Credentials test failed: $($_.Exception.Message)"
    }
}

# Test 7: Multiple Concurrent Jobs
function Test-ConcurrentJobs {
    Write-Log "=== Test 7: Concurrent Jobs Test ==="

    $jobs = @()

    try {
        # Create multiple download jobs
        for ($i = 1; $i -le 5; $i++) {
            $job = Start-BitsTransfer -Source "http://httpbin.org/bytes/$($i * 1024)" -Destination "$TestDirectory\\concurrent_$i.bin" -DisplayName "Concurrent Job $i" -Asynchronous
            Add-JobToTracking -Job $job -TestName "ConcurrentJobs"
            $jobs += $job
            Write-Log "Created concurrent job $i, ID: $($job.JobId)"
        }

        # Monitor all jobs but don't delete
        $timeout = 120
        $elapsed = 0

        while ($elapsed -lt $timeout) {
            Start-Sleep -Seconds 5
            $elapsed += 5

            $completedCount = 0
            $transferringCount = 0

            foreach ($job in $jobs) {
                $currentJob = Get-BitsTransfer -JobId $job.JobId -ErrorAction SilentlyContinue
                if ($currentJob) {
                    switch ($currentJob.JobState) {
                        "Transferred" {
                            $completedCount++
                            Complete-BitsTransfer -BitsJob $currentJob -ErrorAction SilentlyContinue
                        }
                        "Transferring" { $transferringCount++ }
                        "Queued" { $transferringCount++ }
                    }
                }
            }

            Write-Log "Concurrent jobs status: $completedCount completed, $transferringCount active"

            if ($completedCount -eq $jobs.Count) {
                break
            }
        }

        Write-Log "Concurrent jobs test completed - ALL JOBS PRESERVED"
    }
    catch {
        Write-Log "Concurrent jobs test failed: $($_.Exception.Message)"
    }
}


# Sub-function for testing failed download scenarios
function Test-FailedDownloads {
    Write-Log "=== Failed Download Tests ==="

    # Test 1: Invalid URL (DNS failure)
    try {
        Write-Log "--- Test 1: Invalid URL (DNS Failure) ---"
        $failJob1 = Start-BitsTransfer -Source "http://invalid-nonexistent-domain-12345.com/file.txt" -Destination "$TestDirectory\failed_dns.txt" -DisplayName "Failed Download - DNS Error" -Asynchronous
        Add-JobToTracking -Job $failJob1 -TestName "FailedDownload-DNS"

        Write-Log "Created DNS failure test job, ID: $($failJob1.JobId)"

        # Monitor for failure
        $timeout = 60
        $elapsed = 0
        while (($failJob1.JobState -eq "Transferring" -or $failJob1.JobState -eq "Queued" -or $failJob1.JobState -eq "Connecting") -and $elapsed -lt $timeout) {
            Start-Sleep -Seconds 3
            $elapsed += 3
            $failJob1 = Get-BitsTransfer -JobId $failJob1.JobId
            Write-Log "DNS failure job state: $($failJob1.JobState), Elapsed: $elapsed seconds"
        }

        Write-Log "DNS failure test final state: $($failJob1.JobState)"
        if ($failJob1.JobState -eq "Error") {
            Write-Log "  Error Description: $($failJob1.ErrorDescription)"
            Write-Log "  Error Context: $($failJob1.ErrorContext)"
            Write-Log "  Error Count: $($failJob1.ErrorCount)"
            Write-Log "  HTTP Status: $($failJob1.HttpStatus)"
        }
        Write-Log "DNS failure test job PRESERVED for inspection"
    }
    catch {
        Write-Log "DNS failure test exception: $($_.Exception.Message)"
    }

    # Test 2: HTTP 404 Error
    try {
        Write-Log "--- Test 2: HTTP 404 Error ---"
        $failJob2 = Start-BitsTransfer -Source "http://httpbin.org/status/404" -Destination "$TestDirectory\failed_404.txt" -DisplayName "Failed Download - 404 Error" -Asynchronous
        Add-JobToTracking -Job $failJob2 -TestName "FailedDownload-404"

        Write-Log "Created 404 error test job, ID: $($failJob2.JobId)"

        # Monitor for failure
        $timeout = 60
        $elapsed = 0
        while (($failJob2.JobState -eq "Transferring" -or $failJob2.JobState -eq "Queued" -or $failJob2.JobState -eq "Connecting") -and $elapsed -lt $timeout) {
            Start-Sleep -Seconds 3
            $elapsed += 3
            $failJob2 = Get-BitsTransfer -JobId $failJob2.JobId
            Write-Log "404 error job state: $($failJob2.JobState), Elapsed: $elapsed seconds"
        }

        Write-Log "404 error test final state: $($failJob2.JobState)"
        if ($failJob2.JobState -eq "Error") {
            Write-Log "  Error Description: $($failJob2.ErrorDescription)"
            Write-Log "  Error Context: $($failJob2.ErrorContext)"
            Write-Log "  Error Count: $($failJob2.ErrorCount)"
            Write-Log "  HTTP Status: $($failJob2.HttpStatus)"
        }
        Write-Log "404 error test job PRESERVED for inspection"
    }
    catch {
        Write-Log "404 error test exception: $($_.Exception.Message)"
    }

    # Test 3: HTTP 500 Server Error
    try {
        Write-Log "--- Test 3: HTTP 500 Server Error ---"
        $failJob3 = Start-BitsTransfer -Source "http://httpbin.org/status/500" -Destination "$TestDirectory\failed_500.txt" -DisplayName "Failed Download - 500 Error" -Asynchronous
        Add-JobToTracking -Job $failJob3 -TestName "FailedDownload-500"

        Write-Log "Created 500 error test job, ID: $($failJob3.JobId)"

        # Monitor for failure
        $timeout = 60
        $elapsed = 0
        while (($failJob3.JobState -eq "Transferring" -or $failJob3.JobState -eq "Queued" -or $failJob3.JobState -eq "Connecting") -and $elapsed -lt $timeout) {
            Start-Sleep -Seconds 3
            $elapsed += 3
            $failJob3 = Get-BitsTransfer -JobId $failJob3.JobId
            Write-Log "500 error job state: $($failJob3.JobState), Elapsed: $elapsed seconds"
        }

        Write-Log "500 error test final state: $($failJob3.JobState)"
        if ($failJob3.JobState -eq "Error") {
            Write-Log "  Error Description: $($failJob3.ErrorDescription)"
            Write-Log "  Error Context: $($failJob3.ErrorContext)"
            Write-Log "  Error Count: $($failJob3.ErrorCount)"
            Write-Log "  HTTP Status: $($failJob3.HttpStatus)"
        }
        Write-Log "500 error test job PRESERVED for inspection"
    }
    catch {
        Write-Log "500 error test exception: $($_.Exception.Message)"
    }

    # Test 4: Connection Timeout (slow response)
    try {
        Write-Log "--- Test 4: Connection Timeout Test ---"
        $failJob4 = Start-BitsTransfer -Source "http://httpbin.org/delay/30" -Destination "$TestDirectory\failed_timeout.txt" -DisplayName "Failed Download - Timeout" -Asynchronous
        Add-JobToTracking -Job $failJob4 -TestName "FailedDownload-Timeout"

        Write-Log "Created timeout test job, ID: $($failJob4.JobId)"

        # Set a shorter timeout for this test
        try {
            Set-BitsTransfer -BitsJob $failJob4 -NoProgressTimeout 15
            Write-Log "Set NoProgressTimeout to 15 seconds"
        }
        catch {
            Write-Log "Could not set timeout: $($_.Exception.Message)"
        }

        # Monitor for failure
        $timeout = 45
        $elapsed = 0
        while (($failJob4.JobState -eq "Transferring" -or $failJob4.JobState -eq "Queued" -or $failJob4.JobState -eq "Connecting") -and $elapsed -lt $timeout) {
            Start-Sleep -Seconds 3
            $elapsed += 3
            $failJob4 = Get-BitsTransfer -JobId $failJob4.JobId
            Write-Log "Timeout test job state: $($failJob4.JobState), Elapsed: $elapsed seconds"

            # Log additional timeout-related properties
            if ($elapsed % 12 -eq 0) {
                Write-Log "  NoProgressTimeout setting: $($failJob4.NoProgressTimeout) seconds"
                Write-Log "  MinimumRetryDelay: $($failJob4.MinimumRetryDelay) seconds"
                Write-Log "  Error Count: $($failJob4.ErrorCount)"
            }
        }

        Write-Log "Timeout test final state: $($failJob4.JobState)"
        if ($failJob4.JobState -eq "Error") {
            Write-Log "  Error Description: $($failJob4.ErrorDescription)"
            Write-Log "  Error Context: $($failJob4.ErrorContext)"
            Write-Log "  Error Count: $($failJob4.ErrorCount)"
            Write-Log "  HTTP Status: $($failJob4.HttpStatus)"
            Write-Log "  Final NoProgressTimeout: $($failJob4.NoProgressTimeout)"
        }
        Write-Log "Timeout test job PRESERVED for inspection"
    }
    catch {
        Write-Log "Timeout test exception: $($_.Exception.Message)"
    }

    # Test 5: Invalid File Path (Access Denied)
    try {
        Write-Log "--- Test 5: Invalid Destination Path (Access Denied) ---"
        $invalidPath = "C:\\Windows\\System32\failed_access_denied.txt"  # Typically requires admin rights
        $failJob5 = Start-BitsTransfer -Source "http://httpbin.org/bytes/1024" -Destination $invalidPath -DisplayName "Failed Download - Access Denied" -Asynchronous
        Add-JobToTracking -Job $failJob5 -TestName "FailedDownload-AccessDenied"

        Write-Log "Created access denied test job, ID: $($failJob5.JobId)"
        Write-Log "Attempting to write to: $invalidPath"

        # Monitor for failure
        $timeout = 30
        $elapsed = 0
        while (($failJob5.JobState -eq "Transferring" -or $failJob5.JobState -eq "Queued" -or $failJob5.JobState -eq "Connecting") -and $elapsed -lt $timeout) {
            Start-Sleep -Seconds 2
            $elapsed += 2
            $failJob5 = Get-BitsTransfer -JobId $failJob5.JobId
            Write-Log "Access denied job state: $($failJob5.JobState), Elapsed: $elapsed seconds"
        }

        Write-Log "Access denied test final state: $($failJob5.JobState)"
        if ($failJob5.JobState -eq "Error") {
            Write-Log "  Error Description: $($failJob5.ErrorDescription)"
            Write-Log "  Error Context: $($failJob5.ErrorContext)"
            Write-Log "  Error Count: $($failJob5.ErrorCount)"
            Write-Log "  HTTP Status: $($failJob5.HttpStatus)"
        }
        Write-Log "Access denied test job PRESERVED for inspection"
    }
    catch {
        Write-Log "Access denied test exception: $($_.Exception.Message)"
    }
}

Create-TestFiles
Add-JobToTracking
Test-BasicDownload
Test-PriorityLevels
Test-RangeDownload
Test-UploadJobs
Test-CustomHeaders
Test-Credentials
Test-ConcurrentJobs
Test-FailedDownloads
"""  # noqa: E501
