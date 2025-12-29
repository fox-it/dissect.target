from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING

from flow.record.fieldtypes import datetime as dt

from dissect.target.plugins.os.windows.bits._plugin import BitsPlugin
from dissect.target.plugins.os.windows.bits.c_bits import c_bits
from dissect.target.target import Target
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem

JobState = c_bits.JobState
BG_JOB_TYPE = c_bits.BG_JOB_TYPE
BG_NOTIFY = c_bits.BG_NOTIFY
BG_JOB_PRIORITY = c_bits.BG_JOB_PRIORITY


def test_bits_plugin(target_win: Target, fs_win: VirtualFilesystem) -> None:
    qmgr_db = absolute_path("_data/plugins/os/windows/bits/ese/windows_server_2019/qmgr.db")
    fs_win.map_file("ProgramData/Microsoft/Network/Downloader/qmgr.db", qmgr_db)
    target_win.add_plugin(BitsPlugin)

    records = list(target_win.qmgr_ese())

    assert len(records) == 13
    assert Counter((r.name, r.job_id) for r in records) == {
        ("CallbackMulti_20251226_072003", "283c8e6b-cc77-473a-8607-19c4880f09da"): 3,
        ("RangeDownload_20251226_071948", "7318a4ab-866f-48e0-a411-f485d786ea30"): 3,
        ("Credentials Test", "06f4edf0-4fc9-47dd-97fd-1a873ccb6ff6"): 1,
        ("Basic Download Test", "70b45dd7-2a8b-4476-b67e-393821bfe542"): 1,
        ("Failed Download - 500 Error", "4bcdd8ac-9910-4e80-94f7-8f7be0b937cb"): 1,
        ("Failed Download - 404 Error", "da426582-2868-48d8-8389-956d783bc71a"): 1,
        ("Failed Download - DNS Error", "1fb879dc-0a45-4aa5-9246-9f8aef9ab065"): 1,
        ("CallbackUpload_20251226_072002", "a46a6c5e-6606-442c-a63c-c6c54ff9ea2d"): 1,
        ("CallbackDownload_20251226_072002", "896bc393-b278-4166-98a1-dcbc9903b090"): 1,
    }
    # assert type(records[0].job_mtime) == datetime
    assert {
        r.file_guid: (
            r.file_transfer_size,
            r.file_dl_size,
            r.transferred_file_mtime,
            r.file_dst,
            r.file_src,
            r.file_tmp,
            r.has_error,
            r.desc,
            r.callback_cmd,
            r.callback_args,
            r.user_id,
            r.file_drive,
            r.job_mtime,
            r.job_mtime_bis,
            r.job_completion_time,
            r.job_ctime,
            r.job_id,
        )
        for r in records
    } == {
        "010a51dd-b650-4cb2-b92f-2d84ec323a37": (
            51,
            51,
            None,
            "C:\\BITSTest\\auth_test.json",
            "http://httpbin.org/basic-auth/testuser/testpass",
            "C:\\BITSTest\\BITA67F.tmp",
            False,
            "This is a file transfer that uses the Background Intelligent Transfer Service (BITS).",
            "",
            "",
            "S-1-5-21-3326717675-894959027-842342618-1000",
            "C:\\",
            dt("2025-12-26 15:20:27.767214+00:00"),
            dt("2025-12-26 15:19:56.530785+00:00"),
            dt("2025-12-26 15:19:56.530785+00:00"),
            dt("2025-12-26 15:19:55.827888+00:00"),
            "06f4edf0-4fc9-47dd-97fd-1a873ccb6ff6",
        ),
        "0864c6bb-3225-423e-9751-9e291577472f": (
            None,
            0,
            None,
            "C:\\BITSTest\\failed_404.txt",
            "http://httpbin.org/status/404",
            "C:\\BITSTest\\BITA76B.tmp",
            True,
            "This is a file transfer that uses the Background Intelligent Transfer Service (BITS).",
            "",
            "",
            "S-1-5-21-3326717675-894959027-842342618-1000",
            "C:\\",
            dt("2025-12-26 15:19:56.172602+00:00"),
            dt("2025-12-26 15:19:56.172602+00:00"),
            None,
            dt("2025-12-26 15:19:56.062199+00:00"),
            "da426582-2868-48d8-8389-956d783bc71a",
        ),
        "1923e2fa-7469-4c08-aa97-95c72bf8786c": (
            2048,
            2048,
            None,
            "C:\\BITSTest\\multi2.bin",
            "http://httpbin.org/bytes/2048",
            "C:\\BITSTest\\BITC45F.tmp",
            False,
            "",
            "",
            "",
            "S-1-5-21-3326717675-894959027-842342618-1000",
            "C:\\",
            dt("2025-12-26 15:21:20.828646+00:00"),
            dt("2025-12-26 15:21:20.828646+00:00"),
            dt("2025-12-26 15:21:20.828646+00:00"),
            dt("2025-12-26 15:20:03.296831+00:00"),
            "283c8e6b-cc77-473a-8607-19c4880f09da",
        ),
        "2a3089d0-2546-46a4-ba56-838cd0d8b1c4": (
            1024,
            1024,
            None,
            "C:\\BITSTest\\multi1.bin",
            "http://httpbin.org/bytes/1024",
            "C:\\BITSTest\\BITC41F.tmp",
            False,
            "",
            "",
            "",
            "S-1-5-21-3326717675-894959027-842342618-1000",
            "C:\\",
            dt("2025-12-26 15:21:20.828646+00:00"),
            dt("2025-12-26 15:21:20.828646+00:00"),
            dt("2025-12-26 15:21:20.828646+00:00"),
            dt("2025-12-26 15:20:03.296831+00:00"),
            "283c8e6b-cc77-473a-8607-19c4880f09da",
        ),
        "2dbef63d-1d86-487d-be32-1a519dbe5267": (
            2048,
            2048,
            None,
            "C:\\BITSTest\\callback_download.bin",
            "http://httpbin.org/bytes/2048",
            "C:\\BITSTest\\BITC14F.tmp",
            False,
            "",
            "notepad.exe",
            "C:\\BITSTest\\callback_download.bin",
            "S-1-5-21-3326717675-894959027-842342618-1000",
            "C:\\",
            dt("2025-12-26 15:20:27.782486+00:00"),
            dt("2025-12-26 15:20:05.093918+00:00"),
            dt("2025-12-26 15:20:05.093918+00:00"),
            dt("2025-12-26 15:20:02.624641+00:00"),
            "896bc393-b278-4166-98a1-dcbc9903b090",
        ),
        "322b2804-e35a-449a-8120-95be318d8c7c": (
            None,
            0,
            None,
            "C:\\BITSTest\\failed_dns.txt",
            "http://invalid-nonexistent-domain-12345.com/file.txt",
            "C:\\BITSTest\\BITA6ED.tmp",
            True,
            "This is a file transfer that uses the Background Intelligent Transfer Service (BITS).",
            "",
            "",
            "S-1-5-21-3326717675-894959027-842342618-1000",
            "C:\\",
            dt("2025-12-26 15:19:55.984718+00:00"),
            dt("2025-12-26 15:19:55.984718+00:00"),
            None,
            dt("2025-12-26 15:19:55.936983+00:00"),
            "1fb879dc-0a45-4aa5-9246-9f8aef9ab065",
        ),
        "3b02d70f-4d33-4be6-af5d-d8e6397a12ee": (
            76799,
            0,
            None,
            "C:\\BITSTest\\range_download_large.bin",
            "http://httpbin.org/bytes/102400",
            "C:\\BITSTest\\BIT8AD8.tmp",
            True,
            "",
            "",
            "",
            "S-1-5-21-3326717675-894959027-842342618-1000",
            "C:\\",
            dt("2025-12-26 15:19:52.406492+00:00"),
            dt("2025-12-26 15:19:52.406492+00:00"),
            None,
            dt("2025-12-26 15:19:48.515322+00:00"),
            "7318a4ab-866f-48e0-a411-f485d786ea30",
        ),
        "4c36804b-eb2e-42c6-926b-5a981df3f3dc": (
            106,
            106,
            dt("2025-12-26 15:20:02.906315+00:00"),
            "C:\\BITSTest\\upload_callback.txt",
            "http://10.0.2.2:8080/callback_test.txt",
            "",
            False,
            "",
            "notepad.exe",
            "C:\\BITSTest\\upload_callback.txt",
            "S-1-5-21-3326717675-894959027-842342618-1000",
            "C:\\",
            dt("2025-12-26 15:21:19.110544+00:00"),
            dt("2025-12-26 15:21:19.110544+00:00"),
            dt("2025-12-26 15:21:19.110544+00:00"),
            dt("2025-12-26 15:20:02.969839+00:00"),
            "a46a6c5e-6606-442c-a63c-c6c54ff9ea2d",
        ),
        "51113ce6-a2c9-4843-8c7e-7290552617f8": (
            None,
            0,
            None,
            "C:\\BITSTest\\failed_500.txt",
            "http://httpbin.org/status/500",
            "C:\\BITSTest\\BITB3E0.tmp",
            True,
            "This is a file transfer that uses the Background Intelligent Transfer Service (BITS).",
            "",
            "",
            "S-1-5-21-3326717675-894959027-842342618-1000",
            "C:\\",
            dt("2025-12-26 15:20:01.375772+00:00"),
            dt("2025-12-26 15:20:01.375772+00:00"),
            None,
            dt("2025-12-26 15:19:59.249641+00:00"),
            "4bcdd8ac-9910-4e80-94f7-8f7be0b937cb",
        ),
        "a044dcbc-be34-4f8e-963e-0e1391c37a77": (
            7166,
            0,
            None,
            "C:\\BITSTest\\range_download_multiple.bin",
            "http://httpbin.org/bytes/10240",
            "C:\\BITSTest\\BIT8A79.tmp",
            True,
            "",
            "",
            "",
            "S-1-5-21-3326717675-894959027-842342618-1000",
            "C:\\",
            dt("2025-12-26 15:19:52.406492+00:00"),
            dt("2025-12-26 15:19:52.406492+00:00"),
            None,
            dt("2025-12-26 15:19:48.515322+00:00"),
            "7318a4ab-866f-48e0-a411-f485d786ea30",
        ),
        "bcd97ef6-5f4b-4b68-98d3-9853f7633ebc": (
            1023,
            0,
            None,
            "C:\\BITSTest\\range_download_single.bin",
            "http://httpbin.org/bytes/10240",
            "C:\\BITSTest\\BIT8A2A.tmp",
            True,
            "",
            "",
            "",
            "S-1-5-21-3326717675-894959027-842342618-1000",
            "C:\\",
            dt("2025-12-26 15:19:52.406492+00:00"),
            dt("2025-12-26 15:19:52.406492+00:00"),
            None,
            dt("2025-12-26 15:19:48.515322+00:00"),
            "7318a4ab-866f-48e0-a411-f485d786ea30",
        ),
        "c7493c83-41b1-416e-994f-f23f3332788b": (
            1024,
            1024,
            None,
            "C:\\BITSTest\\basic_download.bin",
            "http://httpbin.org/bytes/1024",
            "C:\\BITSTest\\BIT3927.tmp",
            False,
            "This is a file transfer that uses the Background Intelligent Transfer Service (BITS).",
            "",
            "",
            "S-1-5-21-3326717675-894959027-842342618-1000",
            "C:\\",
            dt("2025-12-26 15:20:27.767214+00:00"),
            dt("2025-12-26 15:19:28.353626+00:00"),
            dt("2025-12-26 15:19:28.353626+00:00"),
            dt("2025-12-26 15:19:27.821503+00:00"),
            "70b45dd7-2a8b-4476-b67e-393821bfe542",
        ),
        "fe2136a8-68c3-4daf-b35b-5297d9d2af70": (
            429,
            429,
            None,
            "C:\\BITSTest\\multi3.json",
            "http://httpbin.org/json",
            "C:\\BITSTest\\BITC50C.tmp",
            False,
            "",
            "",
            "",
            "S-1-5-21-3326717675-894959027-842342618-1000",
            "C:\\",
            dt("2025-12-26 15:21:20.828646+00:00"),
            dt("2025-12-26 15:21:20.828646+00:00"),
            dt("2025-12-26 15:21:20.828646+00:00"),
            dt("2025-12-26 15:20:03.296831+00:00"),
            "283c8e6b-cc77-473a-8607-19c4880f09da",
        ),
    }
    assert str(records[0].job_type) == str(BG_JOB_TYPE.DOWNLOAD)
    assert str(records[0].notify_flag) == str(BG_NOTIFY.JOB_TRANSFERRED | BG_NOTIFY.JOB_ERROR)
    assert str(records[0].state) == str(JobState.TRANSFERRED)
    assert str(records[0].priority) == str(BG_JOB_PRIORITY.NORMAL)

    assert str(records[4].job_type) == str(BG_JOB_TYPE.DOWNLOAD)
    assert str(records[4].priority) == str(BG_JOB_PRIORITY.FOREGROUND)
    assert str(records[4].state) == str(JobState.TRANSFERRED)

    assert str(records[5].job_type) == str(BG_JOB_TYPE.DOWNLOAD)
    assert str(records[5].priority) == str(BG_JOB_PRIORITY.FOREGROUND)
    assert str(records[5].state) == str(JobState.QUEUED)

    assert str(records[8].job_type) == str(BG_JOB_TYPE.UPLOAD)
    assert str(records[8].notify_flag) == str(BG_NOTIFY.JOB_TRANSFERRED | BG_NOTIFY.JOB_ERROR)
    assert str(records[8].state) == str(JobState.TRANSFERRED)
    assert str(records[8].priority) == str(BG_JOB_PRIORITY.NORMAL)

    assert str(records[10].job_type) == str(BG_JOB_TYPE.DOWNLOAD)
    assert str(records[10].priority) == str(BG_JOB_PRIORITY.HIGH)
    assert str(records[10].state) == str(JobState.ERROR)


def test_bits_direct_mode(target_win: Target, fs_win: VirtualFilesystem) -> None:
    """
    Just test if direct mode works and return expected number of records

    :param target_win:
    :param fs_win:
    :return:
    """
    data_path = absolute_path("_data/plugins/os/windows/bits/ese/windows_server_2019/qmgr.db")
    target = Target.open_direct([data_path])
    records = list(target.qmgr_ese())

    assert len(records) == 13


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

# PowerShell script used to generate data
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
$TestDirectory = "C:\BITSTest"
$LogFile = "$TestDirectory\BITSTest.log"
$JobsLogFile = "$TestDirectory\BITSJobs.log"

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
    "This is a small test file for BITS upload testing.`nCreated at: $(Get-Date)" | Out-File "$TestDirectory\small_test.txt"

    # Medium file (1MB)
    $content = "A" * 1024
    1..1024 | ForEach-Object { $content } | Out-File "$TestDirectory\medium_test.txt"

    # Large file (5MB) - reduced size for faster testing
    $largeContent = "B" * (5 * 1024 * 1024)
    [System.IO.File]::WriteAllText("$TestDirectory\large_test.txt", $largeContent)

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
            $job = Start-BitsTransfer -Source "http://httpbin.org/bytes/2048" -Destination "$TestDirectory\priority_$priority.bin" -Priority $priority -DisplayName "Priority Test - $priority" -Asynchronous
            Add-JobToTracking -Job $job -TestName "PriorityLevels"

            Write-Log "Job created with priority $priority, ID: $($job.JobId)"

            # Monitor briefly but don't delete
            Start-Sleep -Seconds 5
            $job = Get-BitsTransfer -JobId $job.JobId
            Write-Log "Priority $priority job state: $($job.JobState) - JOB PRESERVED"


            if ($job.JobState -eq "Transferred") {
                Complete-BitsTransfer -BitsJob $job
                Write-Log "Basic download completed successfully - JOB PRESERVED"
            } else {
                Write-Log "Basic download job state: $($job.JobState) - JOB PRESERVED"
            }
        }
        catch {
            Write-Log "Priority test failed for $priority`: $($_.Exception.Message)"
        }
    }
}

# Test 3: Range Download using Add-BitsFile with ranges
# Test 3: Range Download using bitsadmin.exe
function Test-RangeDownload {
    Write-Log "=== Test 3: Range Download Test (Using bitsadmin.exe with Ranges) ==="
    try {
        # Test 1: Single Range Download
        Write-Log "--- Single Range Download Test ---"
        $jobName = "RangeDownload_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        $sourceUrl = "https://files.pythonhosted.org/packages/c3/d9/e71852555f039fb58628863e8266c73d3fbe281d2e74d6883f20cf28b6c7/dissect_target-3.24.tar.gz"  # 1.2Mb file
        $destPath1 = "$TestDirectory\range_download_single.bin"
        
        # Create BITS job using bitsadmin
        Write-Log "Creating BITS job: $jobName"
        $result = & bitsadmin.exe /create /download $jobName
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Job created successfully: $($result -join ' ')"
            
            # Add file with range using bitsadmin
            Write-Log "Adding file with range 0:1023 (first 1KB)"
            $result = & bitsadmin.exe /addfilewithranges $jobName $sourceUrl $destPath1 "0:1023"
            Write-Log "Resuming job..."
        }

        # Test 2: Multiple Ranges Download
        Write-Log "--- Multiple Ranges Download Test ---"
        $destPath2 = "$TestDirectory\range_download_multiple.bin"
        
        Write-Log "Adding file with multiple ranges: 1024:2047,4096:5119"
        $result = & bitsadmin.exe /addfilewithranges $jobName $sourceUrl $destPath2 "1024:2047,4096:5119"
        if ($LASTEXITCODE -eq 0) {
            Write-Log "File with multiple ranges added successfully"
            
            Write-Log "Resuming job..."
            & bitsadmin.exe /resume $jobName
        }
        
        # Test 3: Fulll Range Download
        Write-Log "--- Full Range Download Test ---"
        $destPath3 = "$TestDirectory\range_download_large.bin"
                    
        Write-Log "Adding file with large range: 25600:76799 (50KB from middle of 100KB file)"
        $result = & bitsadmin.exe /addfilewithranges $jobName $sourceUrl $destPath3 "0:1023,1024:2047,2047:eof"
        if ($LASTEXITCODE -eq 0) {
            Write-Log "File with large range added successfully"
            
            # Set priority
            & bitsadmin.exe /setpriority $jobName HIGH
            Write-Log "Set job priority to HIGH"
            
            # Resume the job
            Write-Log "Resuming job..."
            & bitsadmin.exe /resume $jobName
            
        }

        
        Write-Log "Range download tests completed using bitsadmin.exe"
        
    }
    catch {
        Write-Log "Range download test failed: $($_.Exception.Message)"
        Write-Log "Stack trace: $($_.ScriptStackTrace)"
    }
}


# Test 4: Upload Jobs to Test Server
function Test-UploadJobs {
    Write-Log "=== Test 4: Upload Jobs Test ==="

    $testFiles = @("small_test.txt", "medium_test.txt", "binary_test.bin")

    foreach ($file in $testFiles) {
        try {
            $sourcePath = "$TestDirectory\$file"
            if (!(Test-Path $sourcePath)) {
                Write-Log "Source file $sourcePath not found, skipping"
                continue
            }

            $uploadUrl = "http://$ServerAddress/$file"

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


# Test 5: Upload Jobs to Test Server
function Test-UploadJobs-Error {
        Write-Log "=== Test 5: Failed Upload Jobs Test ==="
        try {
            $sourcePath = "$TestDirectory\medium_test.txt"
            if (!(Test-Path $sourcePath)) {
                Write-Log "Source file $sourcePath not found, skipping"
                continue
            }

            $uploadUrl = "http://$ServerAddress/not_existing_folder/medium_test.txt"

            Write-Log "Uploading $file to $uploadUrl"

            $job = Start-BitsTransfer -Source $sourcePath -Destination $uploadUrl -TransferType Upload -DisplayName "Failed Upload Test - medium_test.txt" -Asynchronous
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
        }   catch {
            Write-Log "Failed Upload test failed for $file`: $($_.Exception.Message)"
        }
}

# Test 6: Custom Headers and Authentication Headers
function Test-CustomHeaders {
    Write-Log "=== Test 6: Custom Headers Test ==="
    try {
        # Create credentials for demonstration
        $customHeaders = @(
            "X-Custom-Header: TestValue123",
            "X-Test-Client: PowerShell-BITS-Testing",
            "X-Session-ID: PS-$(Get-Date -Format 'yyyyMMddHHmmss')",
            "X-User-Agent-Custom: BITS-PowerShell/1.0",
            "X-Request-Source: Automated-Testing"
        )

        # Test with httpbin basic auth endpoint
        $job = Start-BitsTransfer -Source "http://httpbin.org/headers" -CustomHeaders $customHeaders  -Authentication Basic -Destination "$TestDirectory\headers_test.json" -DisplayName "Headers Test" -Asynchronous -CustomHeaders
        Add-JobToTracking -Job $job -TestName "Headers"

        Write-Log "Headers test job created, ID: $($job.JobId)"

        $timeout = 60
        $elapsed = 0
        while (($job.JobState -eq "Transferring" -or $job.JobState -eq "Queued") -and $elapsed -lt $timeout) {
            Start-Sleep -Seconds 2
            $elapsed += 2
            $job = Get-BitsTransfer -JobId $job.JobId
        }

        if ($job.JobState -eq "Transferred") {
            Complete-BitsTransfer -BitsJob $job
            Write-Log "Headers test completed successfully - JOB PRESERVED"
        } else {
            Write-Log "Headers test final state: $($job.JobState) - JOB PRESERVED"
            if ($job.ErrorDescription) {
                Write-Log "headers error: $($job.ErrorDescription)"
            }
        }
    }
    catch {
        Write-Log "Credentials test failed: $($_.Exception.Message)"
    }
}


# Test 7: Credentials Test
function Test-Credentials {
    Write-Log "=== Test 7: Credentials Test ==="
    try {
        # Create credentials for demonstration
        $username = "testuser"
        $password = "testpass"
        $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($username, $securePassword)

        # Test with httpbin basic auth endpoint
        $job = Start-BitsTransfer -Source "http://httpbin.org/basic-auth/testuser/testpass" -Authentication Basic -Destination "$TestDirectory\auth_test.json" -Credential $credential -DisplayName "Credentials Test" -Asynchronous
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
        $failJob4 = Start-BitsTransfer -Source "http://httpbin.org/delay/120" -Destination "$TestDirectory\failed_timeout.txt" -DisplayName "Failed Download - Timeout" -Asynchronous -RetryTimeout 0 
        Add-JobToTracking -Job $failJob4 -TestName "FailedDownload-Timeout"

        Write-Log "Created timeout test job, ID: $($failJob4.JobId)"

        # Set a shorter timeout for this test
        try {
            Set-BitsTransfer -BitsJob $failJob4 -NoProgressTimeout 15
            Write-Log "Set NoProgressTimeout to 120 seconds"
        }
        catch {
            Write-Log "Could not set timeout: $($_.Exception.Message)"
        }
    }
    catch {
        Write-Log "Timeout test exception: $($_.Exception.Message)"
    }

    # Test 5: Invalid File Path (Access Denied)
    try {
        Write-Log "--- Test 5: Invalid Destination Path (Access Denied) ---"
        $invalidPath = "C:\Windows\System32\failed_access_denied.txt"  # Typically requires admin rights
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


# Test 9: Callback on Success Test (using bitsadmin)
function Test-CallbackOnSuccess {
    Write-Log "=== Test 9: Callback on Success Test (Using bitsadmin.exe) ==="
    
    try {
        # Test 1: Download with Notepad Callback
        Write-Log "--- Test 1: Download with Notepad Callback ---"
        
        $jobName1 = "CallbackDownload_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        $sourceUrl = "http://httpbin.org/bytes/2048"
        $destPath1 = "$TestDirectory\callback_download.bin"
        
        # Create BITS job
        Write-Log "Creating BITS job: $jobName1"
        & bitsadmin.exe /create /download $jobName1
        
        # Add file
        & bitsadmin.exe /addfile $jobName1 $sourceUrl $destPath1
        Write-Log "Added file to job"
        
        # Set callback to launch notepad
        & bitsadmin.exe /setnotifycmdline $jobName1 "notepad.exe" "`"$destPath1`""
        Write-Log "Set callback: notepad.exe `"$destPath1`""
        
        # Resume job
        & bitsadmin.exe /resume $jobName1
        Write-Log "Job resumed - callback will trigger on completion"
        
        # Test 2: Upload with Notepad Callback
        Write-Log "--- Test 2: Upload with Notepad Callback ---"
        
        # Create upload file
        "Upload callback test content - $(Get-Date)" | Out-File "$TestDirectory\upload_callback.txt"
        
        $jobName2 = "CallbackUpload_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        $uploadUrl = "http://$ServerAddress/callback_test.txt"
        
        # Create upload job
        Write-Log "Creating upload job: $jobName2"
        & bitsadmin.exe /create /upload $jobName2
        
        # Add upload file
        & bitsadmin.exe /addfile $jobName2 $uploadUrl "$TestDirectory\upload_callback.txt"
        Write-Log "Added upload file to job"
        
        # Set callback to launch notepad with source file
        & bitsadmin.exe /setnotifycmdline $jobName2 "notepad.exe" "`"$TestDirectory\upload_callback.txt`""
        Write-Log "Set upload callback: notepad.exe `"$TestDirectory\upload_callback.txt`""
        
        # Resume upload job
        & bitsadmin.exe /resume $jobName2
        Write-Log "Upload job resumed - callback will trigger on completion"
        
        # Test 3: Multiple Files with Batch Callback
        Write-Log "--- Test 3: Multiple Files with Batch Callback ---"
        
        # Create batch file for callback
        $batchFile = "$TestDirectory\success_callback.bat"
        "@echo off`necho BITS Success! > `"$TestDirectory\callback_result.txt`"`nnotepad.exe `"$TestDirectory\callback_result.txt`"" | Out-File $batchFile -Encoding ASCII
        
        $jobName3 = "CallbackMulti_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        
        # Create multi-file job
        Write-Log "Creating multi-file job: $jobName3"
        & bitsadmin.exe /create /download $jobName3
        
        # Add multiple files
        & bitsadmin.exe /addfile $jobName3 "http://httpbin.org/bytes/1024" "$TestDirectory\multi1.bin"
        & bitsadmin.exe /addfile $jobName3 "http://httpbin.org/bytes/2048" "$TestDirectory\multi2.bin"
        & bitsadmin.exe /addfile $jobName3 "http://httpbin.org/json" "$TestDirectory\multi3.json"
        Write-Log "Added 3 files to multi-file job"
        
        # Set batch callback
        & bitsadmin.exe /setnotifycmdline $jobName3 "`"$batchFile`"" ""
        Write-Log "Set batch callback: `"$batchFile`""
        
        # Resume multi-file job
        & bitsadmin.exe /resume $jobName3
        Write-Log "Multi-file job resumed - batch callback will trigger on completion"
        
        Write-Log "=== All Callback Jobs Created ==="
        Write-Log "Jobs created with callbacks - they will execute notepad.exe on successful completion"
        Write-Log "Use 'bitsadmin /list' to monitor job progress"
        
    }
    catch {
        Write-Log "Callback test failed: $($_.Exception.Message)"
    }
}


Create-TestFiles
Test-BasicDownload
Test-PriorityLevels
Test-RangeDownload
Test-UploadJobs
Test-UploadJobs
Test-CustomHeaders
Test-Credentials
Test-FailedDownloads
Test-CallbackOnSuccess
"""  # noqa: E501
