from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.cstruct import cstruct

if TYPE_CHECKING:
    pass

bits_def = """
    // https://learn.microsoft.com/en-us/windows/win32/api/bits/ne-bits-bg_job_type
    enum BG_JOB_TYPE : uint32 {
        DOWNLOAD     = 0x0,
        UPLOAD       = 0x1,
        UPLOAD_REPLY = 0x2
    };
    
    // https://learn.microsoft.com/en-us/windows/win32/api/bits/ne-bits-bg_job_priority
    enum BG_JOB_PRIORITY : uint32 {
        FOREGROUND = 0x0,
        HIGH       = 0x1,
        NORMAL     = 0x2,
        LOW        = 0x3
    };
    
    // https://learn.microsoft.com/en-us/windows/win32/api/bits/nf-bits-ibackgroundcopyjob-setnotifyflags
    flag BG_NOTIFY : uint32 {
        JOB_TRANSFERRED                                       = 0x1,
        JOB_ERROR                                             = 0x2,
        DISABLE                                               = 0x4,
        JOB_MODIFICATION                                      = 0x8,
        FILE_TRANSFERRED                                      = 0x16,
        FILE_RANGES_TRANSFERRED                               = 0x20
    };
    // https://learn.microsoft.com/en-us/windows/win32/api/bits/ne-bits-bg_job_state
    enum JobState : uint32 {
        QUEUED          = 0X0,
        CONNECTING      = 0X1,
        TRANSFERRING    = 0X2,
        SUSPENDED       = 0X3,
        ERROR           = 0X4,
        TRANSIENT_ERROR = 0X05,
        TRANSFERRED     = 0X06,
        ACKNOWLEDGED    = 0X07,
        CANCELLED       = 0X08,
    };
    
    struct BitsFile {
        char guid[16];
        uint32 dst_len;
        WCHAR   dst[dst_len];
        uint32 src_len;
        WCHAR   src[src_len];
        uint32 tmp_len;
        WCHAR   tmp[tmp_len];
        uint64 dl_size;
        uint64 transfer_size;
        char pad;
        uint32 drive_len;
        WCHAR   drive[drive_len];
        uint32 volume_len;
        WCHAR   volume[volume_len];
        uint32 unk1;
        uint32 unk2;
        uint64 unk3;
        uint32 unk4;
    };
    
    // a1 56 09 e1 43 af c9 42 92 e6 6f 98 56 eb a7 f6 -> DownloadJobGuid 10.3.2
    // d0 57 56 8f 2c 01 3e 4e ad 2c f4 a5 d7 65 6f af -> UploadJobGuid 10.3.2
    // 38 5c 71 03 1f 28 ca 40 98 13 9d e9 1a 5a 84 d1 -> DownloadJobGuid 10.3.1
    // d8 1e d3 68 d5 34 e1 4f 89 23 94 ab cb f4 c1 cf -> UploadJobGuid 10.3.0
    
    struct BitsJobsHeader {
        char guid[16]; // Indicate version and type (Upload/Download Job 
            // a1 56 09 e1 43 af c9 42 92 e6 6f 98 56 eb a7 f6 -> DownloadJobGuid 10.3.2
            // d0 57 56 8f 2c 01 3e 4e ad 2c f4 a5 d7 65 6f af -> UploadJobGuid 10.3.2
            // 38 5c 71 03 1f 28 ca 40 98 13 9d e9 1a 5a 84 d1 -> DownloadJobGuid 10.3.1
            // d8 1e d3 68 d5 34 e1 4f 89 23 94 ab cb f4 c1 cf -> UploadJobGuid 10.3.0
        BG_JOB_TYPE type;
        BG_JOB_PRIORITY priority;
        JobState state;
        uint32 _pad;
        char job_id[16]; // Job UUID, le
        uint32 name_len;
        WCHAR name[name_len];
        uint32 desc_len;
        WCHAR desc[desc_len];
        uint32 callback_cmd_len;
        WCHAR callback_cmd[callback_cmd_len];
        uint32 callback_args_len;
        WCHAR callback_args[callback_args_len];
        uint32 sid_len;
        WCHAR sid[sid_len];
        BG_NOTIFY notify_flag; 
    };
    struct BitsJobsFileGuidList{
        uint32 entry_count;
        char files_guid[entry_count][16];
    };
    
    struct BitsMetadata {
           uint32 transient_error_count;
           uint32 retry_delay;
           uint32 timeout;
           uint64 ctime; // Job creation time
           uint64 mtime; // modified on file added, but also on others operation
           uint64 mtime_bis; // Modified when a new file is added, but also when transfer is finished
                            // mtime and mtime_bis should be considered as evidence of activity
                            // Both are modified in CJob::UpdateModificationTime
           uint64 last_job_transferred_end; // Set in the JoBTransferred Function
                                               // Reset to zero on new file added
    }
    """
c_bits = cstruct().load(bits_def)
