# Set the default drive letter to "C"
[string]$driveletter = "C"


# Specify the directory path for the log file
$directoryPath = "C:\Intel\DiskInfo"


# Using the default drive letter, get the full device path
# and extract the UUID using a surely sub-optimal regex
[object]$fulldiskid = (Get-Partition | 
    Where DriveLetter -eq $driveletter | 
    Select DiskId | 
    Select-String "(\\\\\?\\.*?#.*?#)(.*)(#{.*})"
)

# Get the UUID from the list of regex matches
[string]$diskid = $fulldiskid.Matches.Groups[2].Value

# Get the drive model information to determine the drive type
$driveModel = (Get-PhysicalDisk | Where-Object MediaType -ne $null).MediaType

# Determine the drive type based on drive model information
$driveType = if ($driveModel -match 'HDD') { 'HDD' } else { 'SSD' }

# Define the attribute IDs for HDDs and SSDs
$hddAttributeId = 5
$ssdAttributeId = 231

# Define a mapping of SMART attribute IDs to names
$attributeNames = @{
    "5"   = "Reallocated Sectors Count / Remaining Life"
    "231" = "SSD Life Left"
    # Add more attributes as needed
}

# Retrieve the selected SMART attributes for the drive
$rawsmartdata = (Get-WmiObject -Namespace 'Root\WMI' -Class 'MSStorageDriver_ATAPISMartData' |
        Where-Object 'InstanceName' -like "*$diskid*" |
        Select-Object -ExpandProperty 'VendorSpecific'
)

# Initialize drive status variable
$driveStatus = ""

# Initialize additional attributes
$flag = ""
$value = ""
$worst = ""

# Check if disk-low-health file already exists
$lowHealthFile = Join-Path -Path $directoryPath -ChildPath "disk-low-health"
$lowHealthFlag = Test-Path -Path $lowHealthFile

# Check the drive status based on conditions
for ($i = 2; $i -lt $rawsmartdata.Length; $i++) {
    $attributeId = $rawsmartdata[$i]
    
    if (($driveType -eq 'HDD' -and $attributeId -eq $hddAttributeId) -or
        ($driveType -eq 'SSD' -and ($attributeId -eq $hddAttributeId -or $attributeId -eq $ssdAttributeId))) {
        
        $attributeName = $attributeNames["$attributeId"]  # Convert $attributeId to a string for dictionary lookup
        $flags = $rawsmartdata[$i + 1]
        $value = $rawsmartdata[$i + 3]
        $worst = $rawsmartdata[$i + 4]
        # Construct the raw attribute value by combining the two bytes that make it up
        [double]$rawvalue = ($rawsmartdata[$i + 6] * [math]::Pow(2, 8) + $rawsmartdata[$i + 5])
        
        # Check if the drive status conditions are met
        if (($driveType -eq 'HDD' -and $value -gt 10) -or
            ($driveType -eq 'SSD' -and $value -lt 60)) {
            $driveStatus = "Status: LOW"
            $flag = "Flag: $flags"
            $value = "Value: $value"
            $worst = "Worst: $worst"
            
            # If the low health file doesn't exist, create it
            if (-not $lowHealthFlag) {
                New-Item -Path $lowHealthFile -ItemType File
                $lowHealthFlag = $true
            }
        } else {
            $driveStatus = "Status: OK"
        }
        
        # Break the loop once the relevant SMART attribute is found
        break
    }
}

# Get the current timestamp
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"


# Create the directory if it doesn't exist
if (-not (Test-Path -Path $directoryPath -PathType Container)) {
    New-Item -Path $directoryPath -ItemType Directory
}

# Specify the file path for the log
$outputPath = Join-Path -Path $directoryPath -ChildPath "Status.txt"

# Create the log message with timestamp and write it to the file
$logMessage = "$timestamp`r`n$driveStatus`r`n$flag`r`n$value`r`n$worst"
$logMessage | Out-File -FilePath $outputPath -Encoding UTF8

Write-Host "Drive Status: $driveStatus"
Write-Host "Drive Status and additional information have been written to $outputPath"

