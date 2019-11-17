
  #====================================#
  # PIE - Phishing Intelligence Engine #
  # v3.5  --  November, 2019           #
  #====================================#

# Copyright 2019 LogRhythm Inc.   
# Licensed under the MIT License. See LICENSE file in the project root for full license information.

<#

INSTALL:

    Review lines 43 through 110
        Add credentials under each specified section - Office 365 Connectivity and LogRhythm Case API Integration
        Define the folder where you will deploy the Invoke-O365MessageTrace.ps1 script from

    Review Lines 111 through 187
        For each setting that you would like to enable, change the value from $false to $true
        For each enabled third party plugin, set the API key and other required paramters

USAGE:

    Configure as a scheduled task to run every 15-minutes:
        C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -command "& 'C:\PIE_INSTALL_DIR\Invoke-O365Trace.ps1'"

#>

$banner = @"
   _ \   |     _)        |     _)                   _ _|         |          |  | _)                                      ____|               _)              
  |   |  __ \   |   __|  __ \   |  __ \    _' |       |   __ \   __|   _ \  |  |  |   _' |   _ \  __ \    __|   _ \      __|    __ \    _' |  |  __ \    _ \ 
  ___/   | | |  | \__ \  | | |  |  |   |  (   |       |   |   |  |     __/  |  |  |  (   |   __/  |   |  (      __/      |      |   |  (   |  |  |   |   __/ 
 _|     _| |_| _| ____/ _| |_| _| _|  _| \__, |     ___| _|  _| \__| \___| _| _| _| \__, | \___| _|  _| \___| \___|     _____| _|  _| \__, | _| _|  _| \___| 
                                         |___/                                      |___/                                             |___/                  
"@

# Mask errors
$ErrorActionPreference= 'silentlycontinue'
#$VerbosePreference= 'continue'

# ================================================================================
# DEFINE GLOBAL PARAMETERS AND CAPTURE CREDENTIALS
#
# ****************************** EDIT THIS SECTION ******************************
# ================================================================================

# Choose how to handle credentials - set the desired flag to $true
#     Be sure to set credentials or xml file location below
$EncodedXMLCredentials = $false
$PlainText = $true

# XML Configuration - store credentials in an encoded XML (best option)
#     This file will need to be re-generated whenever the server reboots!
if ( $EncodedXMLCredentials ) {
    #
    # To generate the XML:
    #      PS C:\> Get-Credential | Export-Clixml Service-Account_cred.xml
    #
    $CredentialsFile = "C:\Path-To-Credentials-File.xml"
}

# Plain Text Credentials (not recommended)
if ( $PlainText ) {
    $username = "SERVICE-ACCOUNT@SOMEDOMAIN.COM"
    $password = "PASSWORD"
}

# Mailbox where Phishing emails will be reported
$socMailbox = "phishing@somedomain.com"

# LogRhythm Case API Integration
$LogRhythmHost = "LR Web Console Domain/IP:8501"
$caseAPItoken = ""

# Threat List to update with known spammer email addresses. Set to $true if you'd like to automatically update threat lists
$spamTracker = $false
$spammerList = "List Name"

# Case Folder and Logging
$pieFolder = "C:\PIE\INSTALLATION\DIRECTORY"

# Auto-auditing mailboxes. Set to $true if you'd like to automatically enable auditing on new O365 mailboxes
$autoAuditMailboxes = $false

# Case Tagging and User Assignment
$defaultCaseTag = "PIE" # Default value - modify to match your case tagging schema. Note "PIE" tag is used with the Case Management Dashboard.
$caseOwner = "" # Primary case owner / SOC lead
$caseCollaborators = ("lname1, fname1", "lname2, fname2") # Add as many users as you would like, separate them like so: "user1", "user2"...

# Phishing Playbook Assignment
$casePlaybook = "Phishing"
# Assign the playbookwhen the case ThreatScore reaches or exceeds casePlaybookThreat
$casePlaybookThreat = 2


# Set to true if internal e-mail addresses resolve to user@xxxx.onmicrosoft.com.  Typically true for test or lab 365 environments.
$onMicrosoft = $false

# PIE logging - Set to debug or info - output available under \logs\pierun.txt"
$pieLogLevel = "debug"
$pieLogVerbose = "True"
$pluginLogLevel = "debug"

# Set your local organization's e-mail format
# 1 = firstname.lastname@example.com
# 2 = FLastname@example.com - First Initial of First Name, full Last Name
# 3 = FirstnameLastname@example.com
$orgEmailFormat = 2


# ================================================================================
# Third Party Analytics
# ================================================================================

# For each supported module, set the flag to $true and enter the associated API key

# Auto Quarantine or Auto Ban?
$autoQuarantine = $false # Auto quarantine and/or ban the sender
$subjectAutoQuarantine = $false # Auto quarantine and create a case if the email matches the subject line regex check
$autoBan = $false # Auto blacklist known-bad senders
$threatThreshold = 5 # Actions run when the threat score is greater than the 'threatThreshold' below

# General Link Analysis - No API key required and enabled by default
$linkRegexCheck = $true
$shortLink = $false
$sucuri = $false
$getLinkInfo = $false
$spearInspector = $true

# Comodo Valkarie
$comodoValkarie = $false
$comodoApiKey = ""

# Domain Tools
$domainTools = $false
$DTapiUsername = ""
$DTapiKey = ""

# OpenDNS
$openDNS = $false
$openDNSkey =""

# VirusTotal
$virusTotal = $false
$virusTotalAPI = ""
# Determines rate limiting for Virus Total.  Set to $false if commercial license is in use to permit more than 4 queries per minute.
$virusTotalPublic = $true


# URL Scan
$urlscan = $false
$urlscanAPI = ""
#Maximum number of URLs to submit
$urlscanMax = "5"

# URL Void
$urlVoid = $false
$urlVoidIdentifier = ""
$urlVoidKey = ""

# PhishTank.com
$phishTank = $false
$phishTankAPI = ""

# 365 SafeLinks URL Trace
$safelinkTrace = $false

# Shodan.io
$shodan = $false
$shodanAPI = ""
# Set the required threatScore required for plugin.  
$shodanInitThreat = 2

# Screenshot Machine
$screenshotMachine = $false
$screenshotKey = ""

# Cisco AMP Threat Grid
$threatGrid = $false
$threatGridAPI = ""

# Palo Alto Wildfire
$wildfire = $false
$wildfireAPI = ""

# Wrike
$wrike = $false
$wrikeAPI = ""
$wrikeFolder = ""
$wrikeUser = ""


# ================================================================================
# END GLOBAL PARAMETERS
# ************************* DO NOT EDIT BELOW THIS LINE *************************
# ================================================================================


# ================================================================================
# Date, File, and Global Email Parsing
# ================================================================================

# Date Variables
$date = Get-Date
$oldAF = (Get-Date).AddDays(-10)
$96Hours = (Get-Date).AddHours(-96)
$48Hours = (Get-Date).AddHours(-48)
$24Hours = (Get-Date).AddHours(-24)
$inceptionDate = (Get-Date).AddMinutes(-16)
$phishDate = (Get-Date).AddMinutes(-31)
$day = Get-Date -Format MM-dd-yyyy

# Folder Structure
$traceLog = "$pieFolder\logs\ongoing-trace-log.csv"
$phishLog = "$pieFolder\logs\ongoing-phish-log.csv"
$spamTraceLog = "$pieFolder\logs\ongoing-outgoing-spam-log.csv"
$analysisLog = "$pieFolder\logs\analysis.csv"
$lastLogDateFile = "$pieFolder\logs\last-log-date.txt"
$tmpLog = "$pieFolder\logs\tmp.csv"
$caseFolder = "$pieFolder\cases\"
$tmpFolder = "$pieFolder\tmp\"
$confFolder = "$pieFolder\conf\"
$runLog = "$pieFolder\logs\pierun.txt"
$pieLog = "$pieFolder\logs\pielog.txt"
$log = $true
try {
    $lastLogDate = [DateTime]::SpecifyKind((Get-Content -Path $lastLogDateFile),'Utc')
}
catch {
    $lastLogDate = $inceptionDate
}


#URL Whitelist
$urlWhitelist = type "$confFolder\urlWhitelist.txt" | Sort -Unique | foreach { $_ + '*' }
$domainWhitelist = (Get-Content $confFolder\urlWhitelist.txt) | %{ ([System.Uri]$_).Host } | Select-Object -Unique | foreach { $_ + '*' }

#Set VirusTotal runtime clock to null
$vtRunTime = $null

#Set global threat score
$global:threatScore = 0

# Email Parsing Varibles
$boringFiles = @('jpg', 'png', 'ico', 'tif')    
$boringFilesRegex = [string]::Join('|', $boringFiles)
$interestingFiles = @('pdf', 'exe', 'zip', 'doc', 'docx', 'docm', 'xls', 'xlsx', 'xlsm', 'ppt', 'pptx', 'arj', 'jar', '7zip', 'tar', 'gz', 'html', 'htm', 'js', 'rpm', 'bat', 'cmd', 'apk')
$interestingFilesRegex = [string]::Join('|', $interestingFiles)



# Outlook Folder Parsing
function GetSubfolders($Parent) {
    $folders = $Parent.Folders
    foreach ($folder in $folders) {
        $Subfolder = $Parent.Folders.Item($folder.Name)
        Write-Host($folder.Name)
        GetSubfolders($Subfolder)
    }
}

# Timestamp Function
function Get-TimeStamp {
    return "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)
}


function Logger {
    Param(
        $logLevel = $pieLogLevel,
        $logSev,
        $Message,
        $Verbose = $pieLogVerbose
    )
    $cTime = "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)
    #Create phishLog if file does not exist.
    if ( $(Test-Path $runLog -PathType Leaf) -eq $false ) {
        Set-Content $runLog -Value "PIE Powershell Runlog for $date"
        Write-Output "$cTime ALERT - No runLog detected.  Created new $runLog" | Out-File $runLog
    }
    if ($LogLevel -like "info" -Or $LogLevel -like "debug") {
        if ($logSev -like "s") {
            Write-Output "$cTime STATUS - $Message" | Out-File $runLog -Append
        } elseif ($logSev -like "a") {
            Write-Output "$cTime ALERT - $Message" | Out-File $runLog -Append
        } elseif ($logSev -like "e") {
            Write-Output "$cTime ERROR - $Message" | Out-File $runLog -Append
        }
    }
    if ($LogSev -like "i") {
        Write-Output "$cTime INFO - $Message" | Out-File $runLog -Append
    }
    if ($LogSev -like "d") {
        Write-Output "$cTime DEBUG - $Message" | Out-File $runLog -Append
    }
    Switch ($logSev) {
        e {$logSev = "ERROR"}
        s {$logSev = "STATUS"}
        a {$logSev = "ALERT"}
        i {$logSev = "INFO"}
        d {$logSev = "DEBUG"}
        default {$logSev = "LOGGER ERROR"}
    }
    if ( $Verbose -eq "True" ) {
        Write-Host "$cTime - $logSev - $Message"
    }
}

#Enable support for .eml format
#From https://gallery.technet.microsoft.com/office/Blukload-EML-files-to-e1b83f7f
Function Load-EmlFile
{
    Param
    (
        $EmlFileName
    )
    Begin{
        $EMLStream = New-Object -ComObject ADODB.Stream
        $EML = New-Object -ComObject CDO.Message
    }

    Process{
        Try{
            $EMLStream.Open()
            $EMLStream.LoadFromFIle($EmlFileName)
            $EML.DataSource.OpenObject($EMLStream,"_Stream")
        }
        Catch
        {
        }
    }
    End{
        return $EML
    }
}

# Define file hashing function
function Get-Hash(
    [System.IO.FileInfo] $file = $(Throw 'Usage: Get-Hash [System.IO.FileInfo]'), 
    [String] $hashType = 'sha256')
{
    $stream = $null;  
    [string] $result = $null;
    $hashAlgorithm = [System.Security.Cryptography.HashAlgorithm]::Create($hashType )
    $stream = $file.OpenRead();
    $hashByteArray = $hashAlgorithm.ComputeHash($stream);
    $stream.Close();

    trap {
    if ($stream -ne $null) { $stream.Close(); }
    break;
    }

    # Convert the hash to Hex
    $hashByteArray | foreach { $result += $_.ToString("X2") }
    return $result
}

function Create-Hash(
    [string] $inputString, 
    [String] $hashType = 'sha256')
{
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($inputString)
    $hashAlgorithm = [System.Security.Cryptography.HashAlgorithm]::Create($hashType)
    $stringBuild = New-Object System.Text.StringBuilder

    $hashAlgorithm.ComputeHash($bytes) | ForEach-Object { $null = $StringBuild.Append($_.ToString("x2")) } 

    
    $stringBuild.ToString() 
}

function Pie-Log {
    Param(
    $logMessageBody = $messageBody,
    $logSender = $spammer,
    $logRecipient = $reportedBy,
    $logThreatScore = $threatScore,
    $logCaseNum = $caseNumber
    )
    $cTime = "{0:MM/dd/yy} {0:HH:mm:ss}" -f (Get-Date)
    #Create phishLog if file does not exist.
    if ( $(Test-Path $pieLog -PathType Leaf) -eq $false ) {
        Set-Content $pieLog -Value "PIE Powershell pielog for $date"
        Write-Output "$cTime ALERT - No pieLog detected.  Created new $pieLog" | Out-File $pieLog
    }

    Try {
        $logHash = Create-Hash -inputString $logMessageBody
    } Catch {
        Logger -logSev "e" -Message "Unable to create logMessageBody hash"
    }
    Try {
        Write-Output "$cTime; $logCaseNum; $logThreatScore; $logHash; $logSender; $logRecipient" | Out-File $pieLog -Append
    } Catch {
        Logger -logSev -e -Message "Unable to append entry to pielog.  Case: $logCaseNum Hash: $logHash"
    }
}



# Outlook Folder Parsing
function GetSubfolders($Parent) {
    $folders = $Parent.Folders
    foreach ($folder in $folders) {
        $Subfolder = $Parent.Folders.Item($folder.Name)
        Write-Host($folder.Name)
        GetSubfolders($Subfolder)
    }
}


# Function based Plugins
function pluginValkarie {
    Param (
        [string]$cmdCheckDomain,
        [string]$cmdCheckFileHash,
        [string]$cmdCheckUri,
        [Parameter(Mandatory=$true)]
        [string]$cmdApiKey
    )
    $cmdVerdict = ""
    $cmdResultID = ""
    $cmdResultMessage = ""
    $cmdReturnCode = ""
    $cmdLastAnalysis = ""

    # Domain provided by Valkyrie Verdict
    if ($cmdCheckDomain) {
        Logger -logSev "d" -Message "Domain Lookup: $cmdCheckDomain"
        $cmdStatus = "== Comodo Valkarie - Domain Lookup ==\r\nDomain: $cmdCheckDomain\r\n"
        $cmdUri = "https://verdict.valkyrie.comodo.com/api/v1/domain/query?domain=$cmdCheckDomain&analyze=true"

        $InvokeRestMethodSplat = @{
            Method      = 'GET'
            Headers     = @{'x-api-key' = $cmdApiKey}
            ContentType = 'application/json'
            Body        = ''
            Uri         = $cmdUri
            ErrorAction = 'Stop'
        }
        
        $Result = Invoke-RestMethod -Method Get -Headers @{'x-api-key' = $cmdApiKey} -ContentType 'application/json' -Uri $cmdUri -ErrorAction Stop
        $cmdResultText = $Result.domain_result_text
        $cmdResultID = $Result.domain_result_id
        switch ( $cmdResultID) {
            1{
                #1 Not found
                $cmdStatus += "Result Verdict: Domain not found\r\nResult ID: 1\r\n"
                Logger -logSev "i" -Message "Domain Lookup: $cmdCheckDomain Status: Domain not found"
            }
            2{
                #2 Safe
                $cmdStatus += "Result Verdict: Safe\r\nResult ID: 2\r\n"
                Logger -logSev "i" -Message "Domain Lookup: $cmdCheckDomain Status: Safe"
            }
            3{
                #3 Suspicious
                $cmdStatus += "Result Verdict: Suspicious\r\nResult ID: 3\r\n"
                Logger -logSev "i" -Message "Domain Lookup: $cmdCheckDomain Status: Suspicious ThreatScore Add: 1"
                $global:threatScore += 1
            }
            4{
                #4 Phishing
                $cmdStatus += "Result Verdict: Phishing\r\nResult ID: 4\r\n"
                Logger -logSev "i" -Message "Domain Lookup: $cmdCheckDomain Status: Phishing ThreatScore Add: 10"
                $global:threatScore += 10
            }
            5{
                #5 Malware
                $cmdStatus += "Result Verdict: Malware\r\nResult ID: 5\r\n"
                Logger -logSev "i" -Message "Domain Lookup: $cmdCheckDomain Status: Malware ThreatScore Add: 10"
                $global:threatScore += 10
            }
            6{
                #6 Malicious
                $cmdStatus += "Result Verdict: Malicious\r\nResult ID: 6\r\n"
                Logger -logSev "i" -Message "Domain Lookup: $cmdCheckDomain Status: Malicious ThreatScore Add: 5"
                $global:threatScore += 5
            }
            7{
                #7 PUA
                $cmdStatus += "Result Verdict: PUA\r\nResult ID: 7\r\n"
                Logger -logSev "i" -Message "Domain Lookup: $cmdCheckDomain Status: PUA"
            }
        }

        $cmdResultMessage = $Result.result_message
        $cmdReturnCode = $Result.return_code
        switch ( $cmdReturnCode ) {
            0{
                #0 Success 
                $cmdStatus += "\r\nAPI Return Message: Success\r\nAPI Return Code: 0\r\n"
                Logger -logSev "i" -Message "API Return Code: $cmdReturnCode API Return Message: Success"
            }
            3{
                #3 Error in fls lookup service
                $cmdStatus += "\r\nAPI Return Message: Error in fls lookup service\r\nAPI Return Code: 3\r\n"
                Logger -logSev "i" -Message "API Return Code: $cmdReturnCode API Return Message: Error"
            }
            100{
                #100 Requested API Key is invalid
                $cmdStatus += "\r\nAPI Return Message: Requested API Key is invalid\r\nAPI Return Code: 100\r\n"
                Logger -logSev "i" -Message "API Return Code: $cmdReturnCode API Return Message: Invalid API Key"
            }
            101{
                #101 API method is not allowed for this API key
                $cmdStatus += "\r\nAPI Return Message: API method is not allowed for this API key\r\nAPI Return Code: 101\r\n"
                Logger -logSev "i" -Message "API Return Code: $cmdReturnCode API Return Message: API Method not permitted for provided API key"
            }
            102{
                #102 Operation request limit is reached, please try again later
                $cmdStatus += "\r\nAPI Return Message: Operation request limit is reached, please try again later\r\nAPI Return Code: 102\r\n"
                Logger -logSev "i" -Message "API Return Code: $cmdReturnCode API Return Message: API limit reached"
            }
            104{
                #104 Daily operation request limit is reached, please try again later
                $cmdStatus += "\r\nAPI Return Message: Daily operation request limit is reached, please try again later\r\nAPI Return Code: 104\r\n"
                Logger -logSev "i" -Message "API Return Code: $cmdReturnCode API Return Message: Daily operation request limit reached"
            }
            500{
                #500 Internal server error occurred
                $cmdStatus += "\r\nAPI Return Message: Internal server error occurred\r\nAPI Return Code: 500\r\n"
                Logger -logSev "i" -Message "API Return Code: $cmdReturnCode API Return Message: Internal server error"
            }
            default{
                #Unknown error occurred
                $cmdStatus += "\r\nAPI Return Message: An internal PIE error has occured\r\nAPI Return Code: Error\r\n"
                Logger -logSev "e" -Message "API Return Message: An inernal PIE error has occured"
            }
        }
    } elseif ($cmdCheckFileHash) {
        $cmdStatus = "== Comodo Valkarie - File Hash Lookup ==\r\nHash: $cmdCheckFileHash\r\n"
        $cmdUri = "https://verdict.valkyrie.comodo.com/api/v1/file/query/$cmdCheckFileHash"

        $InvokeRestMethodSplat = @{
            Method      = 'GET'
            Headers     = @{'x-api-key' = $cmdApiKey}
            ContentType = 'application/json'
            Body        = ''
            Uri         = $cmdUri
            ErrorAction = 'Stop'
        }
        
        $Result = Invoke-RestMethod -Method Get -Headers @{'x-api-key' = $cmdApiKey} -ContentType 'application/json' -Uri $cmdUri -ErrorAction Stop
        $cmdVerdict = $Result.verdict
        switch ( $cmdVerdict) {
            -1{
                #-1 Clean
                $cmdStatus += "Result Verdict: Clean\r\nResult ID: -1\r\n"
                Logger -logSev "i" -Message "Hash Lookup: $cmdCheckFileHash Status: Clean"
            }
            1{
                #1 Malware
                $cmdStatus += "Result Verdict: Malware\r\nResult ID: 1\r\n"
                Logger -logSev "i" -Message "Hash Lookup: $cmdCheckFileHash Status: Malware Increase ThreatScore: 10"
                $global:threatScore += 10
            }
            2{
                #2 Not Available
                $cmdStatus += "Result Verdict: Not Availabler\nResult ID: 2\r\n"
                Logger -logSev "i" -Message "Hash Lookup: $cmdCheckFileHash Status: Not Available"
            }
            3{
                #4 PUA
                $cmdStatus += "Result Verdict: PUA\r\nResult ID: 3\r\n"
                Logger -logSev "i" -Message "Hash Lookup: $cmdCheckFileHash Status: PUA"
            }
        }
        $cmdLastAnalysis = $Result.last_analysis_date
        $cmdResultID = $Result.url_result_id
        $cmdResultMessage = $Result.result_message
        $cmdReturnCode = $Result.return_code

        switch ( $cmdReturnCode ) {
            0{
                #0 Success 
                $cmdStatus += "\r\nAPI Return Message: Success\r\nAPI Return Code: 0\r\n"
                Logger -logSev "i" -Message "API Return Code: $cmdReturnCode API Return Message: Success"
            }
            1{
                #1 SHA1 can not be empty and must be 40 characters in length
                $cmdStatus += "\r\nAPI Return Message: SHA1 can not be empty and must be 40 characters in length\r\nAPI Return Code: 1\r\n"
                Logger -logSev "i" -Message "API Return Code: $cmdReturnCode API Return Message: SHA1 can not be empty and must be 40 characters in length"
            }
            8{
                #8 Requested file not found (Absent)
                $cmdStatus += "\r\nAPI Return Message: Requested file not found\r\nAPI Return Code: 8\r\n"
                Logger -logSev "i" -Message "API Return Code: $cmdReturnCode API Return Message: Requested file not found"
            }
            9{
                #9 File exists but verdict is not given, please check later
                $cmdStatus += "\r\nAPI Return Message: File exists but verdict is not given, please check later\r\nAPI Return Code: 9\r\n"
                Logger -logSev "i" -Message "API Return Code: $cmdReturnCode API Return Message: FIle exists but verdict is not given, please check later"
            }
            3{
                #3 Error in fls lookup service
                $cmdStatus += "\r\nAPI Return Message: Error in fls lookup service\r\nAPI Return Code: 3\r\n"
                Logger -logSev "i" -Message "API Return Code: $cmdReturnCode API Return Message: Error in fls lookup service"
            }
            11{
                #11 SHA256 Not found
                $cmdStatus += "\r\nAPI Return Message: SHA256 not found in database\r\nAPI Return Code: 11\r\n"
                Logger -logSev "i" -Message "API Return Code: $cmdReturnCode API Return Message: Error"
            }
            100{
                #100 Requested API Key is invalid
                $cmdStatus += "\r\nAPI Return Message: Requested API Key is invalid\r\nAPI Return Code: 100\r\n"
                Logger -logSev "i" -Message "API Return Code: $cmdReturnCode API Return Message: Requested API Key is invalid"
            }
            101{
                #101 API method is not allowed for this API key
                $cmdStatus += "\r\nAPI Return Message: API method is not allowed for this API key\r\nAPI Return Code: 101\r\n"
                Logger -logSev "i" -Message "API Return Code: $cmdReturnCode API Return Message: API method is not allowed for this API key"
            }
            102{
                #102 Operation request limit is reached, please try again later
                $cmdStatus += "\r\nAPI Return Message: Operation request limit is reached, please try again later\r\nAPI Return Code: 102\r\n"
                Logger -logSev "i" -Message "API Return Code: $cmdReturnCode API Return Message: Operation request limit is reached"
            }
            104{
                #104 Daily operation request limit is reached, please try again later
                $cmdStatus += "\r\nAPI Return Message: Daily operation request limit is reached, please try again later\r\nAPI Return Code: 104\r\n"
                Logger -logSev "i" -Message "API Return Code: $cmdReturnCode API Return Message: Daily operation request limit is reached"
            }
            500{
                #500 Internal server error occurred
                $cmdStatus += "\r\nAPI Return Message: Internal server error occurred\r\nAPI Return Code: 500\r\n"
                Logger -logSev "i" -Message "API Return Code: $cmdReturnCode API Return Message: Internal server error occured"
            }
            default{
                #Unknown error occurred
                $cmdStatus += "\r\nAPI Return Message: An internal PIE error has occured\r\nAPI Return Code: Error\r\n"
                Logger -logSev "i" -Message "API Return Message: An internal PIE error has occured.  API Return Code: $cmdReturnCode"
            }
        }
    } elseif ($cmdCheckUri) {
        $cmdStatus = "== Comodo Valkarie - URI Lookup ==\r\nURI: $cmdCheckURI\r\n"
        # Uri provided by Valkyrie Verdict
        $cmdUri = "https://verdict.valkyrie.comodo.com/api/v1/url/query?url=$cmdCheckUri&analyze=true"

        $InvokeRestMethodSplat = @{
            Method      = 'GET'
            Headers     = @{'x-api-key' = $cmdApiKey}
            ContentType = 'application/json'
            Body        = ''
            Uri         = $cmdUri
            ErrorAction = 'Stop'
        }
        
        $Result = Invoke-RestMethod -Method Get -Headers @{'x-api-key' = $cmdApiKey} -ContentType 'application/json' -Uri $cmdUri -ErrorAction Stop
        $cmdVerdict = $Result.url_result_text
        $cmdResultID = $Result.url_result_id

        switch ( $cmdResultID) {
            1{
                #1 Not found
                $cmdStatus += "Result Verdict: URI not found\r\nResult ID: 1\r\n"
                Logger -logSev "i" -Message "URI Lookup: $cmdCheckDomain Status: URI not found"
            }
            2{
                #2 Safe
                $cmdStatus += "Result Verdict: Safe\r\nResult ID: 2\r\n"
                Logger -logSev "i" -Message "URI Lookup: $cmdCheckDomain Status: Safe"
            }
            3{
                #3 Suspicious
                $cmdStatus += "Result Verdict: Suspicious\r\nResult ID: 3\r\n"
                Logger -logSev "i" -Message "URI Lookup: $cmdCheckDomain Status: Suspicious ThreatScore Add: 1"
                $global:threatScore += 1
            }
            4{
                #4 Phishing
                $cmdStatus += "Result Verdict: Phishing\r\nResult ID: 4\r\n"
                Logger -logSev "i" -Message "URI Lookup: $cmdCheckDomain Status: Phishing ThreatScore Add: 10"
                $global:threatScore += 10
            }
            5{
                #5 Malware
                $cmdStatus += "Result Verdict: Malware\r\nResult ID: 5\r\n"
                Logger -logSev "i" -Message "URI Lookup: $cmdCheckDomain Status: Malware ThreatScore Add: 10"
                $global:threatScore += 10
            }
            6{
                #6 Malicious
                $cmdStatus += "Result Verdict: Malicious\r\nResult ID: 6\r\n"
                Logger -logSev "i" -Message "URI Lookup: $cmdCheckDomain Status: Malicious ThreatScore Add: 5"
                $global:threatScore += 5
            }
            7{
                #7 PUA
                $cmdStatus += "Result Verdict: PUA\r\nResult ID: 7\r\n"
                Logger -logSev "i" -Message "URI Lookup: $cmdCheckDomain Status: PUA"
            }
        }

        $cmdLastAnalysis = $Result.last_analysis_date
        $cmdResultMessage = $Result.result_message
        $cmdReturnCode = $Result.return_code
        switch ( $cmdReturnCode ) {
            0{
                #0 Success 
                $cmdStatus += "\r\nAPI Return Message: Success\r\nAPI Return Code: 0\r\n"
                Logger -logSev "i" -Message "API Return Code: $cmdReturnCode API Return Message: Success"
            }
            3{
                #3 Error in fls lookup service
                $cmdStatus += "\r\nAPI Return Message: Error in fls lookup service\r\nAPI Return Code: 3\r\n"
                Logger -logSev "i" -Message "API Return Code: $cmdReturnCode API Return Message: Error"
            }
            100{
                #100 Requested API Key is invalid
                $cmdStatus += "\r\nAPI Return Message: Requested API Key is invalid\r\nAPI Return Code: 100\r\n"
                Logger -logSev "i" -Message "API Return Code: $cmdReturnCode API Return Message: Invalid API Key"
            }
            101{
                #101 API method is not allowed for this API key
                $cmdStatus += "\r\nAPI Return Message: API method is not allowed for this API key\r\nAPI Return Code: 101\r\n"
                Logger -logSev "i" -Message "API Return Code: $cmdReturnCode API Return Message: API Method not permitted for provided API key"
            }
            102{
                #102 Operation request limit is reached, please try again later
                $cmdStatus += "\r\nAPI Return Message: Operation request limit is reached, please try again later\r\nAPI Return Code: 102\r\n"
                Logger -logSev "i" -Message "API Return Code: $cmdReturnCode API Return Message: API limit reached"
            }
            104{
                #104 Daily operation request limit is reached, please try again later
                $cmdStatus += "\r\nAPI Return Message: Daily operation request limit is reached, please try again later\r\nAPI Return Code: 104\r\n"
                Logger -logSev "i" -Message "API Return Code: $cmdReturnCode API Return Message: Daily operation request limit reached"
            }
            500{
                #500 Internal server error occurred
                $cmdStatus += "\r\nAPI Return Message: Internal server error occurred\r\nAPI Return Code: 500\r\n"
                Logger -logSev "i" -Message "API Return Code: $cmdReturnCode API Return Message: Internal server error"
            }
            default{
                #Unknown error occurred
                $cmdStatus += "\r\nAPI Return Message: An internal PIE error has occured\r\nAPI Return Code: Error\r\n"
                Logger -logSev "e" -Message "API Return Message: An inernal PIE error has occured"
            }
        }
    } else {
        Write-Output "No paramaters provided to check against Comodo Valkarie"
    }
     
    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$cmdStatus" -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog
    $cmdStatus += "\r\n==== Comodo Valkarie - END ====\r\n"
    Write-Output $cmdStatus.Replace("\r\n","`r`n") >> "$caseFolder$caseID\spam-report.txt"
}


# Spear Phishing Inspector
function pluginSpearIns {
    Param (
        [string]$sprMessageBody = $messageBody,
        [string]$sprDisplayName = $spammerDisplayName
    )
    Logger -logSev "s" -Message "Begin - Plugin - SpearPhish Inspector"
    Logger -logSev "i" -Message "Pull list of keyNames from LR List API"



    Logger -logSev "i" -Message "Inspecting message body for restricted names"
    $sprReport = $false
    $sprMatchType = $null
    # Add logic for inspecting message body for specific names/values

#force TLS v1.2 required by caseAPI
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#Ignore invalid SSL certification warning
add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy


    $listURL = "https://" + $LogRhythmHost + "/lr-admin-api/"
    $listToken = "Bearer $caseAPItoken"
    $listHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $listHeaders.Add("Content-type", "application/json")
    $listHeaders.Add("Authorization", $listToken)
    $listHeaders.Add("pageSize", "1000")
    $listHeaders.Add("maxItemsThreshold", "1000")

    $listGUIDURL = "$listURL/lists/"
    $output = Invoke-RestMethod -Uri $listGUIDURL -Headers $listHeaders -Method GET
    $listGuid = @($output | Where-Object name -EQ "pieExecutiveWatchlist").guid
    $listItemsURL = $listGUIDURL + $listGuid
    $output = Invoke-RestMethod -Uri $listItemsURL -Headers $listHeaders -Method GET
    [string[]]$keyNames = @($output).items.value


    # Bring Back array list of keywords/names
    # Split array for two additional variables, firstnames and lastnames
    #[string[]]$keyNames = 'bob jones', 'Eric hart', 'jt3ct'
    [string[]]$keyFNames = $null
    [string[]]$keyLNames = $null
    # Bring Back array list of keywords/names
    # Split array for two additional variables, firstnames and lastnames
    $keyNames | ForEach-Object {
        [string[]]$keyFNames += $_.Split(" ")[0]
        [string[]]$keyLNames += $_.Split(" ")[1] 
    }
    $sprStatus = "== SpearPhish Inspector ==\r\n"
    # Run through messageBody inspecting for matches
    If([string]$sprMessageBody -match ($keyNames -join "|")) {
        $sprReport = $true
        $sprMatchType = "full"
        #This should be evald by security even if threatScore = 0
        if ($threatScore -eq 0) {
            $sprStatus += "Status: Name match\r\nMatched Name: $($Matches.Values)\r\nMatch Location: Message body\r\n\r\n"
        } elseif ($threatScore -gt 0) {
            $sprStatus += "Status: Name match\r\nMatched Name: $($Matches.Values)\r\nMatch Location: Message body\r\n\r\n"

        }
        Logger -logSev "i" -Message "Restricted name: $($Matches.Values) identified"
    } elseif ($threatScore -gt 0 -AND ([string]$sprMessageBody -match ($keyFNames -join "|") -or ([string]$sprMessageBody -match ($keyLNames -join "|")))) {
        #This should be evald by security due to threatScore and partial keyName match
        $sprReport = $true
        $sprMatchType = "partial"
        $sprStatus += "Status: Partial name match\r\nMatched Name: $($Matches.Values)\r\nMatch Location: Message body\r\n\r\n"
        Logger -logSev "i" -Message "Threat Score greater than 2.  Restricted Partial Name: $($Matches.Values)"
    } else {
        Logger -logSev "i" -Message "No key names identified in messageBody"
    }

    # Run through Spammer Display name inspecting for matches
    If([string]$sprDisplayName -match ($keyNames -join "|")) {
        $sprReport = $true
        $sprMatchType = "full"
        #This should be evald by security even if threatScore = 0
        if ($threatScore -eq 0) {
            $sprStatus += "Status: Name match\r\nMatched Name: $($Matches.Values)\r\nMatch Location: Sender display name\r\n\r\n"
        } elseif ($threatScore -gt 0) {
            $sprStatus += "Status: Name match\r\nMatched Name: $($Matches.Values)\r\nMatch Location: Sender display name\r\n\r\n"
        }
        Logger -logSev "i" -Message "Restricted name: $($Matches.Values) identified"
    } elseif ($threatScore -gt 0 -AND ([string]$sprDisplayName -match ($keyFNames -join "|") -or ([string]$sprDisplayName -match ($keyLNames -join "|")))) {
        #This should be evald by security due to threatScore and partial keyName match
        $sprReport = $true
        $sprMatchType = "partial"
        $sprStatus = "Status: Partial name match\r\nMatched Name: $($Matches.Values)\r\nMatch Location: Sender display name\r\n\r\n"
        Logger -logSev "i" -Message "Threat Score greater than 2.  Restricted Partial Name: $($Matches.Values)"
    } else {
        Logger -logSev "i" -Message "No key names identified in messageBody"
    }

    if ($sprReport -eq $true) {
        if ($threatScore -eq 0) {
            $global:threatScore += 2
            $sprStatus += "Summary: No indicators of URL/File based threats present.  A $sprMatchType name match with monitor list has been identified.  Review e-mail message content for Social Engineering."
            
        } elseif ($threatScore -gt 0) {
            $global:threatScore += 4
            $sprStatus += "Summary: Indicators of URL/File based threats present.  A $sprMatchType name match with monitor list has been identified."
        }

        & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$sprStatus" -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog
        $sprStatus += "\r\n====  SpearPhish Inspector - END ====\r\n"
        Write-Output $sprStatus.Replace("\r\n","`r`n") >> "$caseFolder$caseID\spam-report.txt"

    }

    # Add logic to hash message body.  Supply to LR function to validate if is member of existing list.  If not a member of list treat as unique

    Logger -logSev "s" -Message "End - Plugin - SpearPhish Inspector"
}

function Submit-Hash {

    Try {
        $logHash = Create-Hash -inputString $messageBody
    } Catch {
        Logger -logSev "e" -Message "Unable to create logMessageBody hash"
    }
    #force TLS v1.2 required by caseAPI
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#Ignore invalid SSL certification warning
add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy


    $listURL = "https://" + $LogRhythmHost + "/lr-admin-api/"
    $listToken = "Bearer $caseAPItoken"
    $listHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $listHeaders.Add("Content-type", "application/json")
    $listHeaders.Add("Authorization", $listToken)
    $listHeaders.Add("pageSize", "1000")
    $listHeaders.Add("maxItemsThreshold", "1000")
    $listGUIDURL = "$listURL/lists/"
    Try {    
        $output = Invoke-RestMethod -Uri $listGUIDURL -Headers $listHeaders -Method GET
    } Catch {
        Logger -logSev "e" -Message "Failed to retrieve list of LogRhythm Lists"
        Logger -logSev "d" -Message "$_.Exception.Message"
    }
    Logger -logSev "s" -Message "Begin - Submit Hash to LogRhythm List"
    if ($threatScore -gt 0 ) {
        Logger -logSev "i" -Message "ThreatScore greater than zero.  Submitting message body hash to LogRhythm"




        $listGuid = @($output | Where-Object name -EQ "pieRiskyMessageHashes").guid
        $listType = @($output | Where-Object name -EQ "pieRiskyMessageHashes").listType
        $listUpdate = $listGUIDURL + $listGuid + "/items"
        Logger -logSev "d" -Message "List Update URL: $listUpdate"
        

        #listType = GeneralValue/String
        if($listType -eq "GeneralValue") {
            $listType = "StringValue"
            $listItemDataType = "String"
        }
        Logger -logSev "d" -Message "ListType: $listType ListItemDataType: $listItemDataType"
		$exp_date = (Get-Date).AddDAys(7).ToString("yyyy-MM-dd")
		
	    $payload = @('{ "items": 
[
{
	"displayValue": "List",
	"expirationDate": "' + $exp_date + '",
	"isExpired": false,
	"isListItem": false,
	"isPattern": false,
	"listItemDataType": "' + $listItemDataType + '",
	"listItemType": "' + $listType + '",
	"value": "' + $logHash + '",
	"valueAsListReference": {}
}
]}')
			
	    try {
            
		    $output = Invoke-RestMethod -Uri $listUpdate -Headers $listHeaders -Method POST -Body $payload
            Logger -logSev "i" -Message "Hash $logHash successfully added to list: pieRiskyMessageHashes"

	    } catch {
            Logger -logSev "e" -Message "Hash $logHash failed append to list: pieRiskyMessageHashes"
            Logger -logSev "d" -Message "$_.Exception.Message"
	    }
    } else {
        Logger -logSev "i" -Message "Message Hash  submitted.  Message ThreatScore: $threatScore"

        Logger -logSev "i" -Message "ThreatScore equal to zero.  Submitting benign hash to LogRhythm"




        $listGuid = @($output | Where-Object name -EQ "pieBenignMessageHashes").guid
        $listType = @($output | Where-Object name -EQ "pieRiskyMessageHashes").listType
        $listUpdate = $listGUIDURL + $listGuid + "/items"
        Logger -logSev "d" -Message "List Update URL: $listUpdate"
        

        #listType = GeneralValue/String
        if($listType -eq "GeneralValue") {
            $listType = "StringValue"
            $listItemDataType = "String"
        }
        Logger -logSev "d" -Message "ListType: $listType ListItemDataType: $listItemDataType"
		$exp_date = (Get-Date).AddDAys(7).ToString("yyyy-MM-dd")
		
	    $payload = @('{ "items": 
[
{
	"displayValue": "List",
	"expirationDate": "' + $exp_date + '",
	"isExpired": false,
	"isListItem": false,
	"isPattern": false,
	"listItemDataType": "' + $listItemDataType + '",
	"listItemType": "' + $listType + '",
	"value": "' + $logHash + '",
	"valueAsListReference": {}
}
]}')
			
	    try {
            
		    $output = Invoke-RestMethod -Uri $listUpdate -Headers $listHeaders -Method POST -Body $payload
            Logger -logSev "i" -Message "Hash $logHash successfully added to list: pieBenignMessageHashes"

	    } catch {
            Logger -logSev "e" -Message "Hash $logHash failed append to list: pieBenignMessageHashes"
            Logger -logSev "d" -Message "$_.Exception.Message"
	    }
    }

    Logger -logSev "s" -Message "End - Submit Hash to LogRhythm List"
}

# Link and Domain Verification
$IPregex='(?<Address>((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))'
[regex]$URLregex = '(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?'
[regex]$IMGregex =  '(http(s?):)([/|.|\w|\s|-])*\.(?:jpg|gif|png)'


Logger -logSev "s" -Message "BEGIN NEW PIE EXECUTION"
# ================================================================================
# Office 365 API Authentication
# ================================================================================

if ( $EncodedXMLCredentials ) {
    try {
        $cred = Import-Clixml -Path $CredentialsFile
        $Username = $cred.Username
        $Password = $cred.GetNetworkCredential().Password
    } catch {
        Write-Error ("Could not find credentials file: " + $CredentialsFile)
        Logger -logSev "e" -Message "Could not find credentials file: $CredentialsFile"
        Break;
    }
}

try {
    if (-Not ($password)) {
        $cred = Get-Credential
    } Else {
        $securePass = ConvertTo-SecureString -string $password -AsPlainText -Force
        $cred = New-Object -typename System.Management.Automation.PSCredential -argumentlist $username, $securePass
    }

    $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $cred -Authentication Basic -AllowRedirection
    Import-PSSession $Session -AllowClobber
    Logger -logSev "s" -Message "Established Office 365 connection"
} Catch {
    Write-Error "Access Denied..."
    Logger -logSev "e" -Message "Office 365 connection Access Denied"
    Exit 1
    Break;
}


# ================================================================================
# MEAT OF THE PIE
# ================================================================================
Logger -logSev "i" -Message "Check for New Reports"
if ( $log -eq $true) {
    if ( $autoAuditMailboxes -eq $true ) {
        Logger -logSev "s" -Message "Begin Inbox Audit Update"
        # Check for mailboxes where auditing is not enabled and is limited to 1000 results
        $UnauditedMailboxes=(Get-Mailbox -Filter {AuditEnabled -eq $false}).Identity
        $UAMBCount=$UnauditedMailboxes.Count
        if ($UAMBCount -gt 0){
            Write-Host "Attempting to enable auditing on $UAMBCount mailboxes, please wait..." -ForegroundColor Cyan
            Logger -logSev "d" -Message "Attempting to enable auditing on $UAMBCount mailboxes"
            $UnauditedMailboxes | ForEach-Object { 
                Try {
                    $auditRecipient = Get-Recipient $_
                    if ( $($auditRecipient.Count) ) {
                        for ($i = 0 ; $i -lt $auditRecipient.Count ; $i++) {
                            Logger -logSev "d" -Message "Setting audit policy for mailbox: $auditRecipient[$i]"
                            Set-Mailbox -Identity $($auditRecipient[$i].guid.ToString()) -AuditLogAgeLimit 90 -AuditEnabled $true -AuditAdmin UpdateCalendarDelegation,UpdateFolderPermissions,UpdateInboxRules,Update,Move,MoveToDeletedItems,SoftDelete,HardDelete,FolderBind,SendAs,SendOnBehalf,Create,Copy,MessageBind -AuditDelegate UpdateFolderPermissions,UpdateInboxRules,Update,Move,MoveToDeletedItems,SoftDelete,HardDelete,FolderBind,SendAs,SendOnBehalf,Create -AuditOwner UpdateCalendarDelegation,UpdateFolderPermissions,UpdateInboxRules,Update,MoveToDeletedItems,Move,SoftDelete,HardDelete,Create,MailboxLogin
                        }
                    } else {
                        Logger -logSev "d" -Message "Setting audit policy for mailbox: $auditRecipient"
                        Set-Mailbox -Identity $($auditRecipient.guid.ToString()) -AuditLogAgeLimit 90 -AuditEnabled $true -AuditAdmin UpdateCalendarDelegation,UpdateFolderPermissions,UpdateInboxRules,Update,Move,MoveToDeletedItems,SoftDelete,HardDelete,FolderBind,SendAs,SendOnBehalf,Create,Copy,MessageBind -AuditDelegate UpdateFolderPermissions,UpdateInboxRules,Update,Move,MoveToDeletedItems,SoftDelete,HardDelete,FolderBind,SendAs,SendOnBehalf,Create -AuditOwner UpdateCalendarDelegation,UpdateFolderPermissions,UpdateInboxRules,Update,MoveToDeletedItems,Move,SoftDelete,HardDelete,Create,MailboxLogin
                    }

                } Catch {
                    #Catch handles conflicts where multiple users share the same firstname, lastname.
                    Write-Host "Issue: $($PSItem.ToString())"
                    Logger -logSev "e" -Message "Set-Mailbox: $($PSItem.ToString())"
                }

            }
            Logger -logSev "i" -Message "Finished attempting to enable auditing on $UAMBCount mailboxes"
            Write-Host "Finished attempting to enable auditing on $UAMBCount mailboxes." -ForegroundColor Yellow
        }
        if ($UAMBCount -eq 0){} # Do nothing, all mailboxes have auditing enabled.
        Logger -logSev "s" -Message "End Inbox Audit Update"
    }

    #Create phishLog if file does not exist.
    if ( $(Test-Path $phishLog -PathType Leaf) -eq $false ) {
        Set-Content $phishLog -Value "MessageTraceId,Received,SenderAddress,RecipientAddress,FromIP,ToIP,Subject,Status,Size,MessageId"
        Logger -logSev "a" -Message "No phishlog detected.  Created new $phishLog"
    }

    # scrape all mail - ongiong log generation
    # new scrape mail - by sslawter - LR Community
    Logger -logSev "s" -Message "Begin processing messageTrace"
    foreach ($page in 1..1000) {
        $messageTrace = Get-MessageTrace -StartDate $lastlogDate -EndDate $date -Page $page | Select MessageTraceID,Received,*Address,*IP,Subject,Status,Size,MessageID
        if ($messageTrace.Count -ne 0) {
            $messageTraces += $messageTrace
            Write-Verbose "Page #: $page"
            Logger -logSev "i" -Message "Processing page: $page"
        }
        else {
            break
        }
    }
    $messageTracesSorted = $messageTraces | Sort-Object Received
    $messageTracesSorted | Export-Csv $traceLog -NoTypeInformation -Append
    ($messageTracesSorted | Select-Object -Last 1).Received.GetDateTimeFormats("O") | Out-File -FilePath $lastLogDateFile -Force -NoNewline
    Logger -logSev "s" -Message "Completed messageTrace"

    # Search for Reported Phishing Messages
    Try {
        Logger -logSev "i" -Message "Loading previous reports to phishHistory"
        $phishHistory = Get-Content $phishLog | ConvertFrom-Csv -Header "MessageTraceID","Received","SenderAddress","RecipientAddress","FromIP","ToIP","Subject","Status","Size","MessageID"
    } Catch {
        Logger -logSev "e" -Message "Unable to read file: $phishLog"
        Logger -logSev "s" -Message "PIE Execution Halting"
        Remove-PSSession $Session
        exit 1
    }

    Try {
        Logger -logSev "i" -Message "Loading current reports to phishTrace"
        $phishTrace = Get-MessageTrace -RecipientAddress $socMailbox -Status Delivered | Select-Object MessageTraceID,Received,SenderAddress,RecipientAddress,FromIP,ToIP,Subject,Status,Size,MessageID | Sort-Object Received
    } Catch {
        Logger -logSev "e" -Message "Unable to retrieve phishTrace from o365"
        Logger -logSev "s" -Message "PIE Execution Halting"
        Remove-PSSession $Session
    }
    try {
        Logger -logSev "i" -Message "Writing phishTrace to $tmpLog"
        $phishTrace | Export-Csv $tmpLog -NoTypeInformation
    } Catch {
        Logger -logSev "e" -Message "Unable to write file: $tmpLog"
        Logger -logSev "s" -Message "PIE Execution Halting"
        Remove-PSSession $Session
    }
    
    Try {
        Logger -logSev "i" -Message "Loading phishNewReports"
        $phishNewReports = Get-Content $tmpLog | ConvertFrom-Csv -Header "MessageTraceID","Received","SenderAddress","RecipientAddress","FromIP","ToIP","Subject","Status","Size","MessageID"
    } Catch {
        Logger -logSev "e" -Message "Unable to read to: $tmpLog"
        Logger -logSev "s" -Message "PIE Execution Halting"
        Remove-PSSession $Session
        exit 1
    }
    if ((get-item $tmpLog).Length -gt 0) {
        Logger -logSev "i" -Message "Populating newReports"
        $newReports = Compare-Object $phishHistory $phishNewReports -Property MessageTraceID -PassThru -IncludeEqual | Where-Object {$_.SideIndicator -eq '=>' } | Select-Object MessageTraceID,Received,SenderAddress,RecipientAddress,FromIP,ToIP,Subject,Status,Size,MessageID
        Logger -logSev "d" -Message "newReports Sender Address: $($newReports.SenderAddress)"
    } 
    if ($newReports -eq $null) {
        Logger -logSev "i" -Message "No new reports detected"
    }
    if ($newReports -ne $null) {
        Logger -logSev "i" -Message "New reports detected reported by $($newReports.RecipientAddress)"
        Logger -logSev "i" -Message "Connecting to local inbox"
        # Connect to local inbox #and check for new mail
        $outlookInbox = 6
        $outlook = new-object -com outlook.application
        $ns = $outlook.GetNameSpace("MAPI")
        $olSaveType = "Microsoft.Office.Interop.Outlook.OlSaveAsType" -as [type]
        $rootFolders = $ns.Folders | ?{$_.Name -match $socMailbox}
        $inbox = $ns.GetDefaultFolder($outlookInbox)
        $inboxConfigCheck = $inbox.Folders.Count
        Logger -logSev "i" -Message "Outlook Inbox Folder Count: $inboxConfigCheck"
        if ($inboxConfigCheck -ge 2 ) {
            Logger -logSev "d" -Message "Outlook Connection Test check successful"
        } else {
            Logger -logSev "e" -Message "Outlook Connection Test check failed.  Validate Outlook inbox established and verify permissions"
            Logger -logSev "s" -Message "PIE Execution Halting"
            exit 1
        }
        Logger -logSev "i" -Message "Connecting to local inbox complete"
        #$messages = $inbox.items
        #$phishCount = $messages.count
        
        Logger -logSev "s" -Message "Begin processing newReports"
        $newReports | ForEach-Object {
            # Setup Object for JSON output
            $jsonPie = New-Object -TypeName psobject -Property @{}
            # Track the user who reported the message
            $reportedBy = $($_.SenderAddress)
            $reportedSubject = $($_.Subject)
            Logger -logSev "i" -Message "Sent By: $($_.SenderAddress)  reportedSubject: $reportedSubject"            
            #Access local inbox and check for new mail
            $messages = $inbox.items
            $phishCount = $messages.count

            Logger -logSev "s" -Message "Begin AutoQuarantine block"    
            # AutoQuarantinebySubject
            if ( $subjectAutoQuarantine -eq $true ) {

                $subjectRegex = 'has\ been\ limited',
                                'We\ have\ locked',
                                'has\ been\ suspended',
                                'unusual\ activity',
                                'notifications\ pending',
                                'your\ (customer\ )?account\ has',
                                'your\ (customer\ )?account\ was',
                                'Periodic\ Maintenance',
                                'refund\ not\ approved',
                                'account\ (is\ )?on\ hold',
                                'wire\ transfer',
                                'secure\ update',
                                'temporar(il)?y\ deactivated',
                                'verification\ required'
                                #'new voice(\ )?mail'
                #[string]
                If($reportedSubject -match ($subjectRegex -join "|")) {
                    # Autoquarantine!
                    $subjectQuarantineNote = "Initiating auto-quarantine based on suspicious email subject RegEx matching. Copying messages to the Phishing inbox and hard-deleting from all recipient inboxes."
                    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$subjextQuarantineNote" -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog
                    sleep 5
                    if ( $EncodedXMLCredentials ) {
                        & $pieFolder\plugins\O365Ninja.ps1 -scrapeMail -sender "$spammer" -nuke -encodedXMLCredentials "$EncodedXMLCredentials" -socMailbox $socMailBox -LogRhythmHost $LogRhythmHost -caseAPItoken $caseAPItoken
                    } else {
                        & $pieFolder\plugins\O365Ninja.ps1 -scrapeMail -sender "$spammer" -nuke -username $username -password $password -socMailbox $socMailBox -LogRhythmHost $LogRhythmHost -caseAPItoken $caseAPItoken
                    }
                } 
            }
            Logger -logSev "s" -Message "End AutoQuarantine block"  

            Logger -logSev "s" -Message "Begin Phishing Analysis block"
            Logger -logSev "d" -Message "Outlook Inbox Message Count: $phishCount"
            # Analyze reported phishing messages, and scrape any other unreported messages    
            if ( $phishCount -gt 0 ) {
                # Set the initial Threat Score to 0 - increases as positive indicators for malware are observed during analysis
                $threatScore = 0
                # Extract reported messages
                Logger -logSev "i" -Message "Parse Outlook messages"  
                $fileHashes = $null
                foreach($message in $messages){
                    Logger -logSev "d" -Message "Outlook Message Subject: $($message.Subject)"                      
                    #Clear variable $msubject
                    $msubject = $null
                    #Match known translation issues
                    Logger -logSev "i" -Message "Filtering known bad characters in `$message.Subject: $($message.Subject)" 
                        
                    #Created regex to identify any and all odd characters in subject and replace with ?
                    $specialPattern = "[^\u0000-\u007F]"
                    if ($($message.Subject) -Match "$specialPattern") { 
                        $msubject = $message.Subject -Replace "$specialPattern","?"
                        Logger -logSev "i" -Message "Invalid characters identified, cleaning non-ASCII: $($message.Subject)" 
                        Logger -logSev "i" -Message "Post filter `$msubject: $($msubject)" 
                        $trueDat = $true 
                    } else {
                        $trueDat = $false
                        $msubject = $null
                    }
                    Logger -logSev "d" -Message "Post filter `$reportedSubject: $reportedSubject"
                    Logger -logSev "d" -Message "Post filter `$message.Subject: $($message.subject)"
                    Logger -logSev "d" -Message "Post filter `$msubject: $msubject"

                    if ($($message.Subject) -eq $reportedSubject -OR $msubject -eq $reportedSubject) {
                        Logger -logSev "i" -Message "Outlook message.subject matched reported message Subject"
                        #Add $newReport to $phishLog
                        Logger -logSev "i" -Message "Adding new report to phishLog for recipient $($_.RecipientAddress)"
                        Try {
                            echo "`"$($_.MessageTraceID)`",`"$($_.Received)`",`"$($_.SenderAddress)`",`"$($_.RecipientAddress)`",`"$($_.FromIP)`",`"$($_.ToIP)`",`"$($_.Subject)`",`"$($_.Status)`",`"$($_.Size)`",`"$($_.MessageID)`"" | Out-File $phishLog -Encoding utf8 -Append
                        } Catch {
                            Logger -logSev "e" -Message "Unable to write to: $phishLog"
                            Logger -logSev "s" -Message "PIE Execution Halting"
                            Remove-PSSession $Session
                            exit 1
                        }
                        $msubject = $message.subject
                        $mBody = $message.body
                        Logger -logSev "s" -Message "Parsing attachments"
                        $message.attachments| ForEach-Object {
                            Logger -logSev "i" -Message "File $($_.filename)"
                            $attachment = $_.filename
                            $attachmentFull = $tmpFolder+$attachment
                            $saveStatus = $null
                            If (-Not ($a -match $boringFilesRegex)) {
                                Try {
                                    $_.SaveAsFile($attachmentFull)
                                    Logger -logSev "i" -Message "Saving file: $attachmentFull"
                                    $saveStatus = $true
                                } Catch {
                                    Logger -logSev "e" -Message "Unable to write file: $attachmentFull"
                                    $saveStatus = $false
                                }
                                if ($saveStatus -eq $true) {
                                    if ($attachment -match $interestingFilesRegex -and $attachment -NotLike "*.msg" -and $attachment -NotLike "*.eml" ) {
                                        Start-Sleep 1
                                        $fileHashes += @(Get-FileHash -Path "$attachmentFull" -Algorithm SHA256)
                                        Logger -logSev "i" -Message "Hash Track for $attachmentFull to variable fileHashes"
                                    } else {
                                        Logger -logSev "d" -Message "Hash Track for $attachment does not match interestingFilesRegex"
                                    }
                                }
                            }
                        }
                        Logger -logSev "s" -Message "End Parsing attachments"
                        Logger -logSev "i" -Message "Moving Outlook message to COMPLETED folder"
                        $MoveTarget = $inbox.Folders.item("COMPLETED")
                        [void]$message.Move($MoveTarget) 
                    }
                }
                Logger -logSev "i" -Message "Setting directoryInfo"
                $directoryInfo = Get-ChildItem $tmpFolder | findstr "\.msg \.eml" | Measure-Object
    
                Logger -logSev "i" -Message "If .msg or .eml observed proceed"
                if ( $directoryInfo.count -gt 0 ) {
                    $reportedMsgAttachments = @(@(Get-ChildItem $tmpFolder).Name)

                    if ( ($reportedMsgAttachments -like "*.msg*") )  {
                        Logger -logSev "s" -Message "Processing .msg e-mail format"
                        #foreach($attachment in $reportedMsgAttachments) {
                            Logger -logSev "d" -Message "Processing reported e-mail attachments: $tmpFolder$attachment"
                            Logger -logSev "i" -Message "Loading submitted .msg e-mail"
                            $msg = $outlook.Session.OpenSharedItem("$tmpFolder$attachment")
                                
                            $subject = $msg.ConversationTopic
                            Logger -logSev "d" -Message "Message subject: $subject"
                            $messageBody = $msg.Body
                            Logger -logSev "d" -Message "Processing Headers"
                            $headers = $msg.PropertyAccessor.GetProperty("http://schemas.microsoft.com/mapi/proptag/0x007D001E")
                            Logger -logSev "d" -Message "Writing Headers: $tmpFolder\headers.txt"
                            try {
                                $headers > "$tmpFolder\headers.txt"
                            } Catch {
                                Logger -logSev "e" -Message "Error writing to file path $tmpFolder\headers.txt"
                            }

                            #Clear file hashes text file
                            Try {
                                $null > "$tmpFolder\hashes.txt"
                            } Catch {
                                Logger -logSev "e" -Message "Error writing to file path $tmpFolder\hashes.txt"
                            }
                            
                            Logger -logSev "s" -Message "Begin Parsing URLs"
                            Logger -logSev "d" -Message "Resetting $tmpFolder\links.txt"
                            #Clear links text file
                            Try {
                                $null > "$tmpFolder\links.txt"
                            } Catch {
                                Logger -logSev "e" -Message "Error writing to file path $tmpFolder\links.txt"
                            }
                                
                            #Load links
                            #Check if HTML Body exists else populate links from Text Body
                            Logger -logSev "i" -Message "Identifying URLs"
                            if ( $($msg.Body.Length -gt 0) ) {
                                Logger -logSev "d" -Message "Processing URLs from Message body - Last Effort Approach"
                                $getLinks = $URLregex.Matches($($msg.Body)).Value.Split("") | findstr http
                                
                            } 
                            else {
                                Logger -logSev "a" -Message "Processing URLs from HTML body"
                                $getLinks = $URLregex.Matches($($msg.HTMLBody)).Value.Split("") | findstr http
                            }

                                
                            Logger -logSev "s" -Message "Begin .msg attachment block"
                            $attachmentCount = $msg.Attachments.Count
                            Logger -logSev "i" -Message "Attachment Count: $attachmentCount"
                            if ( $attachmentCount -gt 0 ) {
                                # Validate path tmpFolder\attachments exists
                                if (Test-Path "$tmpFolder\attachments" -PathType Container) {
                                    Logger -logSev "i" -Message "Folder $tmpFolder\attatchments\ exists"
                                } else {
                                    Logger -logSev "i" -Message "Creating folder: $tmpFolder\attatchments\"
                                    Try {
                                        New-Item -Path "$tmpFolder\attachments" -type Directory -Force
                                    } Catch {
                                        Logger -logSev "e" -Message "Unable to create folder: $tmpFolder\attatchments\"
                                    }
                                }
                                # Get the filename and location
                                $attachedFileName = @(@($msg.Attachments | Select-Object Filename | findstr -v "FileName -") -replace "`n|`r").Trim() -replace '\s',''
                                Logger -logSev "i" -Message "Attached File Name: $attachedFileName"
                                $msg.attachments|ForEach-Object {
                                    $attachmentName = $_.filename
                                    $attachmentFull = $tmpFolder + "\attachments\" + $attachmentName
                                    Logger -logSev "i" -Message "Attachment Name: $attachmentName"
                                    Logger -logSev "d" -Message "Checking attachment against interestingFilesRegex"
                                    $saveStatus = $null
                                    If ($attachmentName -match $interestingFilesRegex) {
                                        Try {
                                            $_.saveasfile($attachmentFull)
                                            $saveStatus = $true
                                            Logger -logSev "i" -Message "Saving Attachment to destination: $tmpFolder\attachments\$attachmentName"
                                        } Catch {
                                            $saveStatus = $false
                                            Logger -logSev "e" -Message "Unable to save Attachment to destination: $tmpFolder\attachments\$attachmentName"
                                        }
                                        if ($saveStatus -eq $true) {
                                            if ($attachmentName -match $interestingFilesRegex -and $attachmentName -NotLike "*.msg*" -and $attachmentName -NotLike "*.eml*" ) {
                                                Start-Sleep 1
                                                $fileHashes += @(Get-FileHash -Path "$attachmentFull" -Algorithm SHA256)
                                                Logger -logSev "i" -Message "Adding hash for $attachmentFull to variable fileHashes"
                                            }
                                        }
                                    }
                                }
                            }

                            # Clean Up the SPAM
                            Logger -logSev "d" -Message "Moving e-mail message to SPAM folder"
                            $MoveTarget = $inbox.Folders.item("SPAM")
                            [void]$msg.Move($MoveTarget)
                            $spammer = $msg.SenderEmailAddress
                            Logger -logSev "i" -Message "Spammer set to: $spammer"
                            $spammerDisplayName = $msg.SenderName
                            Logger -logSev "i" -Message "Spammer Display Name set to: $spammerDisplayName"
                        #}
                    } elseif ( ($reportedMsgAttachments -like "*.eml*") )  {
                        Logger -logSev "s" -Message "Processing .eml e-mail format"
                        $emlAttachment = $reportedMsgAttachments -like "*.eml*"
                        Logger -logSev "d" -Message "Processing reported e-mail attachments: $emlAttachment"
                        Logger -logSev "i" -Message "Loading submitted .eml e-mail to variable msg"
                        $msg = Load-EmlFile("$tmpFolder$emlAttachment ")

                        $subject = $msg.Subject
                        Logger -logSev "d" -Message "Message subject: $subject"

                        #HTML Message Body
                        #$messageBody = $msg.HTMLBody
                        #Plain text Message Body
                        $body = $msg.BodyPart.Fields | Select-Object Name, Value | Where-Object name -EQ "urn:schemas:httpmail:textdescription"
                        $messageBody = $body.Value


                        #Headers
                        Logger -logSev "d" -Message "Processing Headers"
                        $headers = $msg.BodyPart.Fields | Select-Object Name, Value | Where-Object name -Like "*header*" | Format-List
                        Logger -logSev "d" -Message "Writing Headers: $tmpFolder\headers.txt"
                        Try {
                            Write-Output $headers > "$tmpFolder\headers.txt"
                        } Catch {
                            Logger -logSev "e" -Message "Unable to write Headers to path $tmpFolder\headers.txt"
                        }

                        #Clear file hashes text file
                        Try {
                            $null > "$tmpFolder\hashes.txt"
                        } Catch {
                            Logger -logSev "e" -Message "Error writing to file path $tmpFolder\hashes.txt"
                        }
                        
                        Logger -logSev "s" -Message "Begin Parsing URLs"
                            
                        #Clear links text file
                        Logger -logSev "d" -Message "Resetting $tmpFolder\links.txt"
                        Try {
                            $null > "$tmpFolder\links.txt"
                        } Catch {
                            Logger -logSev "e" -Message "Error writing to file path $tmpFolder\links.txt"
                        }
                        
                        #Load links
                        #Check if HTML Body exists else populate links from Text Body
                        Logger -logSev "i" -Message "Identifying URLs"
                        if ( $($msg.HTMLBody.Length -gt 0) ) {
                            Logger -logSev "d" -Message "Processing URLs from message HTML body"
                            $getLinks = $URLregex.Matches($($msg.HTMLBody)).Value.Split("") | findstr http
                        } 
                        else {
                            Logger -logSev "a" -Message "Processing URLs from Text body - Last Effort Approach"
                            $getLinks = $URLregex.Matches($($msg.TextBody)).Value.Split("") | findstr http
                        }

                        

                        Logger -logSev "s" -Message "Begin .eml attachment block"
                        $attachmentCount = $msg.Attachments.Count
                        Logger -logSev "i" -Message "Attachment Count: $attachmentCount"

                        if ( $attachmentCount -gt 0 ) {
                            # Validate path tmpFolder\attachments exists
                            if (Test-Path "$tmpFolder\attachments" -PathType Container) {
                                Logger -logSev "i" -Message "Folder $tmpFolder\attatchments\ exists"
                            } else {
                                Logger -logSev "i" -Message "Creating folder: $tmpFolder\attatchments\"
                                Try {
                                    New-Item -Path "$tmpFolder\attachments" -type Directory -Force
                                } Catch {
                                    Logger -logSev "e" -Message "Unable to create folder: $tmpFolder\attatchments\"
                                }
                            }                
                            # Get the filename and location
                            $attachedFileName = @(@($msg.Attachments | Select-Object Filename | findstr -v "FileName -") -replace "`n|`r").Trim() -replace '\s',''
                            Logger -logSev "i" -Message "Attached File Name: $attachedFileName"
                            $msg.attachments|ForEach-Object {
                                $attachmentName = $_.filename
                                $attachmentFull = $tmpFolder+"/attachments/"+$attachmentName
                                Logger -logSev "d" -Message "Attachment Name: $attachmentName"
                                Logger -logSev "i" -Message "Checking attachment against interestingFilesRegex"
                                $saveStatus = $null
                                If ($attachmentName -match $interestingFilesRegex) {
                                    Logger -logSev "d" -Message "Saving Attachment to destination: $tmpFolder\attachments\$attachmentName"
                                    Try {
                                        $($_).SaveToFile($attachmentFull)
                                        $saveStatus = $true
                                    } Catch {
                                        Logger -logSev "e" -Message "Unable to save Attachment to destination: $tmpFolder\attachments\$attachmentName"
                                        $saveStatus = $false
                                    }
                                    if ($saveStatus -eq $true) {
                                        Logger -logSev "d" -Message "Checking attachment for hash check"
                                        if ($attachmentName -match $interestingFilesRegex -and $attachmentName -NotLike "*.eml" -and $attachmentName -NotLike "*.msg") {
                                            $fileHashes += @(Get-FileHash -Path "$attachmentFull" -Algorithm SHA256)
                                            Logger -logSev "i" -Message "Adding hash for $attachmentFull to variable fileHashes"
                                        } else {
                                            Logger -logSev "i" -Message "Attachment file extension not interesting"
                                        }
                                    }
                                }
                            }
                        }

                        # Clean Up the SPAM
                        Logger -logSev "d" -Message "Moving e-mail message to SPAM folder"
                        $MoveTarget = $inbox.Folders.item("SPAM")
                        [void]$msg.Move($MoveTarget)
                        $spammer = $msg.From.Split("<").Split(">")[1]
                        Logger -logSev "i" -Message "Spammer set to: $spammer"
                        $spammerDisplayName = $msg.From.Split("<").Split(">")[0]
                        Logger -logSev "i" -Message "Spammer Display Name set to: $spammerDisplayName"
                        }
                } else {
                    Logger -logSev "s" -Message "Non .eml or .msg format"
                    $subject = $msubject
                    if ($msubject.Contains("FW:") -eq $true) { $subject = @($msubject.Split(":")[1]).Trim() }
                    if ($msubject.Contains("Fw:") -eq $true) { $subject = @($msubject.Split(":")[1]).Trim() }
                    if ($msubject.Contains("fw:") -eq $true) { $subject = @($msubject.Split(":")[1]).Trim() }
                    if ($msubject.Contains("FWD:") -eq $true) { $subject = @($msubject.Split(":")[1]).Trim() }
                    if ($msubject.Contains("Fwd:") -eq $true) { $subject = @($msubject.Split(":")[1]).Trim() }
                    if ($msubject.Contains("fwd:") -eq $true) { $subject = @($msubject.Split(":")[1]).Trim() }
                    if ($msubject.Contains("RE:") -eq $true) { $subject = @($msubject.Split(":")[1]).Trim() }
                    if ($msubject.Contains("Re:") -eq $true) { $subject = @($msubject.Split(":")[1]).Trim() }
                    if ($msubject.Contains("re:") -eq $true) { $subject = @($msubject.Split(":")[1]).Trim() }
                    
                    $endUserName = $reportedBy.Split("@")[0]
                
                    if ($orgEmailFormat -eq 1) {
                        Logger -logSev "i" -Message "E-mail format 1 - firstname.lastname@example.com"
                        #E-mail format firstname.lastname@example.com
                        $endUserLastName = $endUserName.Split(".")[1]
                    } elseif ($orgEmailFormat -eq 2) {
                        Logger -logSev "i" -Message "E-mail format 2 - FLastname@example.com"
                        #Format 2 - FLastname@example.com
                        $endUserLastName = $endUserName.substring(1) -replace '[^a-zA-Z-]',''
                    } elseif ($orgEmailFormat -eq 3) {
                        Logger -logSev "i" -Message "E-mail format 3 - FirstnameLastname@example.com"
                        #Format 3 - FirstnameLastname@example.com
                        $endUserLastName = ($endUserName -creplace  '([A-Z\W_]|\d+)(?<![a-z])',' $&').trim().Split(' ')[1]
                    } else {
                        Logger -logSev "e" -Message "Organization's E-mail Format must be set."
                    }


                    Logger -logSev "d" -Message "endUserName: $endUserName endUserLastName: $endUserLastName"
                    $subjectQuery = "Subject:" + "'" + $subject + "'" + " Sent:" + $day
                    $subjectQuery = "'" + $subjectQuery + "'"

                    $searchMailboxResults = Search-Mailbox $endUserName -SearchQuery $subjectQuery -TargetMailbox "$socMailbox" -TargetFolder "PROCESSING" -LogLevel Full

                    $targetFolder = $searchMailboxResults.TargetFolder
                    $outlookAnalysisFolder = @(@($rootFolders.Folders | ?{$_.Name -match "PROCESSING"}).Folders).FolderPath | findstr -i $endUserLastName       
            
                    sleep 30 
                    Write-Output $null > $analysisLog
                    $companyDomain = $socMailbox.Split("@")[1]

                    Get-MessageTrace -RecipientAddress $reportedBy -StartDate "$24Hours" -EndDate "$date" | Select MessageTraceID,Received,*Address,*IP,Subject,Status,Size,MessageID | Export-Csv $tmpLog -NoTypeInformation
                    #$subject = $_.Split(",")[6]; $subject = $subject.Split('"')[1]
                    Logger -logSev "d" -Message "Loading variable tmpLog"
                    Try {
                        Get-Content $tmpLog | ForEach-Object { $_ | Select-String -SimpleMatch $subject >> $analysisLog }
                    } Catch {
                        Logger -logSev "e" -Message "Unable to read content from variable tmpLog"
                    }
                
                    (gc $analysisLog) | Where-Object {$_.trim() -ne "" } | set-content $analysisLog
                    $spammer = Get-Content $analysisLog | ForEach-Object { $_.Split(",")[2]  } | Sort-Object | Get-Unique | findstr "@" | findstr -v "$companyDomain"
                    $spammer = $spammer.Split('"')[1] | Sort-Object | Get-Unique
                }

                # Pull more messages if the sender cannot be found (often happens when internal messages are reported)
                if (-Not $spammer.Contains("@") -eq $true) {
                    Write-Verbose "L691 - Spammer not found, looking for more."
                    sleep 10
                    Try {
                        Write-Output $null > $analysisLog
                    } Catch {
                        Logger -logSev "e" -Message "Unable to write to file $analysisLog"
                    }
                
                    $companyDomain = $socMailbox.Split("@")[1]

                    Get-MessageTrace -RecipientAddress $reportedBy -StartDate $24Hours -EndDate $date | Select MessageTraceID,Received,*Address,*IP,Subject,Status,Size,MessageID | Export-Csv $tmpLog -NoTypeInformation
                    #$subject = $_.Split(",")[6]; $subject = $subject.Split('"')[1]
                    Write-Verbose "L697 - The subject var is equal to  $subject"
                    Get-Content $tmpLog | ForEach-Object { $_ | Select-String -SimpleMatch $subject >> $analysisLog }
                    (Get-Content $analysisLog) | Where-Object {$_.trim() -ne "" } | set-content $analysisLog
                        
                    $spammer = "Unknown"
                }

            
                Logger -logSev "s" -Message "Begin Link Processing"
                [Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null                       
                foreach ($link in $getLinks) {
                    if ($link -like "*originalsrc*" ) {
                        Logger -logSev "d" -Message "Original Source Safelink Before: $link"
                        $link = @(@($link.Split("`"")[1]))
                        if ( $link -notmatch $IMGregex ) {
                            $link >> "$tmpFolder\links.txt"
                            Logger -logSev "d" -Message "Original Source Safelink After: $link"
                        }
                    } elseif ( $link -like "*safelinks.protection.outlook.com*" ) {
                        Logger -logSev "d" -Message "Encoded Safelink Before: $link"
                        [string[]] $urlParts = $link.Split("?")[1]
                        [string[]] $linkParams = $urlParts.Split("&")
                        for ($n=0; $n -lt $linkParams.Length; $n++) {
                            [string[]] $namVal = $linkParams[$n].Split("=")
                            if($namVal[0] -eq "url") {
                                $encodedLink = $namVal[1]
                                break
                            }
                        }
                        $link = [System.Web.HttpUtility]::UrlDecode($encodedLink)
                        if ( $link -notmatch $IMGregex ) {
                            $link >> "$tmpFolder\links.txt"
                            Logger -logSev "d" -Message "Encoded Safelink After: $link"
                        }
                    } elseif ( ($link -like "*urldefense.proofpoint.com*") -Or ($link -like "*urldefense.com*")) {
                        #Stage ProofPoint URLs for decode
                        Logger -logSev "d" -Message "Proofpoint Link Before: $link"
                        if ( $link -match '.*"$') {
                            Logger -logSev "d" -Message "Quote identified on URL Tail"
                            $link = $link.Substring(0,$link.Length-1)
                        }
                        if ( $link -match '.*"') {
                            Logger -logSev "d" -Message "Quote contained within URL String"
                            if ( $link -match 'href=\".*"' ) {
                            Logger -logSev "d" -Message "HREF contained within URL String"
                            $link = $link.Split('"')[1]
                            } 
                            $link = $link.Split('"')[0]
                        } 
                        Logger -logSev "d" -Message "Proofpoint Link After: $link"
                        $ppEncodedLinks += @($link)
                    } else {
                        $link = $URLregex.Matches($link).Value.Split("<").Split(">") | findstr http
                        Logger -logSev "d" -Message "Standard Link Before: $link"
                        if ( $link -match '.*"$') {
                            Logger -logSev "d" -Message "Quote identified on URL Tail"
                            $link = $link.Substring(0,$link.Length-1)
                        }
                        if ( $link -match '.*"') {
                            Logger -logSev "d" -Message "Quote contained within URL String"
                            if ( $link -match 'href=\".*"' ) {
                            Logger -logSev "d" -Message "HREF contained within URL String"
                            $link = $link.Split('"')[1]
                            } 
                            $link = $link.Split('"')[0]
                        }
                        if ( $link -notmatch $IMGregex ) {
                            Try {
                                $link >> "$tmpFolder\links.txt"
                            } Catch {
                                Logger -logSev -Message "Error writing to file path $tmpFolder\links.txt"
                            }
                            Logger -logSev "d" -Message "Standard Link After: $link"
                        }
                    }
                }

                #ProofPoint URL Decode Block
                if ( $ppEncodedLinks.Count -gt 0) {
                    $linkLen = $ppEncodedLinks.Count - 1
                    #Stage multiple URLs for decode, else stage single URL
                    if ($ppEncodedLinks.Count -gt 1) {
                        Logger -logSev "d" -Message "Proofpoint - Building Encrypted URL Array"
                        for ($i=0; $i -le $ppEncodedLinks.Count; $i++) {
                            Logger -logSev "d" -Message "Proofpoint - Link $i $($ppEncodedLinks[$i])"
                            if ($i -lt $linkLen ) {
                                $ppEncodedLinks[$i] = $ppEncodedLinks[$i]+ "`", `""
                            }
                            $ppSubmitLinks += $ppEncodedLinks[$i]
                        } 
                    } else {
                        $ppSubmitLinks = $ppEncodedLinks
                    }
                    #Submit bulk URL decode request to Proofpoint
                    Logger -logSev "i" -Message "Proofpoint - Submitting URL list to decode API"
                    $ppDecodeRequest = Invoke-WebRequest -Method Post ` -Body "{`"urls`": [`"$ppSubmitLinks`" ]}" -Uri https://tap-api-v2.proofpoint.com/v2/url/decode ` -ContentType application/json
                    Logger -logSev "d" -Message "Proofpoint - Saving results to $tmpFolder\ppDecodeRequest.txt"
                    try {
                        $ppDecodeRequest.RawContent | Out-File $tmpFolder\ppDecodeRequest.txt
                    } catch {
                        Logger -logSev "e" -Message "Proofpoint - Unable to Write to File $tmpFolder\ppDecodeRequest.txt"
                    }
                    #Find WebRequest line skip and load JSON results
                    Logger -logSev "d" -Message "Proofpoint - Loading JSON results"
                    $lines = Get-Content $tmpFolder\ppDecodeRequest.txt
                    for ($i = 0; $i -le $lines.Length; $i++) {
                        if ($lines[$i].Length -eq 0) {
                            break
                        }
                    }
                    $skip = $i + 1
                    $ppDecodeResults = Get-Content $tmpFolder\ppDecodeRequest.txt | Select-Object -Skip $skip | ConvertFrom-Json
                    #Write decoded URLs to links.txt
                    Logger -logSev "d" -Message "Proofpoint - Writing Decrypted Links to $tmpFolder\links.txt"
                    for ($i = 0; $i -lt $($ppDecodeResults.Length); $i++) {
                        Logger -logSev "d" -Message "Proofpoint - Link $i $($ppDecodeResults.urls[$i].decodedUrl)"
                        try {
                            $ppDecodeResults.urls[$i].decodedUrl >> "$tmpFolder\links.txt"
                        } catch {
                            Logger -logSev "e" -Message "Proofpoint - Unable to Write to File $tmpFolder\links.txt"
                        }
                    }
                    #Cleanup temporary files
                    try {
                        Remove-Item -Path $tmpFolder\ppDecodeRequest.txt
                    } catch {
                        Logger -logSev "e" -Message "Proofpoint - Unable to Delete file $tmpFolder\ppDecodeRequest.txt"
                    }
                }

                #Remove empty lines and duplicates
                Logger -logSev "d" -Message "Removing empty lines from $tmpFolder\links.txt"
                Try {
                    (Get-Content $tmpFolder\links.txt) | Where-Object {$_.trim() -ne "" } | Sort-Object -Unique | set-content $tmpFolder\links.txt
                } Catch {
                    Logger -logSev "e" -Message "Unable to read/write to file $tmpFolder\links.txt"
                }
    
                #Update list of unique URLs
                Logger -logSev "i" -Message "Loading variable links from $tmpFolder\links.txt"
                $links = Get-Content "$tmpFolder\links.txt"

                #Create list of unique Domains
                Logger -logSev "i" -Message "Loading variable domains from $tmpFolder\links.txt"
                $domains = (Get-Content $tmpFolder\links.txt) | %{ ([System.Uri]$_).Host } | Select-Object -Unique

                Logger -logSev "d" -Message "Writing list of unique domains to $tmpFolder\domains.txt"
                Try {
                    $domains > "$tmpFolder\domains.txt"
                } Catch {
                    Logger -logSev "e" -Message "Unable to write to file $tmpFolder\domains.txt"
                }
                        
                Try {
                    $countLinks = @(@(Get-Content "$tmpFolder\links.txt" | Measure-Object -Line | Select-Object Lines | Select-Object -Unique |findstr -v "Lines -") -replace "`n|`r").Trim()
                    Logger -logSev "i" -Message "Total Unique Links: $countLinks"
                } Catch {
                    Logger -logSev "e" -Message "Unable to read from file $tmpFolder\links.txt"
                }

                Try {
                    $countDomains = @(@(Get-Content "$tmpFolder\domains.txt" | Measure-Object -Line | Select-Object Lines | Select-Object -Unique |findstr -v "Lines -") -replace "`n|`r").Trim()
                    Logger -logSev "i" -Message "Total Unique Domains: $countDomains"
                } Catch {
                    Logger -logSev "e" -Message "Unable to read from file $tmpFolder\domains.txt"
                }

                # Remove whitelist Links from Links List
                Logger -logSev "s" -Message "Begin Whitelist Block"
                if ($links) {
                    Logger -logSev "i" -Message "Removing whitelist links from scannable links"
                    [System.Collections.ArrayList]$scanLinks = @($links)
                    [System.Collections.ArrayList]$scanDomains = @($domains)
                    if ( $links.Count -gt 1 ) {
                        for ($i=0; $i -lt $links.Count; $i++) {
                        Logger -logSev "d" -Message "Inspecting link: $($links[$i])"
                            foreach ($wlink in $urlWhitelist) {
                                if ($($links[$i]) -like $wlink ) {
                                    Logger -logSev "i" -Message "Removing matched link: $($links[$i])"
                                    $scanLinks.Remove( "$($links[$i])" )
                                }
                            }
                        }
                    } elseif ( $links.Count -eq 1 ) {
                        Logger -logSev "d" -Message "Inspecting link: $links"
                        foreach ($wlink in $urlWhitelist) {
                            Logger -logSev "d" -Message "Checking for Whitelist URL: $wlink"
                            if ($links -like $wlink ) {
                                Logger -logSev "i" -Message "Removing matched link: $($links[$i])"
                                $scanLinks.Remove( "$($links[$i])" )
                            }
                        }
                    }

                    # Domains
                    Logger -logSev "i" -Message "Removing whitelist domains from scannable domains"
                    if ( $scanDomains.Count -gt 1 ) {
                        for ($b=0; $b -lt $scanDomains.Count; $b++) {
                            Logger -logSev "d" -Message "Inspecting domain: $($scanDomains[$b])"
                            foreach ($wdomain in $domainWhitelist) {
                                Logger -logSev "d" -Message "Checking for Whitelist domain: $wdomain"
                                if ($($scanDomains[$b]) -like $wdomain ) {
                                    Logger -logSev "i" -Message "Removing matched domain: $($scanDomains[$b])"
                                    $scanDomains.Remove( "$($scanDomains[$b])" )
                                }
                            }
                        }
                    } elseif ( $scanDomains.Count -eq 1 ) {
                        Logger -logSev "d" -Message "Inspecting domain: $scanDomains"
                        foreach ($wdomain in $domainWhitelist) {
                            Logger -logSev "d" -Message "Checking for Whitelist domain: $wdomain"
                            if ($($scanDomains[$b]) -like $wdomain ) {
                                Logger -logSev "i" -Message "Removing matched domain: $scanDomains"
                                $scanDomains.Remove( "$($scanDomains[$b])")
                            }
                        }
                    }
                }
                Logger -logSev "s" -Message "End Whitelist Block"

                Logger -logSev "s" -Message "Begin ShortLink parser"
                if ( $scanLinks ) {
                    Logger -logSev "i" -Message "Begin ShortLink parser"
                    $shortList = @{}
                    [System.Collections.ArrayList]$shortCutList = @($null)
                    [System.Collections.ArrayList]$shortAddList = @($null)
                    for ($i=0; $i -lt $scanLinks.Count; $i++) {
                        Logger -logSev "d" -Message "Inspecting url: $($scanLinks[$i]) For loop step: $i"
                        if ( $($scanLinks[$i]) -match "bit.ly/" -or $($scanLinks[$i]) -match "t.co/" -or $($scanLinks[$i]) -match "x.co/" -or $($scanLinks[$i]) -match "tiny.cc/" -or $($scanLinks[$i]) -match "goo.gl/" -or $($scanLinks[$i]) -match "tinyurl.com/") {
                            Logger -logSev "i" -Message "Shortlink detected: $($scanLinks[$i])"
                            $shortURL = $($scanLinks[$i])
                            Do {
                                Logger -logSev "d" -Message "Invoking headers.location request to: $shortURL"
                                $shortExpanded = (Invoke-WebRequest -Uri $shortURL -MaximumRedirection 0 -ErrorAction Ignore).Headers.Location
                                # Set the Final Destination when Expand URL returns no Location Header    
                                if ($shortExpanded -eq $null) {
                                    $shortDestination = $shortURL
                                } else {
                                    $shortDestination = $shortExpanded
                                }
                                # Reset the URL for the loop
                                $shortURL = $shortExpanded
                            # Define the Loop Condition
                            } Until ($shortURL -eq $null)
                            
                            $shortList.Add( $($scanLinks[$i]) , $shortDestination)
                            
                            # Update expanded link destinations array
                            Try {
                                $shortAddList.Add( "$shortDestination" )
                            } Catch {
                                Logger -logSev "e" -Message "Attempting to add variable slDestination:$shortDestination to array:shortAddList"
                            }
                            # Update array to remove shortened link from scanlinks 
                            Try {
                                $shortCutList.Add( "$($scanLinks[$i])" )
                            } Catch {
                                Logger -logSev "e" -Message "Attempting to add variable scanLinks[i]:$($scanLinks[$i]) to array:shortAddList"
                            }
                        }
                    }
                
                    if ( $shortCutList.count -gt 0 ) {
                        $shortCutList | ForEach-Object {
                            if ($_ -ne $null) {
                                Logger -logSev "d" -Message "Removing shortlink: $_ from array scanLinks"
                                Try {
                                    $scanLinks.Remove( "$_" )
                                } Catch {
                                    Logger -logSev "e" -Message "Attempting to remove shortlink:$_ from array:scanLinks"
                                }
                                Try {
                                    $tmpDomain = ([System.Uri]$_).Host
                                    Logger -logSev "d" -Message "Removing shortlink domain:$tmpDomain from array scanDomains"
                                    $scanDomains.Remove( $tmpDomain )
                                } Catch {
                                    Logger -logSev "e" -Message "Attempting to remove shortlink domain from array:scanDomains"
                                }
                            }
                            $tmpDomain = $null
                        }  
                    }
                    if ( $shortAddList.count -gt 0 ) {
                        $shortAddList | ForEach-Object {
                            if ($_ -ne $null) {
                                Try {
                                    Logger -logSev "d" -Message "Adding expanded link: $_ to array scanLinks"
                                    $scanLinks.Add( "$_" ) 
                                } Catch {
                                    Logger -logSev "e" -Message "Attempting to add expanded link:$_ to array:scanLinks"
                                }
                                Try {
                                    Logger -logSev "i" -Message "Adding expanded link: $_ to $tmpFolder\links.txt"
                                    Add-Content "$tmpFolder\links.txt" $_
                                } Catch {
                                    Logger -logSev "e" -Message "ShortLinks - Unable to Write to File $tmpFolder\links.txt"
                                }
                                Try {
                                    $tmpDomain = ([System.Uri]$_).Host
                                    Logger -logSev "d" -Message "Adding expanded domain:$tmpDomain  to array scanDomains"
                                    $scanDomains.Add( $tmpDomain )
                                } Catch {
                                    Logger -logSev "e" -Message "Attempting to add expanded domain:$tmpDomain to array:scanDomains"
                                }
                                Try {
                                    Logger -logSev "i" -Message "Adding expanded link: $_ to $tmpFolder\domains.txt"
                                    Add-Content "$tmpFolder\domains.txt" $tmpDomain
                                } Catch {
                                    Logger -logSev "e" -Message "ShortLinks - Unable to Write to File $tmpFolder\domains.txt"
                                }
                            }
                            $tmpDomain = $null
                        }  
                    }
                }
                Logger -logSev "s" -Message "End ShortLink parser"
                
                Logger -logSev "s" -Message "End Link Processing"
                Logger -logSev "s" -Message "Begin Hash Processing"
                Logger -logSev "i" -Message "Unique Hash Count: $($scanHashes.count)"

                if ( $fileHashes ) {
                    ForEach ($hash in $fileHashes) {
                        $hashOutput = $hash.hash+","+($hash.Path | Split-Path -Leaf )
                        Write-Output $hashOutput >> $tmpFolder\hashes.txt
                    }
                }
                Logger -logSev "s" -Message "End Hash Processing"


                # Create a case folder
                Logger -logSev "s" -Message "Creating Case"
                # - Another shot
                $caseID = Get-Date -Format M-d-yyyy_h-m-s
                if ( $spammer.Contains("@") -eq $true) {
                    $spammerName = $spammer.Split("@")[0]
                    $spammerDomain = $spammer.Split("@")[1]
                    Logger -logSev "d" -Message "Spammer Name: $spammerName Spammer Domain: $spammerDomain"
                    $caseID = Write-Output $caseID"_Sender_"$spammerName".at."$spammerDomain
                } else {
                    Logger -logSev "d" -Message "Case created as Fwd Message source"
                    $caseID = Write-Output $caseID"_Sent-as-Fwd"
                }
                try {
                    Logger -logSev "i" -Message "Creating Directory: $caseFolder$caseID"
                    mkdir $caseFolder$caseID
                } Catch {
                    Logger -logSev "e" -Message "Unable to create directory: $caseFolder$caseID"
                }
                # Support adding Network Share Location to the Case
                $hostname = hostname
                $networkShare = "\\\\$hostname\\PIE\\cases\\$caseID\\"

                # Check for Attachments
                if ($attachmentCount -gt 0) {
                    Try {
                        mkdir "$caseFolder$caseID\attachments\"
                    } Catch {
                        Logger -logSev "e" -Message "Unable to create directory: $caseFolder$caseID\attachments\"
                    }
                
                    $msubject = $msg.subject 
                    $mBody = $msg.body             
                    $files = $true

                    Logger -logSev "i" -Message "Moving interesting files to case folder"
                    # Make sure those files are moved
                    Copy-Item "$tmpFolder\attachments\*.pdf" "$caseFolder$caseID\attachments\"
                    Copy-Item "$tmpFolder\attachments\*.rar" "$caseFolder$caseID\attachments\"
                    Copy-Item "$tmpFolder\attachments\*.tar" "$caseFolder$caseID\attachments\"
                    Copy-Item "$tmpFolder\attachments\*.gz" "$caseFolder$caseID\attachments\"
                    Copy-Item "$tmpFolder\attachments\*.xyz" "$caseFolder$caseID\attachments\"
                    Copy-Item "$tmpFolder\attachments\*.zip" "$caseFolder$caseID\attachments\"
                    Copy-Item "$tmpFolder\attachments\*.doc*" "$caseFolder$caseID\attachments\"
                    Copy-Item "$tmpFolder\attachments\*.xls*" "$caseFolder$caseID\attachments\"
                    Copy-Item "$tmpFolder\attachments\*.7z*" "$caseFolder$caseID\attachments\"
                    Copy-Item "$tmpFolder\attachments\*.ppt*" "$caseFolder$caseID\attachments\"
                    Copy-Item "$tmpFolder\attachments\*.htm*" "$caseFolder$caseID\attachments\"
                    Copy-Item "$tmpFolder\attachments\*.dmg*" "$caseFolder$caseID\attachments\"
                    Copy-Item "$tmpFolder\attachments\*.exe*" "$caseFolder$caseID\attachments\"
                    Copy-Item "$tmpFolder\attachments\*.js" "$caseFolder$caseID\attachments\"
                    Copy-Item "$tmpFolder\attachments\*.txt" "$caseFolder$caseID\attachments\"
                    Copy-Item "$tmpFolder\*.sha256" "$caseFolder$caseID\"
                }

                # Add evidence to the case folder
                Logger -logSev "i" -Message "Moving attachments folder into case folder"
                Try {
                    Logger -logSev "d" -Message "SRC:$tmpFolder$attachment DST:$caseFolder$caseID"
                    Copy-Item $tmpFolder$attachment $caseFolder$caseID
                } Catch {
                    Logger -logSev "e" -Message "Error copying $tmpFolder$attachment to destination $caseFolder$caseID"
                }
                Logger -logSev "i" -Message "Copying links and headers"
                Try {
                    Get-Content "$tmpFolder\links.txt" | Sort-Object -Unique > "$caseFolder$caseID\links.txt"
                } Catch {
                    Logger -logSev "e" -Message "Error writing $tmpFolder\links.txt to destination $caseFolder$caseID\links.txt"
                }
                Try {
                    Get-Content "$tmpFolder\domains.txt" | Sort-Object -Unique > "$caseFolder$caseID\domains.txt"
                } Catch {
                    Logger -logSev "e" -Message "Error writing $tmpFolder\domains.txt to destination $caseFolder$caseID\domains.txt"
                }
                Try {
                    Get-Content "$tmpFolder\hashes.txt" | Sort-Object -Unique > "$caseFolder$caseID\hashes.txt"
                } Catch {
                    Logger -logSev "e" -Message "Error writing $tmpFolder\hashes.txt to destination $caseFolder$caseID\hashes.txt"
                }
                Try {
                    Get-Content "$tmpFolder\headers.txt" > "$caseFolder$caseID\headers.txt"
                } Catch {
                    Logger -logSev "e" -Message "$tmpFolder\headers.txt to destination $caseFolder$caseID\headers.txt"
                }
                Try {
                    $msg.HTMLBody > "$caseFolder$caseID\email-source.txt"
                } Catch {
                    Logger -logSev "e" -Message "Writing msg.HTMLBody to destination $caseFolder$caseID\email-source.txt"
                }


                # Gather and count evidence
                Logger -logSev "s" -Message "Begin gather and count evidence block"
                if ( $spammer.Contains("@") -eq $true) {
                    Start-Sleep 5
                    Logger -logSev "i" -Message "365 - Collecting interesting messages"
                    Get-MessageTrace -SenderAddress $spammer -StartDate $96Hours -EndDate $date | Select MessageTraceID,Received,*Address,*IP,Subject,Status,Size,MessageID | Export-Csv $analysisLog -NoTypeInformation
                }

                #Update here to remove onmicrosoft.com addresses for recipients
                Logger -logSev "d" -Message "365 - Determining Recipients"
                $recipients = Get-Content $analysisLog | ForEach-Object { $_.split(",")[3] }
                $recipients = $recipients -replace '"', "" | Sort | Get-Unique | findstr -v "RecipientAddress"
                if ( $onMicrosoft -eq $true ) {
                    Logger -logSev "d" -Message "365 - Permitting onMicrosoft addresses"
                    $messageCount = Get-Content $analysisLog | findstr -v "MessageTraceId" | Measure-Object | Select-Object Count | findstr -v "Count -"
                    $deliveredMessageCount = Get-Content $analysisLog | findstr "Delivered Resolved" | Measure-Object | Select-Object Count | findstr -v "Count -"
                    $failedMessageCount = Get-Content $analysisLog | findstr "Failed" | Measure-Object | Select-Object Count | findstr -v "Count -"
                } else {
                    Logger -logSev "d" -Message "365 - Filtering out onMicrosoft addresses onMicrosoft addresses"
                    $messageCount = Get-Content $analysisLog | Where-Object {$_ -notmatch 'onmicrosoft.com'} | findstr -v "MessageTraceId" | Measure-Object | Select-Object Count | findstr -v "Count -"
                    $deliveredMessageCount = Get-Content $analysisLog | Where-Object {$_ -notmatch 'onmicrosoft.com'} | findstr "Delivered Resolved" | Measure-Object | Select-Object Count | findstr -v "Count -"
                    $failedMessageCount = Get-Content $analysisLog | Where-Object {$_ -notmatch 'onmicrosoft.com'} | findstr "Failed" | Measure-Object | Select-Object Count | findstr -v "Count -"
                    $recipients = $recipients | Where-Object {$_ -notmatch 'onmicrosoft.com'}
                }
                $messageCount = $messageCount.Trim()
                $deliveredMessageCount = $deliveredMessageCount.Trim()
                $failedMessageCount = $failedMessageCount.Trim()
                Logger -logSev "d" -Message "365 - Message Count: $messageCount Delivered: $deliveredMessageCount Failed: $failedMessageCount"
                $subjects = Get-Content $analysisLog | ForEach-Object { $_.split(",")[6] } | Sort-Object | Get-Unique | findstr -v "Subject"
                Logger -logSev "d" -Message "365 - Subject Count: $($subjects.Count)"

                # Build the Initial Summary
                Logger -logSev "s" -Message "Creation of Summary"
                $summary = @"
============================================================
Phishing Attack Reported by: $reportedBy
Reported on:                 $date
Spammer:                     $spammer
Spammer Name:                $spammerDisplayName
Subject:                     $subject
Messages Sent:              $messageCount
Messages Delivered:         $deliveredMessageCount
Case Folder:                 $caseID
============================================================
"@
    
                Write-Output $banner > "$caseFolder$caseID\spam-report.txt"
                Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output $summary >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "Unique Subject(s):" >> "$caseFolder$caseID\spam-report.txt"
                $subjects | ForEach-Object { Write-Output "    $_"} >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "Recipient(s): " >> "$caseFolder$caseID\spam-report.txt"
                $recipients | ForEach-Object { Write-Output "    $_"} >> "$caseFolder$caseID\spam-report.txt"
                $recipients | ForEach-Object { Write-Output "$_"} >> "$caseFolder$caseID\recipients.txt"
                Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                if ( $links ) {
                    Write-Output "Link(s):" >> "$caseFolder$caseID\spam-report.txt"
                    Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                    Get-Content "$tmpFolder\links.txt" >> "$caseFolder$caseID\spam-report.txt"
                    Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                    Write-Output "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                    Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                }
                Write-Output "Message Body:" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output $messageBody >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "Message Headers:" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output $headers >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                Try {
                    Get-Content $analysisLog >> "$caseFolder$caseID\message-trace-logs.csv"
                } Catch {
                    Logger -logSev "e" -Message "Error writing analysisLog to $caseFolder$caseID\message-trace-logs.csv"
                }
                
                Try {
                    Remove-Item "$tmpFolder\*" -Force -Recurse
                } Catch {
                    Logger -logSev "e" -Message "Unable to purge contents from $tmpFolder"
                }

    #>
    

# ================================================================================
# LOGRHYTHM CASE MANAGEMENT AND THIRD PARTY INTEGRATIONS
# ================================================================================
#
                Logger -logSev "s" -Message "LogRhythm API - Create Case"
                if ( $spammer.Contains("@") -eq $true) {
                    Logger -logSev "d" -Message "LogRhythm API - Create Case with Sender Info"
                    $caseSummary = "Phishing email from $spammer was reported on $date by $reportedBy. The subject of the email is ($subject). Initial analysis shows that $messageCount user(s) received this email in the past 96 hours."
                    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -createCase "Phishing : $spammerName [at] $spammerDomain" -priority 3 -summary "$caseSummary" -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog
                    Start-Sleep 3
                } else {
                    Logger -logSev "d" -Message "LogRhythm API - Create Case without Sender Info"
                    $caseSummary = "Phishing email was reported on $date by $reportedBy. The subject of the email is ($subject). Initial analysis shows that $messageCount user(s) received this email in the past 96 hours."
                    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -createCase "Phishing Message Reported" -priority 3 -summary "$caseSummary" -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog
                }
                Try {
                    $caseNumber = Get-Content "$pieFolder\plugins\case.txt"
                } Catch {
                    Logger -logSev "e" -Message "Unable to read content $pieFolder\plugins\case.txt"
                }
                Try {
                    Move-Item "$pieFolder\plugins\case.txt" "$caseFolder$caseID\"
                } Catch {
                    Logger -logSev "e" -Message "Unable to move $pieFolder\plugins\case.txt to $caseFolder$caseID\"
                }
                
                $caseURL = "https://$LogRhythmHost/cases/$caseNumber"
                Logger -logSev "i" -Message "Case URL: $caseURL"

            
                # Tag the case as phishing
                Logger -logSev "i" -Message "LogRhythm API - Applying case tag"
                if ( $defaultCaseTag ) {
                    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -addTag "$defaultCaseTag" -casenum $caseNumber -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog
                }

                # Adding and assigning the Case Owner
                Logger -logSev "i" -Message "LogRhythm API - Assigning case owner"
                if ( $caseOwner ) {
                    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -addCaseUser "$caseOwner" -casenum $caseNumber -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog
                    Start-Sleep 1
                    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -changeCaseOwner "$caseOwner" -casenum $caseNumber -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog
                }

                # Adding and assigning other users
                Logger -logSev "i" -Message "LogRhythm API - Assigning case collaborators"
                if ( $caseCollaborators ) {
                    foreach ( $i in $caseCollaborators ) {
                        & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -addCaseUser "$i" -casenum $caseNumber -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog
                        Start-Sleep 1
                    }
                }
        
                # Append Case Info to 
                Logger -logSev "i" -Message "LogRhythm - Adding case info to spam-report"
                Write-Output "LogRhythm Case Information:" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "Case #:      $caseNumber" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "Case URL:    $caseURL" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "" >> "$caseFolder$caseID\spam-report.txt"

                # Copy raw logs to case
                Logger -logSev "i" -Message "LogRhythm API - Copying raw logs to case"
                
                Try {
                    $caseNote = Get-Content $analysisLog
                } Catch {
                    Logger -logSev "e" -Message "Unable to read content from analysisLog"
                }
                $caseNote = $caseNote -replace '"', ""
                & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "Raw Phishing Logs: $caseNote" -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog
                
                # Recipients
                Logger -logSev "i" -Message "LogRhythm API - Adding recipient info to case"
                Try {
                    $messageRecipients = (Get-Content "$caseFolder$caseID\recipients.txt") -join ", "
                } Catch {
                    Logger -logSev "e" -Message "Unable to read content from $caseFolder$caseID\recipients.txt"
                }
                & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "Email Recipients: $messageRecipients" -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog

                # Copy E-mail Message text body to case
                Logger -logSev "i" -Message "LogRhythm API - Copying e-mail body text to case"
                if ( $messageBody ) {
                    $caseMessageBody = $($messageBody.Replace("`r`n","\r\n"))
                    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "Submitted Email Message Body:\r\n$caseMessageBody" -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog
                }
                
                # Write cleaned message subject note to case notes
                if ($trueDat -eq $true) {
                    Logger -logSev "i" -Message "LogRhythm API - Copying cleaned message subject note to case"
                    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "Reported Message Subject was cleaned of special characters; see case notes folder for original.\r\n" -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog
                }

                # If multiple subjects, add subjects to case
                if ( $($subjects.Length) -gt 1 ) {
                    Logger -logSev "i" -Message "LogRhythm API - Copying summary of observed subjects to case"
                    $caseSubjects = $subjects | Out-String
                    $caseSubjects = $($caseSubjects.Replace("`r`n","\r\n"))
                    $caseSubjects = $($caseSubjects.Replace("`"",""))
                    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "Subjects from sender:\r\n$caseSubjects" -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog
                }

                # Observed Links
                if ( $links) {
                    Logger -logSev "i" -Message "LogRhythm API - Copying links to case"
                    $messageLinks= (Get-Content "$caseFolder$caseID\links.txt") -join "\r\n"
                    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "Links:\r\n$messageLinks" -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog
                }

                # Observed ShortLinks
                if ( $shortList.count -gt 0 ) {
                    Logger -logSev "i" -Message "LogRhythm API - Copying expanded ShortLinks to case"
                    $shortStatus = "====INFO - ShortLinks Report====\r\n"
                    foreach ($key in $shortList.keys ) {
                        Logger -logSev "d" -Message "Origin URL: $key Destination URL:$($shortlist[$key])"
                        $shortStatus += "$key expanded to $($shortlist[$key])\r\n"
                    }
                    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$shortStatus" -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog
                    Write-Output $shortStatus.Replace("\r\n","`r`n") >> "$caseFolder$caseID\spam-report.txt"
                }

                # Observed Files
                if ( $fileHashes ) {
                    Logger -logSev "i" -Message "LogRhythm API - Copying file hashes to case"
                    Try {
                        $caseHashes= (Get-Content "$caseFolder$caseID\hashes.txt") -join "\r\n"
                    } Catch {
                        Logger -logSev "e" -Message "Unable to read file $caseFolder$caseID\hashes.txt"
                    }
                    
                    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "Hashes:\r\n$caseHashes" -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog
                }


#>

# ================================================================================
# Third Party Integrations
# ================================================================================
#
                Logger -logSev "s" -Message "Begin Third Party Plugins"
                # WRIKE
                if ( $wrike -eq $true ) {
                    Logger -logSev "s" -Message "Begin Wrike"
                    $secOpsSummary = "Phishing email from $spammer was reported on $date by $reportedBy. The subject of the email is ($subject). Initial analysis shows that $messageCount user(s) received this email in the past 48 hours. For more information, review the LogRhythm Case and Evidence folder."           

                    # Security Operations Contact(s)
                    & $pieFolder\plugins\wrike.ps1 -newTask "Case $caseNumber - Phishing email from $spammer" -wrikeUserName $wrikeUser -wrikeFolderName $wrikeFolder -wrikeDescription $secOpsSummary -accessToken $wrikeAPI
            
                    # Labs
                    $labsSummary = "Phishing email from $spammer was reported on $date by $reportedBy. The subject of the email is ($subject). Initial analysis shows that $messageCount user(s) received this email in the past 48 hours. For more information, review the LogRhythm Case ($LogRhythmHost/cases/$caseNumber) and Evidence folder"
                    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "Tasks Created in Wrike..." -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog
                    Logger -logSev "s" -Message "End Wrike"
                }

                # SCREENSHOT MACHINE
                if ( $screenshotMachine -eq $true ) {
                    if ( $scanLinks.length -gt 0 ) {
                        Logger -logSev "s" -Message "Begin Screenshot Machine"
                        $scanLinks | ForEach-Object {
                            $splitLink = ([System.Uri]"$_").Host

                            Invoke-RestMethod "http://api.screenshotmachine.com/?key=$screenshotKey&dimension=1024x768&format=png&url=$_" -OutFile "$caseFolder$caseID\screenshot-$splitLink.png"
                    
                            $screenshotStatus = "Screenshot of hxxp://$splitLink website has been captured and saved with the case folder: screenshot-$splitLink.png"
                            & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$screenshotStatus" -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog
                        }
                        Logger -logSev "s" -Message "End Screenshot Machine"
                    }
                }

                # GET LINK INFO
                if ( $getLinkInfo -eq $true ) {
                    if ( $scanLinks.length -gt 0 ) {
                        Logger -logSev "s" -Message "Begin LinkInfo"
                        $scanLinks | ForEach-Object { 
                            $splitLink = $_.Split(":") | findstr -v http

                            $linkInfo = iwr http://www.getlinkinfo.com/info?link=$_

                            $linkInfo.RawContent | Out-File $tmpFolder\linkInfo.txt
                            $isItSafe = Get-Content $tmpFolder\linkInfo.txt | Select-String -Pattern '((?![0]).) unsafe\)*'

                            if ( $isItSafe ) {
                                $getLinkInfoStatus = "UNSAFE LINK DETECTED (hxxp:$splitLink)! More Information: http://www.getlinkinfo.com/info?link=$_"
                                $threatScore += 1
                            } else {
                                $getLinkInfoStatus = "Link (hxxp:$splitLink) is considered low risk. More Information: http://www.getlinkinfo.com/info?link=$_"
                            }

                            & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$getLinkInfoStatus" -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog

                            Write-Output "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "Get Link Info Status:" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output $getLinkInfoStatus >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "" >> "$caseFolder$caseID\spam-report.txt"

                            Remove-Item -Path $tmpFolder\linkInfo.txt
                        }
                        Logger -logSev "s" -Message "End LinkInfo"
                    }
                }


                # PHISHTANK
                if ( $phishTank -eq $true ) {
                    if ( $scanLinks.length -gt 0 ) {
                        Logger -logSev "s" -Message "Begin Phishtank"
                        $scanLinks | ForEach-Object { 
                        
                            $splitLink = $_.Split(":") | findstr -v http

                            if ( $phishTankAPI ) {
                                $postParams = @{url="$_";format="xml";app_key="$phishTankAPI"}
                            } else {
                                $postParams = @{url="$_";format="xml"}
                            }
                            $phishTankResponse = Invoke-WebRequest -Uri http://checkurl.phishtank.com/checkurl/ -Method POST -Body $postParams
                            Try {
                                $phishTankResponse.Content | Out-File $tmpFolder\phishtankAnalysis.txt
                            } Catch {
                                Logger -logSev 'e' -Message "Unable to write file $tmpFolder\phishtankAnalysis.txt "
                            }
                            Try {
                                [xml]$phishTankResults = Get-Content $tmpFolder\phishtankAnalysis.txt 
                            } Catch {
                                Logger -logSev 'e' -Message "Unable to read file $tmpFolder\phishtankAnalysis.txt "
                            }
                            
                    
                            $phishTankStatus = $phishTankResults.response.results.url0.in_database
                    
                            $phishTankDetails = $phishTankResults.response.results.url0.phish_detail_page
                            $phishTankVerified = $phishTankResults.response.results.url0.verified
                            $phishTankVerifiedOn = $phishTankResults.response.results.url0.verified_at

                            if ( $phishTankStatus -eq "false" ) {
                                $phishTankStatus = "Link (hxxp:$splitLink) is not present in the PhishTank Database."
                            } elseif ( $phishTankStatus -eq "true" ) {
                                $phishTankStatus = "MALICIOUS LINK (hxxp:$splitLink) was found in the PhishTank Database! More Information: $phishTankDetails"
                                $threatScore += 1
                            }

                            & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$phishTankStatus" -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog
                
                            Write-Output "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "PhishTank Status:" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output $phishTankStatus >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                        
                        }
                        Try {
                            Remove-Item $tmpFolder\phishtankAnalysis.txt 
                        } Catch {
                            Logger -logSev 'e' -Message "Unable to remove file $tmpFolder\phishtankAnalysis.txt "
                        }
                        Logger -logSev "s" -Message "End PhishTank"
                    }
                }

                # SUCURI LINK ANALYSIS
                if ( $sucuri -eq $true ) {
                    if ( $scanDomains.length -gt 0 ) {
                        Logger -logSev "s" -Message "Begin Sucuri"
                        $scanDomains | ForEach-Object {
                            Logger -logSev "i" -Message "Submitting domain: $_"
                            
                            $sucuriLink = "https://sitecheck.sucuri.net/results/$_"
                            $sucuriAnalysis = iwr "https://sitecheck.sucuri.net/api/v3/?scan=$_&json"
                            $sucuriAnalysis.RawContent | Out-File $tmpFolder\sucuriAnalysis.txt
                            $skipLines = Get-Content $tmpFolder\sucuriAnalysis.txt | Measure-Object -Line
                            $sucuriResults = Get-Content $tmpFolder\sucuriAnalysis.txt | select -Skip $skipLines.Lines | ConvertFrom-Json
                            $sucuriStatus = "==== INFO - SUCURI ====\r\nDomain scanned: $_\r\n"
                            #Check for blacklisted status
                            if ( $sucuriResults.blacklists -ne $null ) {
                                $itBlacklisted = $true
                                $blVendor = $sucuriResults.blacklists.vendor
                                $blURL = $sucuriResults.blacklists.info_url
                            }
                            #Check for malware status
                            if ( $sucuriResults.warnings.security.malware -ne $null ) {
                                $itMalicious = $true
                                $malwareInfo = $sucuriResults.warnings.security.malware
                            }
                            #Check for spammer status
                            if ( $sucuriResults.warnings.security.spam -ne $null ) {
                                $itSuspicious = $true
                                $susInfo = $sucuriResults.warnings.security.spam
                            }

                            #Build report info
                            if ( $itBlacklisted -eq $true ) {
                                $sucuriStatus += "\r\nALERT: Blacklisted Link Reported by:\r\n"
                                if ($blVendor -is [array] ) {
                                    for ($n=0; $n -lt $blVendor.Length; $n++) {
                                        $sucuriStatus += $blVendor[$n]+" - "+$blURL[$n]+"\r\n"
                                    }
                                } else {
                                    $sucuriStatus += $blVendor+" - "+$blURL+"\r\n"
                                }

                                $sucuriStatus += "\r\n"
                                $threatScore += 1
                            } 
                            
                            if ( $itMalicious -eq $true ) {
                            
                                $sucuriStatus += "\r\nALERT: Malware Reported!\r\n"
                                if ($malwareInfo -is [array] ) {
                                    for ($n=0; $n -lt $malwareInfo.Length; $n++) {
                                        $sucuriStatus += "Type: "+$malwareInfo[$n].type+"\r\n"+$malwareInfo[$n].msg+"\r\n\r\n"
                                    }
                                } else {
                                    $sucuriStatus += "Type: "+$malwareInfo.type+"\r\n"+$malwareInfo.msg+"\r\n\r\n"
                                }
                                $threatScore += 1
                            }

                            if ( $itSuspicious -eq $true ) {
                            
                                $sucuriStatus += "\r\nALERT: Spammer Reported!\r\n"
                                for ($n=0; $n -lt $susInfo.Length; $n++) {
                                    $sucuriStatus += "Type: "+$susInfo[$n].type+"\r\nDetails:"+$susInfo[$n].info_url+"\r\n\r\n"
                                }
                                $sucuriStatus += "\r\n"
                                $threatScore += 1
                            }

                            if ( !$itBlacklisted -eq $true -and !$itMalware -eq $true -AND !$itSuspicious -eq $true ) {
                                $sucuriStatus += "Sucuri has determined this link is clean.\r\n\r\n"
                            }
                            
                            #Submit report info
                            $sucuriStatus += "Last scanned by Sucuri on $($sucuriResults.scan.last_scan).\r\nFull details available here: $sucuriLink."
                            & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$sucuriStatus" -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog
                            $sucuriStatus += "\r\n**** END - SUCURI ****\r\n\r\n"
                            Write-Output $sucuriStatus.Replace("\r\n","`r`n") >> "$caseFolder$caseID\spam-report.txt"
                            
                            #Cleanup
                            Remove-Item -Path $tmpFolder\sucuriAnalysis.txt
                            $itSuspicious = $false
                            $itMalicious = $false
                            $itBlacklisted = $false
                            
                        }
                        Logger -logSev "s" -Message "End Sucuri"
                    }
                }

                # VIRUS TOTAL - Plugin Block
                if ( $virusTotal -eq $true ) {
                    if ( $virusTotalAPI ) {
                        Logger -logSev "s" -Message "Begin VirusTotal"
                        if ( $scanDomains.length -gt 0 ) {
                            $scanDomains | ForEach-Object {
                                #Set VirusTotal API clock
                                if ($vtRunTime -eq $null) {
                                    Logger -logSev "d" -Message "Setting Initial VT Runtime"
                                    $vtRunTime = (Get-Date)
                                    $vtQueryCount = 0
                                } else {
                                    $vtTestTime = (Get-Date)
                                    $vtTimeDiff = New-TimeSpan -Start $vtRunTime -End $vtTestTime
                                    #If the time differene is greater than 4, reset the API use clock to current time.
                                    if ($vtTimeDiff.Minutes -gt 0 ) {
                                        Logger -logSev "d" -Message "VT Runtime Greater than 1, resetting runtime position"
                                        $vtRunTime = (Get-Date)
                                        $vtQueryCount = 0
                                    }
                                }
                                $vtStatus = "====INFO - Virus Total Domain====\r\n"

                                Logger -logSev "d" -Message "Submitting Domain $_"
                                $postParams = @{apikey="$virusTotalAPI";domain="$_";}

                                #Public API use vs Commercial logic block
                                if ( $virusTotalPublic -eq $true ) {
                                    $vtQueryCount = $vtQueryCount + 1
                                    if ($vtQueryCount -lt 5) {
                                        Logger -logSev "d" -Message "Submitting Domain#: $vtQueryCount Domain: $_"
                                        $vtResponse = iwr http://www.virustotal.com/vtapi/v2/domain/report -Method GET -Body $postParams
                                        $vtResponse = $vtResponse.Content | ConvertFrom-Json
                                        $vtResponseCode = $vtResponse.response_code
                                    } else {
                                        $vtTestTime = (Get-Date)
                                        $vtTimeDiff = New-TimeSpan -Start $vtRunTime -End $vtTestTime
                                        if ($vtTimeDiff.Minutes -gt 0 ) {
                                            #If the time difference between time values is greater than 1, new submissions can be made.  Reset the API's run clock to now.
                                            $vtRunTime = (Get-Date)
                                            $vtQueryCount = 1
                                            Logger -logSev "d" -Message "Submitting Domain#: $vtQueryCount Domain: $_"
                                            $vtResponse = iwr http://www.virustotal.com/vtapi/v2/domain/report -Method GET -Body $postParams
                                            $vtResponse = $vtResponse.Content | ConvertFrom-Json
                                            $vtResponseCode = $vtResponse.response_code
                                        } else {
                                            #Set the vtResponseCode to -1.  -1 is a self defined value for exceeding the API limit.
                                            $vtResponseCode = -1
                                        }
                                    }
                                } elseif ( $virusTotalPublic -eq $false ) {
                                    #If running under a commercial license, API call you like >:)
                                    $vtResponse = iwr http://www.virustotal.com/vtapi/v2/domain/report -Method GET -Body $postParams
                                    $vtResponse = $vtResponse.Content | ConvertFrom-Json
                                    $vtResponseCode = $vtResponse.response_code
                                }
                            

                                if ($vtResponseCode -eq 1) {
                                    Logger -logSev "i" -Message "Virus Total Response Code: 1, Results returned on domain."
                                    $vtLink = "https://www.virustotal.com/#/domain/$_"
                    
                                    [System.Collections.ArrayList]$vtDomainUrls = $vtResponse.detected_urls
                                    $vtStatus += "Scanned Domain: $_\r\n"
                                    if ($vtResponse."Alexa domain info" -ne $null) {
                                        $vtStatus += "Alexa Info: "+$vtResponse."Alexa domain info"+"\r\n"
                                    }
                                    if ($vtResponse."Webutation domain info" -ne $null) {
                                        $vtStatus += "Webutation Score: "+$vtResponse."Webutation domain info"."Safety score"+"  Verdict: "+$vtResponse."Webutation domain info".Verdict+"\r\n"
                                    }
                                    if ($vtResponse."TrendMicro category" -ne $null) {
                                        $vtStatus += "TrendMicro Category: "+$vtResponse."TrendMicro category"+"\r\n"
                                    }
                                    if ($vtResponse."Forcepoint ThreatSeeker category" -ne $null) {
                                        $vtStatus += "Forcepoint Category: "+$vtResponse."Forcepoint ThreatSeeker category"+"\r\n"
                                    }


                                    #Step through domain for URL array.
                                    for ($n=0; $n -lt $vtDomainUrls.Count; $n++) {                     
                                        for ($i=0; $i -lt $scanLinks.Count  ; $i++) {
                                            if ($($vtDomainUrls[$n].url) -eq $scanLinks[$i]) {
                                                Logger -logSev "d" -Message "Matched URL"
                                                $vtStatus += "\r\nMatched URL: "+$vtDomainUrls[$n].url+"\r\n"
                                                if ( $vtDomainUrls[$n].positives -lt 2 ) {
                                
                                                    $vtStatus += "The url has been marked benign.\r\n"
                                                    Logger -logSev "i" -Message "Benign URL $($vtDomainUrls[$n].url)"
                                    
                                                } elseif ( $vtDomainUrls[$n].positives -gt 1 ) {
                                                    $vtStatus += "ALERT: This sample has been flagged by "+$vtDomainUrls[$n].positives+"/"+$vtDomainUrls[$n].total+" Anti Virus engines.\r\nScan Date: "+$vtDomainUrls[$n].scan_date+"\r\n"
                                                    #If the url is found on the domain, and hosts malicious content increase the threatScore by the number of positives reported.
                                                    $threatScore += [int]$vtDomainUrls[$n].positives
                                                    Logger -logSev "a" -Message "Malicious URL $($vtDomainUrls[$n].url)"
                                                }
                                                $vtDomainUrls.RemoveAt($n)
                                            }                 
                                        }
                                        if ( $vtDomainUrls[$n].positives -gt 2 ) {
                                            $tempThreat = [int]$vtDomainUrls[$n].positives
                                            $vtStatus += "\r\nALERT: A domain sample has been flagged by "+$vtDomainUrls[$n].positives+"/"+$vtDomainUrls[$n].total+" Anti Virus engines.\r\nURL: "+$vtDomainUrls[$n].url+"\r\nScan Date: "+$vtDomainUrls[$n].scan_date+"\r\n\r\n"
                                            Logger -logSev "a" -Message "Malicious URL hosted by Domain: $($vtDomainUrls[$n].url)"
                                        }

                                    }
                                    if ( $tempThreat -gt 0 ) {
                                        #If the domain hosts malicious content at other URLs outside of the specific URLs contained within the e-mail, increase threat by 1
                                        $threatScore += 1
                                    } elseif ($vtDomainUrls.Count -gt 0) {
                                        $vtStatus += "\r\nDomain URL Summary: Virus Total holds "+$vtDomainUrls.Count+" entries each with benign sample results."+"\r\n"
                                    }

                                    $vtStatus += "\r\nVirusTotal report: $vtLink"
                                } elseif ($vtResponseCode -eq 0) {
                                    Logger -logSev "i" -Message "Response Code: 0, Domain not found in VT Database"
                                    $vtStatus += "\r\nDomain`: $_ not found in VirusTotal database.\r\n"
                                } elseif ($vtResponseCode -eq -1) {
                                    Logger -logSev "i" -Message "Response Code: -1, Rate limit exceeded for public API use."
                                    $vtStatus += "\r\nDomain`: $_ not submitted.  Rate limit exceeded for public API use.\r\n"
                                } else {
                                    Logger -logSev "e" -Message "Response Code: -1, VirusTotal File Plugin Error."
                                    $vtStatus += "\r\nA PIE Plugin error has occured for this plugin.  Please contact your administrator.\r\n"
                                }
                                & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$vtStatus" -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog
                                $vtStatus += "\r\n====END - VirusTotal Domain====\r\n"
                                Write-Output $vtStatus.Replace("\r\n","`r`n") >> "$caseFolder$caseID\spam-report.txt"
                                                            
                                #cleanup vars
                                $vtResponseCode = ""
                                $vtStatus = ""
                                $vtPositives = ""
                                $vtResponse = ""
                                $vtFName = ""
                                $vtHash = ""
                                $tempThreat = ""
                            }
                            Logger -logSev "s" -Message "End Virus Total Domain Plugin"
                        } 
                        if ( $fileHashes.Length -gt 0 ) {
                            $fileHashes | ForEach-Object {
                                #Set VirusTotal API clock
                                if ($vtRunTime -eq $null) {
                                    Logger -logSev "d" -Message "Setting Initial VT Runtime"
                                    $vtRunTime = (Get-Date)
                                    $vtQueryCount = 0
                                } else {
                                    $vtTestTime = (Get-Date)
                                    $vtTimeDiff = New-TimeSpan -Start $vtRunTime -End $vtTestTime
                                    #If the time differene is greater than 4, reset the API use clock to current time.
                                    if ($vtTimeDiff.Minutes -gt 0 ) {
                                        Logger -logSev "d" -Message "VT Runtime Greater than 1, resetting runtime position"
                                        $vtRunTime = (Get-Date)
                                        $vtQueryCount = 0
                                    }
                                }
                                $vtFName = Split-Path -Path $($_.path) -Leaf
                                $vtHash = [string]$($_.hash)

                                Logger -logSev "i" -Message "Submitting file: $vtFName Hash: $vtHash"
                                $postParams = @{apikey="$virusTotalAPI";resource="$vtHash";}
                                
                                #Public API use vs Commercial logic block
                                if ( $virusTotalPublic -eq $true ) {
                                    $vtQueryCount = $vtQueryCount + 1
                                    if ($vtQueryCount -lt 5) {
                                        $vtResponse = iwr http://www.virustotal.com/vtapi/v2/file/report -Method POST -Body $postParams
                                    } else {
                                        $vtTestTime = (Get-Date)
                                        $vtTimeDiff = New-TimeSpan -Start $vtRunTime -End $vtTestTime
                                        if ($vtTimeDiff.Minutes -gt 0 ) {
                                            #If the time difference between time values is greater than 4, new submissions can be made.  Reset the API's run clock to now.
                                            $vtRunTime = (Get-Date)
                                            $vtResponse = iwr http://www.virustotal.com/vtapi/v2/file/report -Method POST -Body $postParams
                                        } else {
                                            #Set the vtResponseCode to -1.  -1 is a self defined value for exceeding the API limit.
                                            $vtResponseCode = -1
                                        }
                                    }
                                } elseif ( $virusTotalPublic -eq $false ) {
                                    #If running under a commercial license, API call you like >:)
                                    $vtResponse = iwr http://www.virustotal.com/vtapi/v2/file/report -Method POST -Body $postParams
                                } 

                                $vtStatus = "====INFO - Virus Total File====\r\n"

                                $vtResponse = $vtResponse.Content | ConvertFrom-Json
                                $vtResponseCode = $vtResponse.response_code
                                if ($vtResponseCode -eq 1) {
                                    $vtLink = $vtResponse.permalink

                                    $vtPositives = [int]$vtResponse.positives
                                    $VTTotal = $vtResponse.total
                                    $VTScanDate = $vtResponse.scan_date

                                    if ( $vtPositives -lt 1 ) {
                                        $vtStatus += "Status: Benign\r\nFile`: $vtFName\r\nSHA256: $vtHash\r\n\r\nThe sample has been marked benign by $VTTotal Anti Virus engines."
                                        Logger -logSev "i" -Message "File Benign"
                                    
                                    } elseif ( $vtPositives -gt 0 ) {
                                        $vtStatus += "Status: Malicious\r\nFile`: $vtFName\r\nSHA256: $vtHash\r\n\r\nALERT: This sample has been flagged by $vtPositives/$VTTotal Anti Virus engines."
                                        $threatScore += $vtPositives
                                        Logger -logSev "a" -Message "File Malicious"
                                    }

                                    $vtStatus += "\r\n\r\nLast scanned by Virus Total on $VTScanDate.\r\nFull details available here: $vtLink."
                                    Write-Host "Entry found in VT database"
                                } elseif ($vtResponseCode -eq 0) {
                                    Logger -logSev "i" -Message "File not found in VT Database"
                                    $vtStatus += "\r\nFile`: $vtFName not found in VirusTotal database.\r\n"
                                } else {
                                    Logger -logSev "e" -Message "VirusTotal File Plugin Error"
                                    $vtStatus += "\r\nA PIE Plugin error has occured for this plugin.  Please contact your administrator.\r\n"
                                }
                                
                                & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$vtStatus" -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog
                                $vtStatus += "\r\n====END - VirusTotal FILE====\r\n"
                                Write-Output $vtStatus.Replace("\r\n","`r`n") >> "$caseFolder$caseID\spam-report.txt"
                                #cleanup vars
                                $vtStatus = ""
                                $vtPositives = ""
                                $vtResponse = ""
                                $vtFName = ""
                                $vtHash = ""
                            }
                            Logger -logSev "s" -Message "End VirusTotal File Plugin"
                        }
                    } else {
                        Logger -logSev "e" -Message "VirusTotal Plugin Enabled but no API key provided"
                        & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "VirusTotal API key required to check / submit samples." -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog
                    }
                    Logger -logSev "s" -Message "End VirusTotal Plugin"
                }

                # URLSCAN
                if ( $urlscan -eq $true ) {
                    if ( $scanLinks.length -gt 0 ) {
                        Logger -logSev "s" -Message "Begin urlScan"
                        Logger -logSev "i" -Message "Max Links: $urlscanMax"
            
                        Write-Output "urlscan.io" >> "$caseFolder$caseID\spam-report.txt"
                        Write-Output "============================================================" >> "$caseFolder$caseID\spam-report.txt"

                        $scanLinks | Select-Object -First $urlscanMax | ForEach-Object {
                            Logger -logSev "i" -Message "Scanning: $_"
                            & $pieFolder\plugins\URLScan.ps1 -key $urlscanAPI -link $_ -caseID $caseID -caseFolder "$caseFolder" -pieFolder "$pieFolder" -logRhythmHost $logRhythmHost -caseAPItoken $caseAPItoken -networkShare $networkShare

                        }

                        if ((Test-Path -Path "$caseFolder$caseID\urlScan\hashes.txt" -PathType Leaf)) {
                            # Wildfire Integration: submits file hashes for URL direct download files
                            if ( $wildfire -eq $true ) {
                                Logger -logSev "i" -Message "urlScan to Wildfire file hash submission"
                                $urlscanHashes = Get-Content "$caseFolder$caseID\urlScan\hashes.txt"
                                Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                                if ( $urlscanHashes.Length -gt 0 ) {
                                
                                    Write-Output "urlScan - File Hashes Observed & Palo Alto Wildfire Enabled -" >> "$caseFolder$caseID\spam-report.txt"
                                    Write-Output "" >> "$caseFolder$caseID\spam-report.txt"

                                    $urlscanHashes | ForEach-Object {
                                        $wfFName = $_.Split(",")[1]
                                        $wfHash = $_.Split(",")[0]
                                        Logger -logSev "i" -Message "Submitting file: $wfFname Hash: $wfHash"
                                        Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                                        Write-Output "Wildfire Analysis: File: $wfFName Hash: $wfHash" >> "$caseFolder$caseID\spam-report.txt"
                                        & $pieFolder\plugins\Wildfire.ps1 -key $wildfireAPI -fileHash $wfHash -fileName $wfFName -caseID $caseID -caseFolder "$caseFolder" -pieFolder "$pieFolder" -logRhythmHost $logRhythmHost -caseAPItoken $caseAPItoken
                                        Write-Output "" >> "$caseFolder$caseID\spam-report.txt"

                                    }
                                    Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                                    $wfFname = ""
                                    $wfHash = ""
                                }
                            }
                            if ( $virusTotal -eq $true ) {
                                Logger -logSev "i" -Message "urlScan to VirusTotal file submission"
                                $urlscanHashes = Get-Content "$caseFolder$caseID\urlScan\hashes.txt"
                                Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                                if ( $urlscanHashes.Length -gt 0 ) {
                                    #Set VirusTotal API clock
                                    if ($vtRunTime -eq $null) {
                                        Logger -logSev "d" -Message "Setting Initial VT Runtime"
                                        $vtRunTime = (Get-Date)
                                        $vtQueryCount = 0
                                    } else {
                                        $vtTestTime = (Get-Date)
                                        $vtTimeDiff = New-TimeSpan -Start $vtRunTime -End $vtTestTime
                                        #If the time differene is greater than 1, reset the API use clock to current time.
                                        if ($vtTimeDiff.Minutes -gt 0 ) {
                                            Logger -logSev "d" -Message "VT Runtime Greater than 1, resetting runtime position"
                                            $vtRunTime = (Get-Date)
                                            $vtQueryCount = 0
                                        }
                                    }
                                    Write-Output "urlScan - File Hashes Observed & Virus Total Enabled -" >> "$caseFolder$caseID\spam-report.txt"
                                    Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                                    $urlscanHashes | ForEach-Object {
                                        $vtFName = $_.Split(",")[1]
                                        $vtHash = $_.Split(",")[0]

                                        Logger -logSev "i" -Message "Submitting file: $vtFName Hash: $vtHash"
                                        $postParams = @{apikey="$virusTotalAPI";resource="$vtHash";}
                                        if ( $virusTotalPublic -eq $true ) {
                                            $vtQueryCount = $vtQueryCount + 1
                                            if ($vtQueryCount -lt 5) {
                                                $vtResponse = iwr http://www.virustotal.com/vtapi/v2/file/report -Method POST -Body $postParams
                                            } else {
                                                $vtTestTime = (Get-Date)
                                                $vtTimeDiff = New-TimeSpan -Start $vtRunTime -End $vtTestTime
                                                if ($vtTimeDiff.Minutes -gt 0 ) {
                                                    #If the time difference between time values is greater than 1, new submissions can be made.  Reset the API's run clock to now.
                                                    $vtRunTime = (Get-Date)
                                                    $vtResponse = iwr http://www.virustotal.com/vtapi/v2/file/report -Method POST -Body $postParams
                                                } else {
                                                    #Set the vtResponseCode to -1.  -1 is a self defined value for exceeding the API limit.
                                                    $vtResponseCode = -1
                                                }
                                            }
                                        } elseif ( $virusTotalPublic -eq $false ) {
                                            #If running under a commercial license, API call you like >:)
                                            $vtResponse = iwr http://www.virustotal.com/vtapi/v2/file/report -Method POST -Body $postParams
                                        } 
                                        $vtStatus = "====INFO - urlScan to Virus Total File====\r\nurlScan observed file download link.  File hash for downloadable file submitted to Virus Total.\r\n"

                                        $vtResponse = $vtResponse.Content | ConvertFrom-Json
                                        $vtResponseCode = $vtResponse.response_code
                                        if ($vtResponseCode -eq 1) {
                                            $vtLink = $vtResponse.permalink

                                            $vtPositives = [int]$vtResponse.positives
                                            $VTTotal = $vtResponse.total
                                            $VTScanDate = $vtResponse.scan_date

                                            if ( $vtPositives -lt 1 ) {
                                                $vtStatus += "Status: Benign\r\nFile`: $vtFName\r\nSHA256: $vtHash\r\n\r\nThe sample has been marked benign by $VTTotal Anti Virus engines."
                                                Logger -logSev "i" -Message "File Benign"
                                    
                                            } elseif ( $vtPositives -gt 0 ) {
                                                $vtStatus += "Status: Malicious\r\nFile`: $vtFName\r\nSHA256: $vtHash\r\n\r\nALERT: This sample has been flagged by $vtPositives/$VTTotal Anti Virus engines."
                                                $threatScore += $vtPositives
                                                Logger -logSev "a" -Message "File Malicious"
                                            }

                                            $vtStatus += "\r\n\r\nLast scanned by Virus Total on $VTScanDate.\r\nFull details available here: $vtLink."
                                            Write-Host "Entry found in VT database"
                                        } elseif ($vtResponseCode -eq 0) {
                                            Logger -logSev "i" -Message "File not found in VT Database"
                                            $vtStatus += "\r\nFile`: $vtFName not found in VirusTotal database.\r\n"
                                        } elseif ($vtResponseCode -eq -1) {
                                            Logger -logSev "i" -Message "File not submitted to Virus Total.\r\nRate limit exceeded for public API use."
                                            $vtStatus += "\r\nFile`: $vtFName not submitted.  Rate limit exceeded for public API use.\r\n"
                                        } else {
                                            Logger -logSev "e" -Message "VirusTotal File Plugin Error"
                                            $vtStatus += "\r\nA PIE Plugin error has occured for this plugin.  Please contact your administrator.\r\n"
                                        }
                                
                                        & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$vtStatus" -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog
                                        $vtStatus += "\r\n====END - VirusTotal File====\r\n"
                                        Write-Output $vtStatus.Replace("\r\n","`r`n") >> "$caseFolder$caseID\spam-report.txt"
                                        #cleanup vars
                                        $vtStatus = ""
                                        $vtPositives = ""
                                        $vtResponse = ""
                                        $vtFName = ""
                                        $vtHash = ""
                                    }

                                }
                            }
                        }

                        Write-Output "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                        Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                        Try {
                            Remove-Item -Path $tmpFolder\urlscanAnalysis.txt
                        } Catch {
                            Logger -logSev "e" -Message "Unable to remove file $tmpFolder\urlscanAnalysis.txt"
                        }
                        Try {
                            Remove-Item -Path $tmpFolder\urlscanRequest.txt
                        } Catch {
                            Logger -logSev "e" -Message "Unable to remove file $tmpFolder\urlscanRequest.txt"
                        }
                        Logger -logSev "s" -Message "End urlScan"
                    }
                }

                # DOMAIN TOOLS
                if ( $domainTools -eq $true ) {
                    Logger -logSev "s" -Message "Begin Domain Tools"

                    $domainIgnoreList = "bit.ly","ow.ly","x.co","goo.gl","logrhythm.com","google.com"
                    $threshold = (Get-Date).AddMonths(-3)
                    $threshold = $threshold.ToString("yyy-MM-dd")

                    if ( $scanLinks.length -gt 0 ) {
                        $scanLinks | ForEach-Object {
                            If([string]$_ -match ($domainIgnoreList -join "|")) {
                                Logger -logSev "i" -Message "Nothing to analyze"
                                Write-Output "Nothing to analyze"
                            } else {

                                $domain = @(([System.Uri]"$_").Host).Split(".")[-2]
                                $dn = @(([System.Uri]"$_").Host).Split(".")[-1]
                                $domain = "$domain.$dn"

                                try {
                                    $domainDetails = Invoke-RestMethod "http://api.domaintools.com/v1/$domain/?api_username=$DTapiUsername&api_key=$DTapiKey"
                                } catch {
                                    Logger -logSev "e" -Message "Unable to retrieve data from api.domaintools.com"
                                    Write-Error "fail..."
                                }

                                $createdDate = $domainDetails.response.registration.created
                                $updatedDate = $domainDetails.response.registration.updated

                                $events = $domainDetails.response.history.registrar.events

                                if ( $createdDate ) {

                                    if($threshold -le $createdDate){
                                        $domainToolsUpdate = "DomainTools: Domain ($domain) is less than 3-months old - likely malicious! Registered on $createdDate. Threat Score Elevated."
                                        #Rescore Candidate
                                        $threatScore += 1
                                        Logger -logSev "i" -Message "Domain is less than 3-months old - likely malicious! Registered on $registrationTime. Threat Score Elevated."
                                    }else{
                                        $domainToolsUpdate = "DomainTools: Domain ($domain) has been registered since $createdDate - low risk"
                                        Logger -logSev "i" -Message "Domain has been registered since $registrationTime - low risk"
                                    }

                                } else {

                                    $registrationTime = $domainDetails.response.history.registrar.earliest_event

                                    if($threshold -le $registrationTime){
                                        $domainToolsUpdate = "DomainTools: Domain is less than 3-months old - likely malicious! Registered on $registrationTime. Threat Score Elevated."
                                        #Rescore Candidate
                                        $threatScore += 1
                                        Logger -logSev "i" -Message "Domain is less than 3-months old - likely malicious! Registered on $registrationTime. Threat Score Elevated."
                                    }else{
                                        $domainToolsUpdate = "DomainTools: Domain has been registered since $registrationTime - low risk"
                                        Logger -logSev "i" -Message "Domain has been registered since $registrationTime - low risk"
                                    }
                                }
                            }
                
                            & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$domainToolsUpdate" -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog

                            Write-Output "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "Domain Tools Status:" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output $domainToolsUpdate >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                        }
                        Logger -logSev "s" -Message "End Domain Tools"
                    }
                }

                # OPEN DNS
                if ( $openDNS -eq $true ) {
                    if ( $scanLinks.length -gt 0 ) {
                        Logger -logSev "s" -Message "Start OpenDNS"
                        $scanLinks | ForEach-Object {

                            $splitLink = ([System.Uri]"$_").Host

                            $OpenDNSurl = "https://investigate.api.umbrella.com/domains/categorization/$splitLink`?showLabels"
                            $result = Invoke-RestMethod -Headers @{'Authorization' = "Bearer $openDNSkey"} -Uri $OpenDNSurl | ConvertTo-Json -Depth 4
                            $newresult = $result | ConvertFrom-Json
                            $score = $newresult.$splitLink.status

                            if ($score -eq -1){
                                $OpenDNSStatus = "MALICIOUS DOMAIN - OpenDNS analysis determined $splitLink to be unsafe!"
                                $threatScore += 1
                            }elseif ($score -eq 0) {
                                $OpenDNSStatus = "OpenDNS - Uncategorized Domain: $splitLink"
                            } elseif ($score -eq 1) {
                                $OpenDNSStatus = "OpenDNS - Benign Domain: $splitLink"
                            }

                            & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$OpenDNSStatus" -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog

                            Write-Output "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "OpenDNS Status:" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output $OpenDNSStatus >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                        }
                        Logger -logSev "s" -Message "End Domain Tools"
                    }
                }

                # URL VOID
                if ( $urlVoid -eq $true ) {
                    if ( $scanLinks.length -gt 0 ) {
                        Logger -logSev "s" -Message "Begin URLVoid"
                        $scanLinks | ForEach-Object {
                
                            $splitLink = ([System.Uri]"$_").Host
                    
                            $urlVoidResponse = Invoke-RestMethod http://api.urlvoid.com/$urlVoidIdentifier/$urlVoidKey/host/$splitLink/
                            $urlVoidCheckResponse = $urlVoidResponse.response.details.ip.addr
                            $urlVoidError = $urlVoidResponse.response.error

                            if ( $urlVoidError ) {
                                $urlVoidStatus = "URL VOID Error: API Key is Invalid"
                            } else {

                                if ( $urlVoidCheckResponse ) {

                                    $checkDetection = $urlVoidResponse.response.detections

                                    if ( $checkDetection ) {

                                        $urlVoidEngines = $urlVoidResponse.response.detections.engines.engine
                                        $urlVoidCount = $urlVoidResponse.response.detections.count

                                        $urlVoidStatus = "URL VOID: MALWARE DETECTED on (hxxp://$splitLink)! Detection Count: $urlVoidCount. Engines: $urlVoidEngines"
                                        $threatScore += [int]$urlVoidCount

                                    } else {

                                        $urlVoidStatus = "URL VOID: Safe link detected (hxxp://$splitLink)"
                                    }

                                    $urlVoidIPdetails = $urlVoidResponse.response.details.ip

                                } else {

                                    $urlVoidResponse = Invoke-RestMethod http://api.urlvoid.com/$urlVoidIdentifier/$urlVoidKey/host/$splitLink/scan/

                                    if ( $urlVoidResponse.response.action_result -eq "OK" ) {

                                        $checkDetection = $urlVoidResponse.response.detections

                                        if ( $checkDetection ) {

                                            $urlVoidEngines = $urlVoidResponse.response.detections.engines.engine
                                            $urlVoidCount = $urlVoidResponse.response.detections.count

                                            $urlVoidStatus = "URL VOID: New Scan - MALWARE DETECTED on (hxxp://$splitLink)! Detection Count: $urlVoidCount. Engines: $urlVoidEngines"
                                            $threatScore += [int]$urlVoidCount

                                        } else {

                                            $urlVoidStatus = "URL VOID: New scan - Safe link detected (hxxp://$splitLink)"
                                        }

                                        $urlVoidIPdetails = $urlVoidResponse.response.details.ip

                                    }

                                }    
                            }
                            & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$urlVoidStatus" -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog

                            Write-Output "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "URL Void Domain Information (hxxp://$splitLink):" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output $urlVoidIPdetails >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                        }
                        Logger -logSev "s" -Message "End URLVoid"
                    }
                }


                # Wildfire
                if ( $wildfire -eq $true ) {
                    if ( $fileHashes.Length -gt 0 ) {
                        Logger -logSev "s" -Message "Begin WIldfire"
                        Write-Output "Palo Alto Wildfire" >> "$caseFolder$caseID\spam-report.txt"
                        Write-Output "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                        Write-Output "" >> "$caseFolder$caseID\spam-report.txt"

                        $fileHashes | ForEach-Object {
                            $wfFName = Split-Path -Path $($_.path) -Leaf
                            Logger -logSev "s" -Message "Submitting file: $wfFName Hash: $($_.hash)"
                            Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "Wildfire Analysis: File: $caseFolder$caseID\attachments\$wfFName Hash: $($_.hash)" >> "$caseFolder$caseID\spam-report.txt"
                            & $pieFolder\plugins\Wildfire.ps1 -key $wildfireAPI -fileHash $($_.hash) -fileName $wfFName -caseID $caseID -caseFolder "$caseFolder" -pieFolder "$pieFolder" -logRhythmHost $logRhythmHost -caseAPItoken $caseAPItoken
                            Write-Output "" >> "$caseFolder$caseID\spam-report.txt"

                        }

                        Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                        Write-Output "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                        Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                        Logger -logSev "s" -Message "End Wildfire"
                    }
                }

                # Comodo Valkarie
                if ( $comodoValkarie -eq $true ) {
                    Logger -logSev "s" -Message "Begin Comodo Valkarie"
                    if ( $fileHashes.Length -gt 0 ) {
                        Logger -logSev "i" -Message "Inspecting File Hashes"

                        $fileHashes | ForEach-Object {
                            $comodoFileName = Split-Path -Path $($_.path) -Leaf
                            pluginValkarie -cmdCheckFileHash $($_.hash) -cmdApiKey $comodoApiKey
                            Logger -logSev "d" -Message "Submitting file: $comodoFileName Hash: $($_.hash)"
                        }
                    }
                    if ( $scanLinks.length -gt 0 ) {
                        Logger -logSev "i" -Message "Inspecting URLs"
                        $scanLinks | ForEach-Object {
                            #pluginValkarie -cmdCheckUri $_ -cmdApiKey $comodoApiKey
                        }
                    }
                    if ( $scanDomains.length -gt 0 ) {
                        Logger -logSev "i" -Message "Inspecting Domains"
                        $scanDomains | ForEach-Object {
                            pluginValkarie -cmdCheckDomain $_ -cmdApiKey $comodoApiKey
                        }

                    }
                    Logger -logSev "s" -Message "End Comodo Valkarie"
                }


                # SHORT LINK ANALYSIS
                if ( $shortLink -eq $true ) {
                    if ( $scanLinks.length -gt 0 ) {
                        Logger -logSev "s" -Message "Begin ShortLink Analysis"
                        $scanLinks | ForEach-Object {

                            if ( $_ -match "https://bit.ly" ) {
                
                                # bit.ly
                                $shortLinkContent = iwr "$_+"
                                $expandedLink = ($shortLinkContent.Content | findstr -i long_url).Split('"') | findstr -i "http https" | unique

                                $splitLink = $expandedLink.Split(":") | findstr -v http

                                $shortLinkStatus = "Shortened Link Detected! Metrics: $_+. Redirect: hxxp:$splitLink"

                                & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$shortLinkStatus" -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog
                            }

                            if ( $_ -match "https://goo.gl" ) {
                
                                # goo.gl
                                $shortLinkContent = iwr "$_+"
                                $expandedLink = ($shortLinkContent.Content | findstr -i long_url).Split('"') | findstr -i "http https" | unique
                                $splitLink = $expandedLink.Split(":") | findstr -v http

                                $shortLinkStatus = "Shortened Link Detected! Metrics: $_+."

                                & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$shortLinkStatus" -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog
                            }

                            if ( $_ -match "http://x.co" ) {

                                # x.co
                                $splitLink = $_.Split(":") | findstr -v http
                                $shortLinkStatus = "Machine Learning analysis has detected a possibly malicious link hxxp:$_."
                                $threatScore += 1

                                & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$shortLinkStatus" -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog
                            }
                        }
                        Logger -logSev "s" -Message "End ShortLink Analysis"
                    }
                }

                # Link RegEx Check
                if ( $linkRegexCheck ) {
                    if ( $scanLinks.length -gt 0 ) {
                        Logger -logSev "s" -Message "Begin link RegEx Check"
                        $linkRegexList = '/wp-admin/',
                                            '/wp-includes/',
                                            '/wp-content/(?!\S{0,60}Campaign\S{0,2}\=)(?!\S{0,60}\.pdf[<\"\t\r\n])(?!\S{0,60}\.jpg[<"\t\r\n])',
                                            'blocked\ your?\ online',
                                            'suspicious\ activit',
                                            'updated?\ your\ account\ record',
                                            'Securely\ \S{3,4}\ one(\ )?drive',
                                            'Securely\ \S{3,4}\ drop(\ )?box',
                                            'Securely\ \S{3,4}\ Google\ Drive',
                                            'sign\ in\S{0,7}(with\ )?\ your\ email\ address',
                                            'Verify\ your\ ID\s',
                                            'dear\ \w{3,8}(\ banking)?\ user',
                                            'chase\S{0,10}\.html"',
                                            '\b(?<=https?://)(www\.)?icloud(?!\.com)',
                                            '(?<![\x00\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5A])appie\W',
                                            '/GoogleDrive/',
                                            '/googledocs?/',
                                            '/Dropfile/',
                                            'limit\ (and\ suspend\ )?your\ account',
                                            '\b(?<=https?://)(?!www\.paypal\.com/)\S{0,40}pa?y\S{0,2}al(?!\S*\.com/)',
                                            'sitey\.me',
                                            'myfreesites\.net',
                                            '/uploadfile/',
                                            '/\S{0,3}outloo\S{0,2}k\S{1,3}\W',
                                            '\b(?<=https?://webmail\.)\S{0,40}webmail\w{0,3}(?!/[0-9])(?!\S{0,40}\.com/)',
                                            'owaportal',
                                            'outlook\W365',
                                            '/office\S{0,3}365/',
                                            '-icloud\Wcom',
                                            'pyapal',
                                            '/docu\S{0,3}sign\S{1,4}/',
                                            '/helpdesk/',
                                            'pay\Sa\S{0,2}login',
                                            '/natwest/',
                                            '/dro?pbo?x/',
                                            '%20paypal',
                                            '\.invoice\.php',
                                            'security-?err',
                                            '/newdropbox/',
                                            '/www/amazon',
                                            'simplefileupload',
                                            'security-?warning',
                                            '-(un)?b?locked',
                                            '//helpdesk(?!\.)',
                                            '\.my-free\.website',
                                            'mail-?update',
                                            '\.yolasite\.com',
                                            '//webmail(?!\.)',
                                            '\.freetemplate\.site',
                                            '\.sitey\.me',
                                            '\.ezweb123\.com',
                                            '\.tripod\.com',
                                            '\.myfreesites\.net',
                                            'mailowa',
                                            '-icloud',
                                            'icloud-',
                                            'contabo\.net',
                                            '\.xyz/',
                                            'ownership\ validation\ (has\ )?expired',
                                            'icloudcom',
                                            '\w\.jar(?=\b)',
                                            '/https?/www/',
                                            '\.000webhost(app)?\.com',
                                            'is\.gd/',
                                            '\.weebly\.com',
                                            '\.wix\.com',
                                            'tiny\.cc/',
                                            '\.joburg',
                                            '\.top/'
                        $scanLinks | ForEach-Object { 
                            $splitLink = $_.Split(":") | findstr -v http

                            If([string]$_ -match ($linkRegexList -join "|")) {
                                $regExCheckStatus = "UNSAFE LINK DETECTED (hxxp:$splitLink)! Positive RegEx match - possibly malicious."
                                $threatScore += 1
                            } else {
                                Write-Host "No RegEx matches for (hxxp:$splitLink) - potentially benign."
                            }

                            & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$regExCheckStatus" -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog

                            Write-Output "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "RegEx Check Status:" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output $regExCheckStatus >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                        }
                        Logger -logSev "s" -Message "End Link Regex Check"
                    }
                }

                # THREAT GRID
                if ( $threatGrid -eq $true ) {
                    Logger -logSev "s" -Message "Begin ThreatGrid"
                    if ( $files ) {
                        # Update Case
                        $caseNote = "The collected files are now being analyzed for risk using Cisco AMP Threat Grid..."
                        & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$caseNote" -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog
                
                        $allAttachments = ls "$tmpFolder\attachments\"
                        $allAttachments.Name | ForEach-Object { 
                            & $pieFolder\plugins\ThreatGRID-PIE.ps1 -file "$tmpFolder\attachments\$_" -key $threatGridAPI -caseNumber $caseNumber -caseFolder "$caseFolder$caseID" -caseAPItoken $caseAPItoken -LogRhythmHost $LogRhythmHost
                        }
            
                    } elseif ( $countLinks -gt 0 ) {
                        # Update Case
                        $caseNote = "The collected links are now being analyzed for risk using Cisco AMP Threat Grid..."
                        & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$caseNote" -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog

                        $scanLinks | ForEach-Object { 
                            & $pieFolder\plugins\ThreatGRID-PIE.ps1 -url "$_" -key $threatGridAPI -caseNumber $caseNumber -caseFolder "$caseFolder$caseID" -caseAPItoken $caseAPItoken -LogRhythmHost $LogRhythmHost
                        }
                    } else {
                        # Nothing to do
                        $caseNote = "No content for Cisco AMP Threat Grid to analyze..."
                        & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$caseNote" -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog
                    }

                    #$threatGridScore = "90"
                    #$threatGridRisk = "HIGH RISK"
                    #& $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "ThreatGRID Analysis Score: $threatGridScore ($threatGridRisk)" -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog
                    Logger -logSev "s" -Message "End ThreatGrid"
                }

                # SHODAN
                if ( $shodan -eq $true ) {
                    Logger -logSev "s" -Message "Begin Shodan"
                    if ( $threatScore -ge $shodanInitThreat ) {
                        Logger -logSev "d" -Message "ThreatScore:$threatScore is greater than or equal to shodanInitThreat:$shodanInitThreat"
                        if ( $scanDomains.length -gt 0 ) {
                
                            Write-Output "Shodan.io" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "============================================================" >> "$caseFolder$caseID\spam-report.txt"
    
                            $scanDomains | ForEach-Object {
                                Write-Output "Shodan Analysis: $_" >> "$caseFolder$caseID\spam-report.txt"
                                Logger -logSev "i" -Message "Submitting domain: $_"
                                & $pieFolder\plugins\Shodan.ps1 -key $shodanAPI -link $_ -caseID $caseID -caseFolder "$caseFolder" -pieFolder "$pieFolder" -logRhythmHost $logRhythmHost -caseAPItoken $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog
    
                            }
    
                            Write-Output "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                            Logger -logSev "s" -Message "End Shodan"
                        }
                    } else {
                        Logger -logSev "d" -Message "ThreatScore:$threatScore is less than shodanInitThreat:$shodanInitThreat"
                    }
                    Logger -logSev "s" -Message "End Shodan"
                }

                Logger -logSev "s" -Message "End Third Party Plugins"
                Logger -logSev "s" -Message "Begin Auto-Remediation Block"
                # ADD SPAMMER TO LIST
                if ($spamTracker -eq $true) {
                    if ( $spammerList ) {
                        Logger -logSev "s" -Message "Begin update Spammer List"
                        if ( $threatScore -gt 1 ) {
                            if ( $spammer.Contains("@") -eq $true) {
                    
                                & $pieFolder\plugins\List-API.ps1 -lrhost $LogRhythmHost -appendToList "$spammer" -listName "$spammerList" -token $caseAPItoken
                                sleep 1
                                & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "Spammer ($spammer) added to Threat List ($spammerList)" -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog
                
                            } else {
                                $spammerStatus = "====PIE - Add Spammer to List====\r\nUnable to extract the spammer's e-mail. \r\nManual analysis of message is required."
                                & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase $spammerStatus -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog
                
                            }
                        }
                        Logger -logSev "s" -Message "End update Spammer List"
                    }
                }

                # SafeLink Trace
                if ( $safelinkTrace -eq $true ) {
                    if ( $scanLinks.length -gt 0 ) {
                        Logger -logSev "s" -Message "Begin Safelink Trace"
                        $sltClear = $null
                        $sltStatus = "== 365 Safelink Trace ==\r\n"
                        $scanLinks | ForEach-Object {

                            Logger -logSev "d" -Message "365 Safelinks - Inspecting URL: $_"
                            $sltResults = Get-UrlTrace -UrlOrDomain "$_"
                            if ( $sltResults ) {
                                $sltStatus += "Trace report for URL: \r\n$_\r\n"
                                $sltResults | ForEach-Object {
                                    $sltStatus += "Clicked On: $($_.Clicked) UTC | By recipient $($_.RecipientAddress)\r\n"
                                    Logger -logSev "s" -Message "365 Safelinks - URL: $($_.Url) Date: $($_.Clicked) UTC By recipient $($_.RecipientAddress)"
                                }
                            } else {
                                $sltClear += "$_\r\n"
                                Logger -logSev "i" -Message "365 Safelinks - No access record for URL: $_"
                            }
                            $sltResults = $null
                        }
                        if ($sltClear) {
                            $sltStatus += "\r\nNo access recorded for the following URLs:\r\n$sltClear\r\n" 
                        }
                        & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$sltStatus" -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog

                        Write-Output "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                        Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                        Write-Output "Safelink Trace Status:" >> "$caseFolder$caseID\spam-report.txt"
                        Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                        Write-Output $($slStatus.Replace("\r\n","`r`n")) >> "$caseFolder$caseID\spam-report.txt"
                        Write-Output "" >> "$caseFolder$caseID\spam-report.txt"

                        Logger -logSev "s" -Message "End Safelink Trace"
                    }
                }

                if ($spearInspector) {
                    pluginSpearIns
                }
                

            #>
    
            
                # AUTO QUARANTINE ACTIONS
                if ( $autoQuarantine -eq $true ) {
                    Logger -logSev "s" -Message "Begin AUTO QUARANTINE Block"
                    if ( $threatScore -gt $threatThreshold ) {
                        Logger -logSev "i" -Message "Threat score $threatScore is greater than threshold of $threatThreshold"
                        $autoQuarantineNote = "Initiating auto-quarantine based on Threat Score of $threatScore. Copying messages to the Phishing inbox and hard-deleting from all recipient inboxes."
                        Logger -logSev "i" -Message "LogRhythm API - Case Updated"
                        & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$autoQuarantineNote" -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog
                        sleep 5
                        Logger -logSev "i" -Message "Invoking 365Ninja Quarantine"
                        if ( $EncodedXMLCredentials ) {
                            & $pieFolder\plugins\O365Ninja.ps1 -scrapeMail -sender "$spammer" -nuke -caseNumber $caseNumber -encodedXMLCredentials "$EncodedXMLCredentials" -socMailbox $socMailBox -LogRhythmHost $LogRhythmHost -caseAPItoken $caseAPItoken
                        } else {
                            & $pieFolder\plugins\O365Ninja.ps1 -scrapeMail -sender "$spammer" -nuke -caseNumber $caseNumber -username $username -password $password -socMailbox $socMailBox -LogRhythmHost $LogRhythmHost -caseAPItoken $caseAPItoken
                        }
                    }

                    if ( $threatScore -lt $threatThreshold ) {
                        Logger -logSev "i" -Message "Threat score $threatScore is less than threshold of $threatThreshold"
                        $autoQuarantineNote = "Email not quarantined due to a required Threat Threshold of $threatThreshold."
                        Logger -logSev "i" -Message "LogRhythm API - Case Updated"
                        & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$autoQuarantineNote" -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog
                    }
                    Logger -logSev "i" -Message "Spam-report Auto Quarantine Results Added"
                    Write-Output "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                    Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                    Write-Output "Message Auto Quarantine Status:" >> "$caseFolder$caseID\spam-report.txt"
                    Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                    Write-Output $autoQuarantineNote >> "$caseFolder$caseID\spam-report.txt"
                    Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                    Logger -logSev "s" -Message "End AUTO QUARANTINE Block"
                }

                if ( $autoBan -eq $true ) {
                    Logger -logSev "s" -Message "Begin AUTO BAN Block"
                    if ( $threatScore -gt $threatThreshold ) {
                        Logger -logSev "i" -Message "Threat score $threatScore is greater than threshold of $threatThreshold"
                        Logger -logSev "i" -Message "Automatically banning $spammer based on Threat Score of $threatScore."
                        Logger -logSev "i" -Message "LogRhythm API - Case Updated"
                        & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$autoBanNote" -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog
                        sleep 5
                        Logger -logSev "i" -Message "Invoking 365Ninja Block Sender"
                        if ( $EncodedXMLCredentials ) {
                            & $pieFolder\plugins\O365Ninja.ps1 -blockSender -sender "$spammer" -caseNumber $caseNumber -encodedXMLCredentials "$EncodedXMLCredentials" -socMailbox $socMailBox -LogRhythmHost $LogRhythmHost -caseAPItoken $caseAPItoken
                        } else {
                            & $pieFolder\plugins\O365Ninja.ps1 -blockSender -sender "$spammer" -caseNumber $caseNumber -username $username -password $password -socMailbox $socMailBox -LogRhythmHost $LogRhythmHost -caseAPItoken $caseAPItoken
                        }
                    }

                    if ( $threatScore -lt $threatThreshold ) {
                        Logger -logSev "i" -Message "Threat score $threatScore is less than threshold of $threatThreshold"
                        $autoBanNote = "Sender ($spammer) not quarantined due to a required Threat Threshold of $threatThreshold."
                        Logger -logSev "i" -Message "LogRhythm API - Case Updated"
                        & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$autoBanNote" -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog
                    }

                    Logger -logSev "i" -Message "Spam-report Auto Ban Results Added"
                    Write-Output "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                    Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                    Write-Output "Message Auto Ban Status:" >> "$caseFolder$caseID\spam-report.txt"
                    Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                    Write-Output $autobanNote >> "$caseFolder$caseID\spam-report.txt"
                    Write-Output "" >> "$caseFolder$caseID\spam-report.txt"

                    Logger -logSev "s" -Message "End AUTO BAN Block"
                }
                Logger -logSev "s" -Message "End Auto-Remediation Block"
                Logger -logSev "s" -Message "Begin JSON Block"

                $specialPattern = "[^\u0000-\u007F]"
                if ($messageBody -Match "$specialPattern") { 
                    $messageBody = $messageBody -Replace "$specialPattern","?"
                    Logger -logSev "i" -Message "Invalid characters identified, cleaning non-ASCII out of messageBody"  
                }


                # Build Json Summary
                $jsonPie | Add-Member -ErrorAction Continue -Name 'summary' -MemberType NoteProperty -Value (New-Object -TypeName psobject -Property @{
                    reportedBy=$reportedBy;
                    date=$date;
                    spammer=$spammer;
                    spammerDisplayName=$spammerDisplayName;
                    subject=$subjects;
                    counts= (New-Object -TypeName psobject -Property @{
                        sent=$messageCount;
                        delivered=$deliveredMessageCount;
                    });
                })

                # Build Json Metadata
                #links=[string[]](Get-Content "$tmpFolder\links.txt");
                $jsonPie | Add-Member -ErrorAction Continue -Name 'meta' -MemberType NoteProperty -Value (New-Object -TypeName psobject -Property @{
                    subjects=[string[]]($subjects);
                    recipients=[string[]]($recipients);
                    body=$messageBody;
                    headers=$headers;
                })

                # Build Json Case Info
                $jsonPie | Add-Member -ErrorAction Continue -Name 'lr-case' -MemberType NoteProperty -Value (New-Object -TypeName psobject -Property @{
                    number=$caseNumber;
                    url=$caseURL;
                })

                # Finish the json Object
                $jsonPie | Add-Member -ErrorAction Continue -Name 'threatScore' -MemberType NoteProperty -Value $threatScore
                $jsonPie | Add-Member -ErrorAction Continue -Name 'hostname' -MemberType NoteProperty -Value $hostname
                $jsonPie | Add-Member -ErrorAction Continue -Name 'networkShare' -MemberType NoteProperty -Value $networkShare

                # Finally save out Case
                $jsonPie | ConvertTo-Json >> "$caseFolder$caseID\spam-report.json"
                Logger -logSev "s" -Message "End JSON Block"
# ================================================================================
# Case Closeout
# ================================================================================
                #Write out PIE Log
                Pie-Log

                #Submit Hashes to LR
                Submit-Hash

                # Final Threat Score
                Logger -logSev "i" -Message "LogRhythm API - Add Threat Score"
                & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "Email Threat Score: $threatScore" -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog
                
                Logger -logSev "s" -Message "Begin LogRhythm Playbook Block"
                if ($casePlaybook -and ($threatScore -ge $casePlaybookThreat)) {
                    Logger -logSev "i" -Message "LogRhythm API - Adding Playbook:$casePlaybook to Case:$caseNumber"
                    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -addPlaybook "$casePlaybook" -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog
                } elseif ($casePlaybook -and ($threatScore -lt $casePlaybookThreat)) {
                    Logger -logSev "i" -Message "LogRhythm API - Playbook Omision - Threatscore is less than casePlaybookThreat"
                } else {
                    Logger -logSev "i" -Message "LogRhythm API - Playbook Omision - Playbook not defined"
                }

                Logger -logSev "s" -Message "End LogRhythm Playbook Block"

                Logger -logSev "i" -Message "Spam-report Case closeout"
                Write-Output "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "Email Threat Score: $threatScore" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "" >> "$caseFolder$caseID\spam-report.txt"

                Logger -logSev "i" -Message "LogRhythm API - Add network share details"
                & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "Case Details: $networkShare" -token $caseAPItoken -pluginLogLevel $pluginLogLevel -runLog $runLog
            }   
            #Cleanup Variables prior to next evaluation
            Logger -logSev "s" -Message "Resetting analysis varaiables"
            $jsonPie = $null
            $reportedBy = $null
            $reportedSubject = $null
            $endUserName = $null
            $endUserLastName = $null
            $subjectQuery = $null
            $searchMailboxResults = $null
            $targetFolder = $null
            $outlookAnalysisFolder = $null
            $companyDomain = $null
            $spammer = $null
            $spammerDisplayName = $null
            $message = $null
            $msg = $null
            $msubject = $null
            $subject = $null
            $subjects = $null
            $recipients = $null
            $messageCount = $null
            $deliveredMessageCount = $null
            $failedMessageCount = $null
            $mBody = $null
            $messageBody = $null
            $headers = $null
            $getLinks = $null
            $links = $null
            $domains = $null
            $countLinks = $null
            $attachmentCount = $null
            $attachmentFull = $null
            $attachment = $null
            $attachments = $null
            $directoryInfo = $null
            $caseID = $null
            $summary = $null
            $scanLinks = $null
            $scanDomains = $null
            $trueDat = $null
            $fileHashes = $null
            $ppEncodedLinks = $null
            $ppDecodeResults = $null
            $shortAddList = $null
            $shortCutList = $null
            $shortDestination = $null
            $shortExpanded = $null
            $shortURL = $null
            $shortList = $null
        }
        
        #Close Outlook
        Logger -logSev "s" -Message "Closing Outlook"
        $processOutlook = Get-Process OUTLOOK
        if ($processOutlook) {
            Logger -logSev "i" -Message "Stopping Outlook PID:$($processOutlook.Id)"
            Try {
                Stop-Process $processOutlook.Id -Force
            } Catch {
                Logger -logSev "e" -Message "Unable Stop-Process for Outlook PID:$($processOutlook.Id)"
            }
        } else {
            Logger -logSev "i" -Message "Unable to identify Outlook PID.  Is Outlook running?"
        }

    }
}

# ================================================================================
# LOG ROTATION
# ================================================================================

# Log rotation script stolen from:
#      https://gallery.technet.microsoft.com/scriptcenter/PowerShell-Script-to-Roll-a96ec7d4

function Reset-Log 
{ 
    #function checks to see if file in question is larger than the paramater specified if it is it will roll a log and delete the oldes log if there are more than x logs. 
    param([string]$fileName, [int64]$filesize = 1mb , [int] $logcount = 5) 
     
    $logRollStatus = $true 
    if(test-path $filename) 
    { 
        $file = Get-ChildItem $filename 
        if((($file).length) -ige $filesize) #this starts the log roll 
        { 
            $fileDir = $file.Directory 
            $fn = $file.name #this gets the name of the file we started with 
            $files = Get-ChildItem $filedir | ?{$_.name -like "$fn*"} | Sort-Object lastwritetime 
            $filefullname = $file.fullname #this gets the fullname of the file we started with 
            #$logcount +=1 #add one to the count as the base file is one more than the count 
            for ($i = ($files.count); $i -gt 0; $i--) 
            {  
                #[int]$fileNumber = ($f).name.Trim($file.name) #gets the current number of the file we are on 
                $files = Get-ChildItem $filedir | ?{$_.name -like "$fn*"} | Sort-Object lastwritetime 
                $operatingFile = $files | ?{($_.name).trim($fn) -eq $i} 
                if ($operatingfile) 
                 {$operatingFilenumber = ($files | ?{($_.name).trim($fn) -eq $i}).name.trim($fn)} 
                else 
                {$operatingFilenumber = $null} 
 
                if(($operatingFilenumber -eq $null) -and ($i -ne 1) -and ($i -lt $logcount)) 
                { 
                    $operatingFilenumber = $i 
                    $newfilename = "$filefullname.$operatingFilenumber" 
                    $operatingFile = $files | ?{($_.name).trim($fn) -eq ($i-1)} 
                    write-host "moving to $newfilename" 
                    move-item ($operatingFile.FullName) -Destination $newfilename -Force 
                } 
                elseif($i -ge $logcount) 
                { 
                    if($operatingFilenumber -eq $null) 
                    {  
                        $operatingFilenumber = $i - 1 
                        $operatingFile = $files | ?{($_.name).trim($fn) -eq $operatingFilenumber} 
                        
                    } 
                    write-host "deleting " ($operatingFile.FullName) 
                    remove-item ($operatingFile.FullName) -Force 
                } 
                elseif($i -eq 1) 
                { 
                    $operatingFilenumber = 1 
                    $newfilename = "$filefullname.$operatingFilenumber" 
                    write-host "moving to $newfilename" 
                    move-item $filefullname -Destination $newfilename -Force 
                } 
                else 
                { 
                    $operatingFilenumber = $i +1  
                    $newfilename = "$filefullname.$operatingFilenumber" 
                    $operatingFile = $files | ?{($_.name).trim($fn) -eq ($i-1)} 
                    write-host "moving to $newfilename" 
                    move-item ($operatingFile.FullName) -Destination $newfilename -Force    
                } 
                     
            } 
 
                     
          } 
         else 
         { $logRollStatus = $false} 
    } 
    else 
    { 
        $logrollStatus = $false 
    } 
    $LogRollStatus 
}

Logger -logSev "s" -Message "Begin Reset-Log block"
$traceSize = Get-Item $traceLog
if ($traceSize.Length -gt 49MB ) {
    Start-Sleep -Seconds 30
    Reset-Log -fileName $traceLog -filesize 50mb -logcount 10
}
Reset-Log -fileName $phishLog -filesize 25mb -logcount 10
Reset-Log -fileName $runLog -filesize 50mb -logcount 10
#Reset-Log -fileName $spamTraceLog -filesize 25mb -logcount 10
Logger -logSev "s" -Message "End Reset-Log block"
Logger -logSev "i" -Message "Close Office 365 connection"
# Kill Office365 Session and Clear Variables
Remove-PSSession $Session
Logger -logSev "s" -Message "PIE Execution Completed"
Get-Variable -Exclude Session,banner | Remove-Variable -EA 0