using namespace System.Collections.Generic
Add-Type -Path "N:\Projects\git\MailKit\MailKit\MailKit\bin\Debug\net45\MailKit.dll"
Add-Type -Path "N:\Projects\git\MailKit\MailKit\MailKit\bin\Debug\net45\MimeKit.dll"
  #====================================#
  # PIE - Phishing Intelligence Engine #
  # v3.8  --  January 2021             #
  #====================================#

# Copyright 2021 LogRhythm Inc.   
# Licensed under the MIT License. See LICENSE file in the project root for full license information.

<#

INSTALL:

    Review lines 43 through 110
        Add credentials under each specified section


    Review Lines 111 through 187
        For each setting that you would like to enable, change the value from $false to $true

USAGE:

    Configure as a scheduled task to run every 15-minutes:
        C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -command "& 'C:\PIE_INSTALL_DIR\Invoke-PIE.ps1'"

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
$EncodedXMLCredentials = $true
$PlainText = $false

# XML Configuration - store credentials in an encoded XML (best option)
#     This file will need to be re-generated whenever the server reboots!
if ( $EncodedXMLCredentials ) {
    #
    # To generate the XML:
    #      PS C:\> Get-Credential | Export-Clixml Service-Account_cred.xml
    #
    $CredentialsFile = "N:\Projects\git\PIE\Service-Account_cred.xml"
    $PSCredential = Import-CliXml -Path $CredentialsFile 
}

# Plain Text Credentials (not recommended)
if ( $PlainText ) {
    $username = "SERVICE-ACCOUNT@SOMEDOMAIN.COM"
    $password = "PASSWORD"
}

$MailServer = "outlook.office365.com"
$MailServerPort = 993


# LogRhythm Case API Integration
$LogRhythmHost = "logrhythmhost.example.com"

# Case Folder and Logging
$pieFolder = "N:\Projects\git\PIE\Scripts\PIE"


# Case Tagging and User Assignment
# Default value - modify to match your case tagging schema. Note "PIE" tag is used with the Case Management Dashboard.
$defaultCaseTag = "PIE" 
# Primary case owner / SOC lead
$caseOwner = "hart, eric" 
# Add as many users as you would like, separate them like so: "user1", "user2"...
$caseCollaborators = ("hart, eric") 

# Phishing Playbook Assignment
$casePlaybook = "Phishing"


# ================================================================================
# Third Party Analytics
# ================================================================================

# For each supported module, set the flag to $true.
# Note these modules must be appropriately setup and configured as part of LogRhythm.Tools.
# For additional details on LogRhyhtm.Tools setup and configuration, visit: 
# https://github.com/LogRhythm-Tools/LogRhythm.Tools

# VirusTotal
$virusTotal = $true

# URL Scan
$urlscan = $true

# Shodan.io
$shodan = $true

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
$phishLog = "$pieFolder\logs\ongoing-phish-log.csv"
$caseFolder = "$pieFolder\cases\"
$tmpFolder = "$pieFolder\tmp\"
$runLog = "$pieFolder\logs\pierun.txt"
$log = $true


# PIE Version
$PIEVersion = 3.8

# LogRhythm API Integration via LogRhyhtm.Tools
Try {
    #Import-Module logrhythm.tools
    #Start-Sleep 10
} Catch {
    Write-Host "PIE requires installation and setup of PowerShell module: LogRhythm.Tools"
    Write-Host "Please visit https://github.com/LogRhythm-Tools/LogRhythm.Tools"
    Return 0
}
New-PIELogger -logSev "s" -Message "BEGIN NEW PIE EXECUTION" -LogFile $runLog -PassThru

# LogRhythm Tools Version
$LRTVersion = $(Get-Module -name logrhythm.tools | Select-Object -ExpandProperty Version) -join ","

New-PIELogger -logSev "i" -Message "PIE Version: $PIEVersion" -LogFile $runLog -PassThru
New-PIELogger -logSev "i" -Message "LogRhythm Tools Version: $LRTVersion" -LogFile $runLog -PassThru

# Email Parsing Varibles
$interestingFiles = @('pdf', 'exe', 'zip', 'doc', 'docx', 'docm', 'xls', 'xlsx', 'xlsm', 'ppt', 'pptx', 'arj', 'jar', '7zip', 'tar', 'gz', 'html', 'htm', 'js', 'rpm', 'bat', 'cmd')
$interestingFilesRegex = [string]::Join('|', $interestingFiles)

$specialPattern = "[^\u0000-\u007F]"

# Determine Available E-mail Log Sources
$SupportedLogSourceTypes = @('API - Office 365 Message Tracking', 'Flat File - MS Exchange 2003 Message Tracking Log', 'Flat File - MS Exchange 2007 Message Tracking Log', 'Flat File - MS Exchange 2010 Message Tracking Log', 'Flat File - MS Exchange 2013 Message Tracking Log', 'Flat File - MS Exchange 2016 Message Tracking Log', 'Flat File - Office 365 Message Tracking', 'Syslog - Open Collector - Gmail Message Tracking')
$LogSourceIDs = [list[int32]]::new()

# Lookup Log Source ID # for each SupportedLogSourceType
ForEach ($LogSourceType in $SupportedLogSourceTypes) {
    $LogTypeDetails = Get-LrLogSourceTypes -Name $LogSourceType
    if ($LogSourceIDs -notcontains $LogTypeDetails.id) {
        $LogSourceIDs.add($LogTypeDetails.Id)
    }
}

# Lookup each Log Source of each supported LogSource Type
$SearchLogSources = [list[int32]]::new()
ForEach ($LogSourceID in $LogSourceIDs) {
    $LogSourceDetails = Get-LrLogSources -MessageSourceTypeId $LogSourceId
    if ($LogSourceDetails) {
        if ($SearchLogSources -notcontains $LogSourceDetails.id) {
            $SearchLogSources.add($LogSourceDetails.Id)
        }
    }
}


# ================================================================================
# MEAT OF THE PIE
# ================================================================================
New-PIELogger -logSev "i" -Message "Check for New Reports" -LogFile $runLog -PassThru
if ( $log -eq $true) {
    #Create phishLog if file does not exist.
    if ( $(Test-Path $phishLog -PathType Leaf) -eq $false ) {
        Set-Content $phishLog -Value "MessageTraceId,Received,SenderAddress,RecipientAddress,FromIP,ToIP,Subject,Status,Size,MessageId"
        New-PIELogger -logSev "a" -Message "No phishlog detected.  Created new $phishLog"
    }

    # Search for Reported Phishing Messages
    <#
    Try {
        New-PIELogger -logSev "i" -Message "Loading previous reports to phishHistory" -LogFile $runLog -PassThru
        $phishHistory = Get-Content $phishLog | ConvertFrom-Csv -Header "MessageTraceID","Received","SenderAddress","RecipientAddress","FromIP","ToIP","Subject","Status","Size","MessageID"
    } Catch {
        New-PIELogger -logSev "e" -Message "Unable to read file: $phishLog" -LogFile $runLog -PassThru
        New-PIELogger -logSev "s" -Message "PIE Execution Halting" -LogFile $runLog -PassThru
        exit 1
    }
    #>
    <# IMAP #>
    # Establish Mailkit IMAP Mail Client
    $MailClient = New-Object MailKit.Net.Imap.ImapClient
    $MailClientSsl = [MailKit.Security.SecureSocketOptions]::Auto
    $MailClientCancelToken = New-Object System.Threading.CancellationToken ($false)

    # Define Connection String
    $MailClient.Connect("$MailServer", $MailServerPort, $MailClientSsl, $MailClientCancelToken)
    # Authenticate
    if ($PSCredential) {
        Try {
            $MailClient.Authenticate($PSCredential.Username, $PSCredential.GetNetworkCredential().Password, $MailClientCancelToken)
        } Catch {
            New-PIELogger -logSev "e" -Message "Unable to authenticate to mail server." -LogFile $runLog -PassThru
            New-PIELogger -logSev "s" -Message "PIE Execution Halting" -LogFile $runLog -PassThru
            exit 1
        }
    } elseif ($Username -and $Password) {
        New-PIELogger -logSev "i" -Message "Warning - Username and Password stored in plain text" -LogFile $runLog -PassThru
        Try {
            $MailClient.Authenticate($username, $password, $MailClientCancelToken)
        } Catch {
            New-PIELogger -logSev "e" -Message "Unable to authenticate to mail server." -LogFile $runLog -PassThru
            New-PIELogger -logSev "s" -Message "PIE Execution Halting" -LogFile $runLog -PassThru
            exit 1
        }
    } else {
            New-PIELogger -logSev "e" -Message "Username or Password not provided.  Unable to attempt connection." -LogFile $runLog -PassThru
            New-PIELogger -logSev "s" -Message "PIE Execution Halting" -LogFile $runLog -PassThru
            exit 1
    }

    

    #Open Inbox
    $Inbox = $MailClient.Inbox
    $Inbox.Open([MailKit.FolderAccess]::ReadWrite) | Out-Null
    $InboxNewMail = $inbox.Search([MailKit.Search.SearchQuery]::All)

    #Validate Inbox/COMPLETED Folder
    $InboxCompleted = $MailClient.Inbox
    $InboxCompleted = $InboxCompleted.GetSubfolders($false) | Where-Object {$_.Name -eq 'COMPLETED'}

    # If the folder does not exist, create it.
    if (!$InboxCompleted) {
        # Setup to create folders:
        $void = $inbox.Create("COMPLETED", $true)
        # Refresh Inbox folders
        $InboxCompleted = $cnn.Inbox
        # Set folder context for Completed
        $InboxCompleted = $InboxCompleted.GetSubfolders($false) | Where-Object {$_.Name -eq 'COMPLETED'}
    }

    #Validate Inbox/SKIPPED Folder
    $InboxSkipped = $MailClient.Inbox
    $InboxSkipped = $InboxSkipped.GetSubfolders($false) | Where-Object {$_.Name -eq 'SKIPPED'}

    # If the folder does not exist, create it.
    if (!$InboxSkipped) {
        # Setup to create folders:
        $void = $inbox.Create("SKIPPED", $true)
        # Refresh Inbox folders
        $InboxSkipped = $cnn.Inbox
        # Set folder context for Skipped
        $InboxSkipped = $InboxSkipped.GetSubfolders($false) | Where-Object {$_.Name -eq 'SKIPPED'}
    }

    # Establish List objects to facilitate moving e-mail messages to their target folders
    $FolderDestCompleted = [list[MailKit.UniqueId]]::new()
    $FolderDestSkipped = [list[MailKit.UniqueId]]::new()

    if ($InboxNewMail.count -eq 0) {
        New-PIELogger -logSev "i" -Message "No new reports detected" -LogFile $runLog -PassThru
    } else {
        New-PIELogger -logSev "i" -Message "New inbox items detected.  Proceeding to evaluate for PhishReports." -LogFile $runLog -PassThru

        # Loop through each inbox item to identify PhishReports
        for ($i = 0; $i -lt $InboxNewMail.Count; $i++) {
            $EmailMessage = $Inbox.GetMessage($i)
            $ValidSubmissionAttachment = $false
            foreach ($Attachment in $($EmailMessage.Attachments)) {
                if ($Attachment.ContentType.MimeType -eq "message/rfc822") {
                    $ValidSubmissionAttachment = $true
                } elseif ($Attachment.ContentType.Name -match "^.*\.(eml|msg)") {
                    $ValidSubmissionAttachment = $true
                }
            }

            $MailId = [MailKit.UniqueId]($InboxNewMail[$i])
            if ($ValidSubmissionAttachment) {
                if ($FolderDestCompleted -notcontains $MailId) {
                    $FolderDestCompleted.add($MailId)
                }
            } else {
                if ($FolderDestSkipped -notcontains $MailId) {
                    $FolderDestSkipped.add($MailId) 
                }
            }
        }
    
        
        New-PIELogger -logSev "s" -Message "Begin processing newReports" -LogFile $runLog -PassThru

        :newReport ForEach ($MailId in $FolderDestCompleted) {
            $StartTime = (get-date).ToUniversalTime()

            # Load NewReport
            $NewReport = $Inbox.GetMessage($MailId)

            # Establish Submission PSObject
            $Attachments = [list[object]]::new()

            # Report GUID
            $ReportGuid = $(New-Guid | Select-Object -ExpandProperty Guid)

            # Add data for evaluated email
            $ReportEvidence = [PSCustomObject]@{
                Meta = [PSCustomObject]@{ 
                    GUID = $ReportGuid
                    Timestamp = $StartTime.ToString("yyyy-MM-ddTHHmmssffZ")
                    Metrics = [PSCustomObject]@{ 
                        Begin = $StartTime.ToString("yyyy-MM-ddTHHmmssffZ")
                        End = $null
                        Duration = $null
                    }
                    Version = [PSCustomObject]@{ 
                        PIE = $PIEVersion
                        LRTools = $LRTVersion
                    }
                }
                ReportSubmission = [PSCustomObject]@{
                    Sender = $($NewReport.From.Address)
                    SenderDisplayName = $($NewReport.From.Name)
                    Recipient = $($NewReport.To.Address)
                    Subject = [PSCustomObject]@{
                        Original = $($NewReport.Subject)
                        Modified = $null
                    }
                    UtcDate = $($NewReport.date.utcdatetime).ToString("yyyy-MM-ddTHHmmssffZ")
                    MessageId = $($NewReport.messageid)
                    Attachment = [PSCustomObject]@{
                        Name = $null
                        Type = $null
                        Hash = $null
                    }
                }
                EvaluationResults = [PSCustomObject]@{
                    Sender = $null
                    SenderDisplayName = $null
                    Recipient = [PSCustomObject]@{
                        To = $null
                        CC = $null
                    }
                    UtcDate = $null
                    Subject = [PSCustomObject]@{
                        Original = $null
                        Modified = $null
                    }
                    Body = [PSCustomObject]@{
                        Original = $null
                        Modified = $null
                    }
                    HTMLBody = [PSCustomObject]@{
                        Original = $null
                        Modified = $null
                    }
                    Headers = $null
                    Attachments = $null
                    Links = [PSCustomObject]@{
                        Source = $null
                        Value = $null
                        Details = $null
                    }
                }
                LogRhythmCase = [PSCustomObject]@{
                    Number = $null
                    Url = $null
                    Details = $null
                }
                LogRhythmSearch = $null
            }

            # Track the user who reported the message
            New-PIELogger -logSev "i" -Message "Sent By: $($ReportEvidence.ReportSubmission.Sender)  Reported Subject: $($ReportEvidence.ReportSubmission.Subject.Original)" -LogFile $runLog -PassThru
            
            # Extract and load attached e-mail attachment
            foreach ($Attachment in $($NewReport.Attachments)) {
                

                if ($Attachment.ContentType.MimeType -eq "message/rfc822") {
                    New-PIELogger -logSev "s" -Message "Processing rfc822 data format" -LogFile $runLog -PassThru
                    $ReportEvidence.ReportSubmission.Attachment.Name = $Attachment.Message.From.Address.Replace("@","_").replace(".","-") + ".eml"
                    $ReportEvidence.ReportSubmission.Attachment.Type = $Attachment.ContentType.MimeType
                    $TmpSavePath = [System.IO.FileInfo]::new((Join-Path -Path $tmpFolder -ChildPath $ReportEvidence.ReportSubmission.Attachment.Name))
                    $Attachment.Message.WriteTo($TmpSavePath)

                    $ReportEvidence.ReportSubmission.Attachment.Hash = @(Get-FileHash -Path $TmpSavePath -Algorithm SHA256)
                } elseif ($Attachment.ContentType.Name -match "^.*\.(eml|msg)") {
                    New-PIELogger -logSev "s" -Message "Processing .msg/.eml file format" -LogFile $runLog -PassThru
                    $ReportEvidence.ReportSubmission.Attachment.Name = $Attachment.ContentType.Name
                    $ReportEvidence.ReportSubmission.Attachment.Type = $Attachment.ContentType.MimeType
                    $TmpSavePath = [System.IO.FileInfo]::new((Join-Path -Path $tmpFolder -ChildPath $Attachment.ContentType.Name))
                    
                    # Establish FileStream to faciliating extracting e-mail attachment
                    $SaveFileMode = [System.IO.FileMode]::Create
                    $SaveFileAccess = [System.IO.FileAccess]::Write
                    $SaveFileShare = [System.IO.FileShare]::Read
                    $SaveFileStream = New-Object -TypeName System.IO.FileStream($TmpSavePath, $SaveFileMode, $SaveFileAccess, $SaveFileShare)

                    # Save attachment to TmpSavePath
                    Try {
                        $Attachment.Content.DecodeTo($SaveFileStream) | Out-Null
                    } Catch {
                        New-PIELogger -logSev "e" -Message "Unable to save file $TmpSavePath" -LogFile $runLog -PassThru
                    }
                    # Release FileStream
                    $SaveFileStream.Close()
                }
            }

            # Load e-mail from file
            $Eml = [MimeKit.MimeMessage]::Load($TmpSavePath)
            $ReportEvidence.ReportSubmission.Attachment.Hash = @(Get-FileHash -Path $TmpSavePath -Algorithm SHA256)

            $ReportEvidence.EvaluationResults.Subject.Original = $Eml.Subject
            if ($($ReportEvidence.EvaluationResults.Subject.Original) -Match "$specialPattern") {
                New-PIELogger -logSev "i" -Message "Creating Message Subject without Special Characters to support Case Note." -LogFile $runLog -PassThru
                $ReportEvidence.EvaluationResults.Subject.Modified = $ReportEvidence.EvaluationResults.Subject.Original -Replace "$specialPattern","?"
            }

            New-PIELogger -logSev "d" -Message "Message subject: $($ReportEvidence.EvaluationResults.Subject)" -LogFile $runLog -PassThru

                        
            #Plain text Message Body
            $ReportEvidence.EvaluationResults.Body.Original = $Eml.TextBody
            
            if ($($ReportEvidence.EvaluationResults.Body.Original) -Match "$specialPattern") {
                New-PIELogger -logSev "i" -Message "Creating Message Body without Special Characters to support Case Note." -LogFile $runLog -PassThru
                $ReportEvidence.EvaluationResults.Body.Modified = $ReportEvidence.EvaluationResults.Body.Original -Replace "$specialPattern","?"
            }                     

            #Headers
            New-PIELogger -logSev "d" -Message "Processing Headers" -LogFile $runLog -PassThru
            $ReportEvidence.EvaluationResults.Headers = $Eml.Headers

                        
            New-PIELogger -logSev "s" -Message "Begin Parsing URLs" -LogFile $runLog -PassThru                  
            #Load links
            #Check if HTML Body exists else populate links from Text Body
            New-PIELogger -logSev "i" -Message "Identifying URLs" -LogFile $runLog -PassThru
                        
            if ( $($Eml.HTMLBody.Length -gt 0) ) {
                # Set ReportEvidence HTMLBody Content
                #HTML Message Body
                $ReportEvidence.EvaluationResults.HTMLBody.Original = $Eml.HTMLBody.ToString()
                # Pull URL data from HTMLBody Content
                New-PIELogger -logSev "d" -Message "Processing URLs from message HTML body" -LogFile $runLog -PassThru
                $ReportEvidence.EvaluationResults.Links.Source = "HTML"
                $ReportEvidence.EvaluationResults.Links.Value = Get-PIEURLsFromHTML -HTMLSource $($ReportEvidence.EvaluationResults.HTMLBody.Original)

                # Create copy of HTMLBody with special characters removed.
                if ($($ReportEvidence.EvaluationResults.HTMLBody.Original) -Match "$specialPattern") {
                    New-PIELogger -logSev "i" -Message "Creating HTMLBody without Special Characters to support Case Note." -LogFile $runLog -PassThru
                    $ReportEvidence.EvaluationResults.HTMLBody.Modified = $ReportEvidence.EvaluationResults.HTMLBody.Original -Replace "$specialPattern","?"
                }
            } else {
                New-PIELogger -logSev "a" -Message "Processing URLs from Text body - Last Effort Approach" -LogFile $runLog -PassThru
                $ReportEvidence.EvaluationResults.Links.Source = "Text"
                $ReportEvidence.EvaluationResults.Links.Value = $(Get-PIEURLsFromText -Text $($ReportEvidence.EvaluationResults.Body.Original))
            }
            New-PIELogger -logSev "s" -Message "End Parsing URLs" -LogFile $runLog -PassThru

            New-PIELogger -logSev "s" -Message "Begin Attachment block" -LogFile $runLog -PassThru
            New-PIELogger -logSev "i" -Message "Attachment Count: $($Eml.Attachments.Count)" -LogFile $runLog -PassThru

            if ( $Eml.Attachments.Count -gt 0 ) {
                # Validate path tmpFolder\attachments exists
                if (Test-Path "$tmpFolder\attachments" -PathType Container) {
                    New-PIELogger -logSev "i" -Message "Folder $tmpFolder\attatchments\ exists" -LogFile $runLog -PassThru
                } else {
                    New-PIELogger -logSev "i" -Message "Creating folder: $tmpFolder\attatchments\" -LogFile $runLog -PassThru
                    Try {
                        New-Item -Path "$tmpFolder\attachments" -type Directory -Force | Out-null
                    } Catch {
                        New-PIELogger -logSev "e" -Message "Unable to create folder: $tmpFolder\attatchments\" -LogFile $runLog -PassThru
                    }
                }                
                # Get the filename and location
                $Eml.attachments | ForEach-Object {
                    $attachmentName = $_.filename
                    $attachmentFull = $tmpFolder+"attachments\"+$attachmentName
                    New-PIELogger -logSev "d" -Message "Attachment Name: $attachmentName" -LogFile $runLog -PassThru
                    New-PIELogger -logSev "i" -Message "Checking attachment against interestingFilesRegex" -LogFile $runLog -PassThru
                    If ($attachmentName -match $interestingFilesRegex) {
                        New-PIELogger -logSev "d" -Message "Saving Attachment to destination: $tmpFolder\attachments\$attachmentName" -LogFile $runLog -PassThru

                        # Establish FileStream to faciliating extracting e-mail attachment
                        $TmpSavePath = $attachmentFull
                        $SaveFileMode = [System.IO.FileMode]::Create
                        $SaveFileAccess = [System.IO.FileAccess]::Write
                        $SaveFileShare = [System.IO.FileShare]::Read
                        $SaveFileStream = New-Object -TypeName System.IO.FileStream $TmpSavePath, $SaveFileMode, $SaveFileAccess, $SaveFileShare

                        # Save attachment to TmpSavePath
                        Try {
                            $_.Content.DecodeTo($SaveFileStream) 
                        } Catch {
                            New-PIELogger -logSev "e" -Message "Unable to save file $TmpSavePath." -LogFile $runLog -PassThru
                        }
                        # Release FileStream
                        $SaveFileStream.Close()    

                        $Attachment = [PSCustomObject]@{
                            Name = $_.filename
                            Type = $_.ContentType.MimeType
                            Hash = @(Get-FileHash -Path $TmpSavePath -Algorithm SHA256)
                            Plugins = [pscustomobject]@{
                                VirusTotal = $null
                            }
                        }
                        # Add Attachment object to Attachments list
                        if ($Attachments -notcontains $attachment) {
                            $Attachments.Add($Attachment)
                        }
                    }
                }
            }
                        

            $ReportEvidence.EvaluationResults.Sender = $Eml.From.Address
            New-PIELogger -logSev "i" -Message "Origin sender set to: $($ReportEvidence.EvaluationResults.Sender )" -LogFile $runLog -PassThru
            $ReportEvidence.EvaluationResults.SenderDisplayName = $Eml.From.Name
            if ($Eml.To.count -ge 1 -or $Eml.To.Length -ge 1) {
                $ReportEvidence.EvaluationResults.Recipient.To = $Eml.To.Address
            } else {
                $ReportEvidence.EvaluationResults.Recipient.To = $ReportEvidence.ReportSubmission.Sender
            }
            $ReportEvidence.EvaluationResults.Recipient.CC = $Eml.CC
            
            $ReportEvidence.EvaluationResults.UtcDate = $Eml.Date.UtcDateTime.ToString("yyyy-MM-ddTHHmmssffZ")
            New-PIELogger -logSev "i" -Message "Origin Sender Display Name set to: $($ReportEvidence.EvaluationResults.SenderDisplayName)" -LogFile $runLog -PassThru

        
            New-PIELogger -logSev "s" -Message "Begin Link Processing" -LogFile $runLog -PassThru
            
            $EmailUrls = [list[string]]::new()
            $EmailDomains = [list[string]]::new()

            if ($ReportEvidence.EvaluationResults.Links.Value) {
                $UrlDetails = [list[pscustomobject]]::new()
                if ($ReportEvidence.EvaluationResults.Links.Source -like "HTML") {
                    New-PIELogger -logSev "i" -Message "Link processing from HTML Source" -LogFile $runLog -PassThru
                    $EmailUrls = $($ReportEvidence.EvaluationResults.Links.Value | Where-Object -Property Type -like "Url")
                    $DomainGroups = $EmailUrls.hostname | group-object
                    $UniqueDomains = $DomainGroups.count
                    New-PIELogger -logSev "i" -Message "Links: $($EmailUrls.count) Domains: $UniqueDomains" -LogFile $runLog -PassThru
                    ForEach ($UniqueDomain in $DomainGroups) {  
                        New-PIELogger -logSev "i" -Message "Domain: $($UniqueDomain.Name) URLs: $($UniqueDomain.Count)" -LogFile $runLog -PassThru
                        if ($UniqueDomain.count -ge 2) {
                            # Collect details for initial
                            $ScanTarget = $EmailUrls | Where-Object -Property hostname -like $UniqueDomain.Name | Select-Object -ExpandProperty Url -First 1
                            New-PIELogger -logSev "i" -Message "Retrieve Domain Details - Url: $ScanTarget" -LogFile $runLog -PassThru
                            $DetailResults = Get-PIEUrlDetails -Url $ScanTarget -EnablePlugins -VTDomainScan
                            if ($UrlDetails -NotContains $DetailResults) {
                                $UrlDetails.Add($DetailResults)
                            }

                            # Provide summary but skip plugin output for remainder URLs
                            $SummaryLinks = $EmailUrls | Where-Object -Property hostname -like $UniqueDomain.Name | Select-Object -ExpandProperty Url -Skip 1
                            ForEach ($SummaryLink in $SummaryLinks) {
                                $DetailResults = Get-PIEUrlDetails -Url $SummaryLink
                                if ($UrlDetails -NotContains $DetailResults) {
                                    $UrlDetails.Add($DetailResults)
                                }
                            }
                        } else {
                            $ScanTargets = $EmailUrls | Where-Object -Property hostname -like $UniqueDomain.Name | Select-Object -ExpandProperty Url
                            ForEach ($ScanTarget in $ScanTargets) {
                                New-PIELogger -logSev "i" -Message "Retrieve URL Details - Url: $ScanTarget" -LogFile $runLog -PassThru
                                $DetailResults = Get-PIEUrlDetails -Url $ScanTarget -EnablePlugins
                                if ($UrlDetails -NotContains $DetailResults) {
                                    $UrlDetails.Add($DetailResults)
                                }
                            }
                        }
                    }
                }
                if ($ReportEvidence.EvaluationResults.Links.Source -like "Text") {
                    $EmailUrls = $ReportEvidence.EvaluationResults.Links.Value
                    ForEach ($EmailURL in $EmailUrls) {
                        $DetailResults  = Get-PIEUrlDetails -Url $EmailURL
                        if ($UrlDetails -NotContains $DetailResults) {
                            $UrlDetails.Add($DetailResults)
                        }
                    }
                }
                # Add the UrlDetails results to the ReportEvidence object.
                if ($UrlDetails) {
                    $ReportEvidence.EvaluationResults.Links.Details = $UrlDetails
                }
            }
            
            if ($ReportEvidence.EvaluationResults.Links.Details) {                    
                New-PIELogger -logSev "d" -Message "Writing list of unique domains to $tmpFolder`domains.txt" -LogFile $runLog -PassThru
                Try {
                    $($ReportEvidence.EvaluationResults.Links.Details.ScanTarget | Select-Object -ExpandProperty Domain -Unique) > "$tmpFolder`domains.txt"
                } Catch {
                    New-PIELogger -logSev "e" -Message "Unable to write to file $tmpFolder`domains.txt" -LogFile $runLog -PassThru
                }

                
                New-PIELogger -logSev "d" -Message "Writing list of unique urls to $tmpFolder`links.txt" -LogFile $runLog -PassThru
                Try {
                    $($ReportEvidence.EvaluationResults.Links.Details.ScanTarget | Select-Object -ExpandProperty Url -Unique) > "$tmpFolder`links.txt"
                } Catch {
                    New-PIELogger -logSev "e" -Message "Unable to write to file $tmpFolder`links.txt" -LogFile $runLog -PassThru
                }
                
                
                $CountLinks = $($ReportEvidence.EvaluationResults.Links.Details.ScanTarget | Select-Object -ExpandProperty Url -Unique | Measure-Object | Select-Object -ExpandProperty Count)
                New-PIELogger -logSev "i" -Message "Total Unique Links: $countLinks" -LogFile $runLog -PassThru

                $CountDomains = $($ReportEvidence.EvaluationResults.Links.Details.ScanTarget | Select-Object -ExpandProperty Domain -Unique | Measure-Object | Select-Object -ExpandProperty Count)
                New-PIELogger -logSev "i" -Message "Total Unique Domains: $countDomains" -LogFile $runLog -PassThru
            }
            New-PIELogger -logSev "s" -Message "End Link Processing" -LogFile $runLog -PassThru

            New-PIELogger -logSev "s" -Message "Begin Attachment Processing" -LogFile $runLog -PassThru
            ForEach ($Attachment in $ReportEvidence.EvaluationResults.Attachments) {
                New-PIELogger -logSev "i" -Message "Attachment: $($Attachment.Name)" -LogFile $runLog -PassThru
                if ($LrtConfig.VirusTotal.ApiKey) {
                    New-PIELogger -logSev "i" -Message "VirusTotal - Submitting Hash: $($Attachment.Hash.Hash)" -LogFile $runLog -PassThru
                    $VTResults = Get-VtHashReport -Hash $Attachment.Hash.Hash
                    # Response Code 0 = Result not in dataset
                    if ($VTResults.response_code -eq 0) {
                        New-PIELogger -logSev "i" -Message "VirusTotal - Result not in dataset." -LogFile $runLog -PassThru
                        $VTResponse = [PSCustomObject]@{
                            Status = $true
                            Note = $VTResults.verbose_msg
                            Results = $VTResults
                        }
                        $Attachment.Plugins.VirusTotal = $VTResponse
                    } elseif ($VTResults.response_code -eq 1) {
                        # Response Code 1 = Result in dataset
                        New-PIELogger -logSev "i" -Message "VirusTotal - Result in dataset." -LogFile $runLog -PassThru
                        $VTResponse = [PSCustomObject]@{
                            Status = $true
                            Note = $VTResults.verbose_msg
                            Results = $VTResults
                        }
                        $Attachment.Plugins.VirusTotal = $VTResults
                    } else {
                        New-PIELogger -logSev "i" -Message "VirusTotal - Request failed." -LogFile $runLog -PassThru
                        $VTResponse = [PSCustomObject]@{
                            Status = $false
                            Note = "Requested failed."
                            Results = $VTResults
                        }
                        $Attachment.Plugins.VirusTotal = $VTResponse
                    }
                }
            }
            New-PIELogger -logSev "s" -Message "End Attachment Processing" -LogFile $runLog -PassThru
            # Create a case folder
            New-PIELogger -logSev "s" -Message "Creating Evidence Folder" -LogFile $runLog -PassThru
            # - Another shot
            $caseID = Get-Date -Format M-d-yyyy_h-m-s
            if ( $ReportEvidence.EvaluationResults.Sender.Contains("@") -eq $true) {
                $spammerName = $ReportEvidence.EvaluationResults.Sender.Split("@")[0]
                $spammerDomain = $ReportEvidence.EvaluationResults.Sender.Split("@")[1]
                New-PIELogger -logSev "d" -Message "Spammer Name: $spammerName Spammer Domain: $spammerDomain" -LogFile $runLog -PassThru
                $caseID = $caseID+"_Sender_"+$spammerName+".at."+$spammerDomain
            } else {
                New-PIELogger -logSev "d" -Message "Case created as Fwd Message source" -LogFile $runLog -PassThru
                $caseID = $caseID+"_"+$ReportEvidence.EvaluationResults.SenderDisplayName
            }
            try {
                New-PIELogger -logSev "i" -Message "Creating Directory: $caseFolder$caseID" -LogFile $runLog -PassThru
                mkdir $caseFolder$caseID | out-null
            } Catch {
                New-PIELogger -logSev "e" -Message "Unable to create directory: $caseFolder$caseID" -LogFile $runLog -PassThru
            }
            # Support adding Network Share Location to the Case
            $hostname = hostname
            $networkShare = "\\$hostname\PIE\cases\$caseID\"

            # Copy evidence files to case folder
            New-PIELogger -logSev "i" -Message "Moving interesting files to case folder" -LogFile $runLog -PassThru
            Try {
                # Make sure those files are moved
                Copy-Item -Force -Recurse "$tmpFolder*" -Destination $caseFolder$caseID | Out-Null
            } Catch {
                New-PIELogger -logSev "e" -Message "Unable to copy contents from $tmpFolder to $CaseFolder$CaseId" -LogFile $runLog -PassThru
            }
            
            # Cleanup Temporary Folder
            Try {
                Remove-Item "$tmpFolder*" -Force -Recurse | Out-Null
            } Catch {
                New-PIELogger -logSev "e" -Message "Unable to purge contents from $tmpFolder" -LogFile $runLog -PassThru
            }  


            New-PIELogger -logSev "s" -Message "LogRhythm API - Create Case" -LogFile $runLog -PassThru
            if ( $ReportEvidence.EvaluationResults.Sender.Contains("@") -eq $true) {
                New-PIELogger -logSev "d" -Message "LogRhythm API - Create Case with Sender Info" -LogFile $runLog -PassThru
                $caseSummary = "Phishing email from $($ReportEvidence.EvaluationResults.Sender) was reported on $($ReportEvidence.ReportSubmission.UtcDate) UTC by $($ReportEvidence.ReportSubmission.Sender). The subject of the email is ($($ReportEvidence.EvaluationResults.Subject.Original))."
                $CaseDetails = New-LrCase -Name "Phishing : $spammerName [at] $spammerDomain" -Priority 3 -Summary $caseSummary -PassThru
            } else {
                New-PIELogger -logSev "d" -Message "LogRhythm API - Create Case without Sender Info" -LogFile $runLog -PassThru
                $caseSummary = "Phishing email was reported on $($ReportEvidence.ReportSubmission.UtcDate) UTC by $($ReportEvidence.ReportSubmission.Sender). The subject of the email is ($($ReportEvidence.EvaluationResults.Subject.Original))."
                $CaseDetails = New-LrCase -Name "Phishing Message Reported" -Priority 3 -Summary $caseSummary -PassThru
                
            }
            Start-Sleep .2

            # Set ReportEvidence CaseNumber
            $ReportEvidence.LogRhythmCase.Number = $CaseDetails.number

            Try {
                $ReportEvidence.LogRhythmCase.Number | Out-File "$caseFolder$caseID\case.txt"
            } Catch {
                New-PIELogger -logSev "e" -Message "Unable to move $pieFolder\plugins\case.txt to $caseFolder$caseID\" -LogFile $runLog -PassThru
            }
            
            # Establish Case URL to ReportEvidence Object
            $ReportEvidence.LogRhythmCase.Url = "https://$LogRhythmHost/cases/$($ReportEvidence.LogRhythmCase.Number)"
            New-PIELogger -logSev "i" -Message "Case URL: $($ReportEvidence.LogRhythmCase.Url)" -LogFile $runLog -PassThru

            # Update case Earliest Evidence
            if ($ReportEvidence.EvaluationResults.UtcDate) {
                # Based on recipient's e-mail message recieve timestamp from origin sender
                [datetime] $EvidenceTimestamp = [datetime]::parseexact($ReportEvidence.EvaluationResults.UtcDate, "yyyy-MM-ddTHHmmssffZ", $null)
                Update-LrCaseEarliestEvidence -Id $($ReportEvidence.LogRhythmCase.Number) -Timestamp $EvidenceTimestamp
            } else {
                # Based on report submission for evaluation
                [datetime] $Timestamp = [datetime]::parseexact($ReportEvidence.ReportSubmission.UtcDate, "yyyy-MM-ddTHHmmssffZ", $null)
                Update-LrCaseEarliestEvidence -Id $($ReportEvidence.LogRhythmCase.Number) -Timestamp $EvidenceTimestamp
            }
            
        
            # Tag the case as phishing
            New-PIELogger -logSev "i" -Message "LogRhythm API - Applying case tag" -LogFile $runLog -PassThru
            if ( $defaultCaseTag ) {
                $TagStatus = Get-LrTags -Name $defaultCaseTag -Exact
                Start-Sleep 0.2
                if (!$TagStatus) {
                        $TagStatus = New-LrTag -Tag $defaultCaseTag -PassThru
                        Start-Sleep 0.2
                }
                if ($TagStatus) {
                        Add-LrCaseTags -Id $ReportEvidence.LogRhythmCase.Number -Tags $TagStatus.Number
                        New-PIELogger -logSev "i" -Message "LogRhythm API - Adding tag $defaultCaseTag Tag Number $($TagStatus.number)" -LogFile $runLog -PassThru
                        Start-Sleep 0.2
                }
            }

            # Adding and assigning other users
            New-PIELogger -logSev "i" -Message "LogRhythm API - Assigning case collaborators" -LogFile $runLog -PassThru
            if ( $caseCollaborators ) {
                Add-LrCaseCollaborators -Id $ReportEvidence.LogRhythmCase.Number -Names $caseCollaborators
            }

            # Begin Section - Search
            if ($SearchLogSources) {
                $SearchSender = New-LrSearch -MaxMsgsToQuery 10000 -QueryTimeout 300 -QueryEventManager $false -LogSources $SearchLogSources -MsgFilterType grouped -GroupFilterOperator and -GroupFilterMode filterin -Param1MetaField "Sender" -Param1Value $($ReportEvidence.EvaluationResults.Sender) -Verbose
                New-PIELogger -logSev "i" -Message "LogRhythm Search API - TaskId: $($SearchSender.TaskId) Status: Starting" -LogFile $runLog -PassThru
                if ($SearchSender.StatusCode -eq 200) {
                    do {
                        $SearchStatus = Get-LrSearchResults -TaskId $SearchSender.TaskId -Verbose -PageSize 1000
                        Start-Sleep 10
                        New-PIELogger -logSev "i" -Message "LogRhythm Search API - TaskId: $($SearchSender.TaskId) Status: Searching" -LogFile $runLog -PassThru
                    } until ($SearchStatus.TaskStatus -like "Completed:*")
                    New-PIELogger -logSev "i" -Message "LogRhythm Search API - TaskId: $($SearchSender.TaskId) Status: Complete" -LogFile $runLog -PassThru
                    $ReportEvidence.LogRhythmSearch = $SearchStatus
                } else {
                    $ReportEvidence.LogRhythmSearch = $SearchSender
                }
            }
            # End Section - Search
    

# ================================================================================
# Case Closeout
# ================================================================================
            
            New-PIELogger -logSev "s" -Message "Begin LogRhythm Playbook Block" -LogFile $runLog -PassThru
            if ($casePlaybook) {
                New-PIELogger -logSev "i" -Message "LogRhythm API - Adding Playbook:$casePlaybook to Case:$($ReportEvidence.LogRhythmCase.Number)" -LogFile $runLog -PassThru
                Add-LrCasePlaybook -Id $ReportEvidence.LogRhythmCase.Number -Playbook $casePlaybook
            } else {
                New-PIELogger -logSev "i" -Message "LogRhythm API - Playbook Omision - Playbook not defined" -LogFile $runLog -PassThru
            }
            New-PIELogger -logSev "s" -Message "End LogRhythm Playbook Block" -LogFile $runLog -PassThru


            # Add Link plugin output to Case
            ForEach ($UrlDetails in $ReportEvidence.EvaluationResults.Links.Details) {
                if ($shodan) {
                    if ($UrlDetails.Plugins.Shodan) {
                        $CasePluginShodanNote = $UrlDetails.Plugins.Shodan | Format-ShodanTextOutput
                        Add-LrNoteToCase -id $ReportEvidence.LogRhythmCase.Number -Text $($CasePluginShodanNote).subString(0, [System.Math]::Min(20000, $CasePluginShodanNote.Length))
                    }
                }
                if ($urlscan) {
                    if ($UrlDetails.Plugins.urlscan) {
                        $CasePluginUrlScanNote = $UrlDetails.Plugins.urlscan | Format-UrlscanTextOutput
                        Add-LrNoteToCase -id $ReportEvidence.LogRhythmCase.Number -Text $($CasePluginUrlScanNote).subString(0, [System.Math]::Min(20000, $CasePluginUrlScanNote.Length))
                    }
                }
                if ($virusTotal) {
                    if ($UrlDetails.Plugins.VirusTotal) {
                        $CasePluginVTNote = $UrlDetails.Plugins.VirusTotal  | Format-VTTextOutput 
                        Add-LrNoteToCase -id $ReportEvidence.LogRhythmCase.Number -Text $($CasePluginVTNote).subString(0, [System.Math]::Min(20000, $CasePluginVTNote.Length))
                    }
                }
            }

            # Add Attachment plugin output to Case
            ForEach ($AttachmentDetails in $ReportEvidence.EvaluationResults.Attachments) {
                if ($virusTotal) {
                    if ($AttachmentDetails.Plugins.VirusTotal.Status) {
                        $CasePluginVTNote = $AttachmentDetails.Plugins.VirusTotal.Results | Format-VTTextOutput 
                        Add-LrNoteToCase -id $ReportEvidence.LogRhythmCase.Number -Text $($CasePluginVTNote).subString(0, [System.Math]::Min(20000, $CasePluginVTNote.Length))
                    }
                }
            }

            # Copy E-mail Message text body to case
            New-PIELogger -logSev "i" -Message "LogRhythm API - Copying e-mail body text to case" -LogFile $runLog -PassThru
            if ( $ReportEvidence.EvaluationResults.Body.Original ) {
                $DefangBody = $ReportEvidence.EvaluationResults.Body.Modified.subString(0, [System.Math]::Min(19910, $ReportEvidence.EvaluationResults.Body.Modified.Length)).Replace('<http','<hxxp')
                $NoteStatus = Add-LrNoteToCase -Id $ReportEvidence.LogRhythmCase.Number -Text "=== Reported Message Body ===`r`n--- BEGIN ---$DefangBody`r`n--- END ---" -PassThru
                if ($NoteStatus.Error) {
                    New-PIELogger -logSev "e" -Message "LogRhythm API - Unable to add ReportEvidence.EvaluationResults.Body to LogRhythm Case." -LogFile $runLog -PassThru
                    New-PIELogger -logSev "d" -Message "LogRhythm API - Code: $($NoteStatus.Error.Code) Note: $($NoteStatus.Error.Note)" -LogFile $runLog -PassThru
                }
            }

            # Add Link/Attachment Summary as second Case note
            $CaseEvidenceSummaryNote = Format-PIEEvidenceSummary -EvaluationResults $ReportEvidence.EvaluationResults
            Add-LrNoteToCase -Id $ReportEvidence.LogRhythmCase.Number -Text $CaseEvidenceSummaryNote.Substring(0,[System.Math]::Min(20000, $CaseEvidenceSummaryNote.Length))

            # Conclude runtime metrics
            $EndTime = (get-date).ToUniversalTime()
            $ReportEvidence.Meta.Metrics.End = $EndTime.ToString("yyyy-MM-ddTHHmmssffZ")
            $Duration = New-Timespan -Start $StartTime -End $EndTime
            $ReportEvidence.Meta.Metrics.Duration = $Duration.ToString("%m\.%s\.%f")

            # Add overall summary as last, top most case note.
            $CaseSummaryNote = Format-PIECaseSummary -ReportEvidence $ReportEvidence
            Add-LrNoteToCase -Id $ReportEvidence.LogRhythmCase.Number -Text $CaseSummaryNote.Substring(0,[System.Math]::Min(20000, $CaseSummaryNote.Length))

            $ReportEvidence.LogRhythmCase.Details = Get-LrCaseById -Id $ReportEvidence.LogRhythmCase.Number

            $Reports.Add($ReportEvidence)

            # Write PIE Report Json object out to Case as Evidence
            $ReportEvidence | ConvertTo-Json -Depth 50 | Out-File -FilePath "$caseFolder$caseID\Case_Report.json"
            
            # Write TXT Report as Evidence
            $CaseFile = "\Case_Report.txt"
            $CaseSummaryNote | Out-File -FilePath $caseFolder$caseID$CaseFile
            $CaseEvidenceSummaryNote | Out-File -FilePath $caseFolder$caseID$CaseFile -Append

            $EvidenceSeperator = "-----------------------------------------------`r`n"
            # Add Link plugin output to TXT Case
            ForEach ($UrlDetails in $ReportEvidence.EvaluationResults.Links.Details) {
                if ($shodan) {
                    if ($UrlDetails.Plugins.Shodan) {
                        $EvidenceSeperator  | Out-File -FilePath $caseFolder$caseID$CaseFile -Append
                        $($UrlDetails.Plugins.Shodan | Format-ShodanTextOutput) | Out-File -FilePath $caseFolder$caseID$CaseFile -Append
                    }
                }
                if ($urlscan) {
                    if ($UrlDetails.Plugins.urlscan) {
                        $EvidenceSeperator  | Out-File -FilePath $caseFolder$caseID$CaseFile -Append
                        $($UrlDetails.Plugins.urlscan | Format-UrlscanTextOutput)  | Out-File -FilePath $caseFolder$caseID$CaseFile -Append
                    }
                }
                if ($virusTotal) {
                    if ($UrlDetails.Plugins.VirusTotal) {
                        $EvidenceSeperator  | Out-File -FilePath $caseFolder$caseID$CaseFile -Append
                        $($UrlDetails.Plugins.VirusTotal | Format-VTTextOutput)  | Out-File -FilePath $caseFolder$caseID$CaseFile -Append
                    }
                }
            }
            # Add Attachment plugin output to Case
            ForEach ($AttachmentDetails in $ReportEvidence.EvaluationResults.Attachments) {
                if ($virusTotal) {
                    $EvidenceSeperator  | Out-File -FilePath $caseFolder$caseID$CaseFile -Append
                    if ($AttachmentDetails.Plugins.VirusTotal.Status) {
                        $($AttachmentDetails.Plugins.VirusTotal.Results | Format-VTTextOutput)  | Out-File -FilePath $caseFolder$caseID$CaseFile -Append
                    }
                }
            }
        }

        #Cleanup Variables prior to next evaluation
        New-PIELogger -logSev "s" -Message "Resetting analysis varaiables" -LogFile $runLog -PassThru
        $attachmentFull = $null
        $attachment = $null
        $attachments = $null
        $caseID = $null
    }

    # Move items from inbox to target folders
    ForEach ($CompletedItem in $FolderDestCompleted) {
        try { 
            $Inbox.MoveTo($CompletedItem,$InboxCompleted,$MailClientCancelToken) | Out-Null
        } catch { 
            $_ 
        }
    }

    ForEach ($SkippedItem in $FolderDestSkipped) {
        try { 
            $Inbox.MoveTo($SkippedItem,$InboxSkipped,$MailClientCancelToken) | Out-Null
        } catch { 
            $_ 
        }
    }
}
# ================================================================================
# LOG ROTATION
# ================================================================================

# Log rotation script stolen from:
#      https://gallery.technet.microsoft.com/scriptcenter/PowerShell-Script-to-Roll-a96ec7d4

function Reset-Log { 
    #function checks to see if file in question is larger than the paramater specified if it is it will roll a log and delete the oldes log if there are more than x logs. 
    param(
        [string]$fileName, 
        [int64]$filesize = 1mb, 
        [int] $logcount = 5) 
     
    $logRollStatus = $true 
    if(test-path $filename) { 
        $file = Get-ChildItem $filename 
        #this starts the log roll 
        if((($file).length) -ige $filesize) { 
            $fileDir = $file.Directory 
            $fn = $file.name #this gets the name of the file we started with 
            $files = Get-ChildItem $filedir | ?{$_.name -like "$fn*"} | Sort-Object lastwritetime 
            $filefullname = $file.fullname #this gets the fullname of the file we started with 
            #$logcount +=1 #add one to the count as the base file is one more than the count 
            for ($i = ($files.count); $i -gt 0; $i--) {  
                #[int]$fileNumber = ($f).name.Trim($file.name) #gets the current number of the file we are on 
                $files = Get-ChildItem $filedir | ?{$_.name -like "$fn*"} | Sort-Object lastwritetime 
                $operatingFile = $files | ?{($_.name).trim($fn) -eq $i} 
                if ($operatingfile) {
                    $operatingFilenumber = ($files | ?{($_.name).trim($fn) -eq $i}).name.trim($fn)
                } else {
                    $operatingFilenumber = $null
                } 

                if (($operatingFilenumber -eq $null) -and ($i -ne 1) -and ($i -lt $logcount)) { 
                    $operatingFilenumber = $i 
                    $newfilename = "$filefullname.$operatingFilenumber" 
                    $operatingFile = $files | ?{($_.name).trim($fn) -eq ($i-1)} 
                    write-host "moving to $newfilename" 
                    move-item ($operatingFile.FullName) -Destination $newfilename -Force 
                } elseif($i -ge $logcount) { 
                    if($operatingFilenumber -eq $null) {  
                        $operatingFilenumber = $i - 1 
                        $operatingFile = $files | ?{($_.name).trim($fn) -eq $operatingFilenumber} 
                    } 
                    write-host "deleting " ($operatingFile.FullName) 
                    remove-item ($operatingFile.FullName) -Force 
                } elseif($i -eq 1) { 
                    $operatingFilenumber = 1 
                    $newfilename = "$filefullname.$operatingFilenumber" 
                    write-host "moving to $newfilename" 
                    move-item $filefullname -Destination $newfilename -Force 
                } else { 
                    $operatingFilenumber = $i +1  
                    $newfilename = "$filefullname.$operatingFilenumber" 
                    $operatingFile = $files | ?{($_.name).trim($fn) -eq ($i-1)} 
                    write-host "moving to $newfilename" 
                    move-item ($operatingFile.FullName) -Destination $newfilename -Force    
                } 
            }    
        } else { 
            $logRollStatus = $false
        }
    } else { 
        $logrollStatus = $false 
    }
    $LogRollStatus 
}

New-PIELogger -logSev "s" -Message "Begin Reset-Log block" -LogFile $runLog -PassThru
Reset-Log -fileName $phishLog -filesize 25mb -logcount 10
Reset-Log -fileName $runLog -filesize 50mb -logcount 10
New-PIELogger -logSev "s" -Message "End Reset-Log block" -LogFile $runLog -PassThru
New-PIELogger -logSev "i" -Message "Close mailbox connection" -LogFile $runLog -PassThru
# Kill Office365 Session and Clear Variables
$MailClient.Disconnect($true)
New-PIELogger -logSev "s" -Message "PIE Execution Completed" -LogFile $runLog -PassThru
return $EvaluationResults