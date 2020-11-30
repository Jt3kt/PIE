using namespace System.Collections.Generic
  #====================================#
  # PIE - Phishing Intelligence Engine #
  # v3.7  --  December 2020            #
  #====================================#

# Copyright 2020 LogRhythm Inc.   
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
$PlainText = $false

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
$LogRhythmHost = "logrhythmhost.example.com"

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

# Set to true if internal e-mail addresses resolve to user@xxxx.onmicrosoft.com.  Typically true for test or lab 365 environments.
$onMicrosoft = $false

# PIE logging - Set to debug or info - output available under \logs\pierun.txt"
$pieLogLevel = "debug"
$pieLogVerbose = "True"


# ================================================================================
# Third Party Analytics
# ================================================================================

# For each supported module, set the flag to $true.
# Note these modules must be appropriately setup and configured as part of LogRhythm.Tools.
# For additional details on LogRhyhtm.Tools setup and configuration, visit: 
# https://github.com/LogRhythm-Tools/LogRhythm.Tools

# VirusTotal
$virusTotal = $false

# URL Scan
$urlscan = $false

# Shodan.io
$shodan = $false

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
$log = $true


# PIE Version
$PIEVersion = 3.7

# LogRhythm Tools Version
$LRTVersion = $(Get-Module -name logrhythm.tools | Select-Object -ExpandProperty Version) -join ","

New-PIELogger -logSev "s" -Message "BEGIN NEW PIE EXECUTION" -LogFile $runLog
# LogRhythm API Integration via LogRhyhtm.Tools
if (Get-Module -ListAvailable -Name logrhythm.tools) {
    Import-Module logrhythm.tools
    Start-Sleep 10
} else {
    New-PIELogger -logSev "e" -Message "PIE requires installation and setup of PowerShell module: LogRhythm.Tools" -LogFile $runLog
    New-PIELogger -logSev "e" -Message "Please visit https://github.com/LogRhythm-Tools/LogRhythm.Tools" -LogFile $runLog
    Return 0
}

# Microsoft Exchange Online Management
if (Get-Module -ListAvailable -Name ExchangeOnlineManagement) {
    Import-Module ExchangeOnlineManagement
    Start-Sleep 10
} else {
    New-PIELogger -logSev "e" -Message "PIE requires installation of PowerShell module: ExchangeOnlineManagement" -LogFile $runLog
    New-PIELogger -logSev "e" -Message "Open Administrator PowerShell session and run: Install-Module -Name ExchangeOnlineManagement" -LogFile $runLog
    Return 0
}
New-PIELogger -logSev "i" -Message "PIE Version: $PIEVersion" -LogFile $runLog
New-PIELogger -logSev "i" -Message "LogRhythm Tools Version: $LRTVersion" -LogFile $runLog

# Email Parsing Varibles
$boringFiles = @('jpg', 'png', 'ico', 'tif', 'gif')    
$boringFilesRegex = [string]::Join('|', $boringFiles)
$interestingFiles = @('pdf', 'exe', 'zip', 'doc', 'docx', 'docm', 'xls', 'xlsx', 'xlsm', 'ppt', 'pptx', 'arj', 'jar', '7zip', 'tar', 'gz', 'html', 'htm', 'js', 'rpm', 'bat', 'cmd')
$interestingFilesRegex = [string]::Join('|', $interestingFiles)

#Enable support for .eml format
#From https://gallery.technet.microsoft.com/office/Blukload-EML-files-to-e1b83f7f
Function Load-EmlFile {
    Param (
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
        } Catch {
        }
    }

    End{
        return $EML
    }
}

# ================================================================================
# Office 365 API Authentication
# ================================================================================

if ( $EncodedXMLCredentials ) {
    try {
        $Credential = Import-Clixml -Path $CredentialsFile
    } catch {
        Write-Error ("Could not find credentials file: " + $CredentialsFile)
        New-PIELogger -logSev "e" -Message "Could not find credentials file: $CredentialsFile" -LogFile $runLog
        Break;
    }
} else {
    if (-Not ($password) -And -Not ($Credential)) {
        $Credential = Get-Credential
    } Else {
        $securePass = ConvertTo-SecureString -string $password -AsPlainText -Force
        $Credential = New-Object -typename System.Management.Automation.PSCredential -argumentlist $username, $securePass
    }
}

try {
    Connect-ExchangeOnline -Credential $Credential
    New-PIELogger -logSev "s" -Message "Established Office 365 connection" -LogFile $runLog
} Catch {
    Write-Error "Access Denied..."
    New-PIELogger -logSev "e" -Message "Office 365 connection Access Denied" -LogFile $runLog
    Exit 1
    Break;
}


# ================================================================================
# MEAT OF THE PIE
# ================================================================================
New-PIELogger -logSev "i" -Message "Check for New Reports" -LogFile $runLog
if ( $log -eq $true) {
    if ( $autoAuditMailboxes -eq $true ) {
        New-PIELogger -logSev "s" -Message "Begin Inbox Audit Update" -LogFile $runLog
        # Check for mailboxes where auditing is not enabled and is limited to 1000 results
        $UnauditedMailboxes=(Get-Mailbox -Filter {AuditEnabled -eq $false}).Identity
        $UAMBCount=$UnauditedMailboxes.Count
        if ($UAMBCount -gt 0){
            Write-Host "Attempting to enable auditing on $UAMBCount mailboxes, please wait..." -ForegroundColor Cyan
            New-PIELogger -logSev "d" -Message "Attempting to enable auditing on $UAMBCount mailboxes" -LogFile $runLog
            $UnauditedMailboxes | ForEach-Object { 
                Try {
                    $auditRecipient = Get-Recipient $_
                    if ( $($auditRecipient.Count) ) {
                        for ($i = 0 ; $i -lt $auditRecipient.Count ; $i++) {
                            New-PIELogger -logSev "d" -Message "Setting audit policy for mailbox: $auditRecipient[$i]" -LogFile $runLog
                            Set-Mailbox -Identity $($auditRecipient[$i].guid.ToString()) -AuditLogAgeLimit 90 -AuditEnabled $true -AuditAdmin UpdateCalendarDelegation,UpdateFolderPermissions,UpdateInboxRules,Update,Move,MoveToDeletedItems,SoftDelete,HardDelete,FolderBind,SendAs,SendOnBehalf,Create,Copy,MessageBind -AuditDelegate UpdateFolderPermissions,UpdateInboxRules,Update,Move,MoveToDeletedItems,SoftDelete,HardDelete,FolderBind,SendAs,SendOnBehalf,Create -AuditOwner UpdateCalendarDelegation,UpdateFolderPermissions,UpdateInboxRules,Update,MoveToDeletedItems,Move,SoftDelete,HardDelete,Create,MailboxLogin
                        }
                    } else {
                        New-PIELogger -logSev "d" -Message "Setting audit policy for mailbox: $auditRecipient" -LogFile $runLog
                        Set-Mailbox -Identity $($auditRecipient.guid.ToString()) -AuditLogAgeLimit 90 -AuditEnabled $true -AuditAdmin UpdateCalendarDelegation,UpdateFolderPermissions,UpdateInboxRules,Update,Move,MoveToDeletedItems,SoftDelete,HardDelete,FolderBind,SendAs,SendOnBehalf,Create,Copy,MessageBind -AuditDelegate UpdateFolderPermissions,UpdateInboxRules,Update,Move,MoveToDeletedItems,SoftDelete,HardDelete,FolderBind,SendAs,SendOnBehalf,Create -AuditOwner UpdateCalendarDelegation,UpdateFolderPermissions,UpdateInboxRules,Update,MoveToDeletedItems,Move,SoftDelete,HardDelete,Create,MailboxLogin
                    }

                } Catch {
                    #Catch handles conflicts where multiple users share the same firstname, lastname.
                    Write-Host "Issue: $($PSItem.ToString())"
                    New-PIELogger -logSev "e" -Message "Set-Mailbox: $($PSItem.ToString())" -LogFile $runLog
                }

            }
            New-PIELogger -logSev "i" -Message "Finished attempting to enable auditing on $UAMBCount mailboxes" -LogFile $runLog
            Write-Host "Finished attempting to enable auditing on $UAMBCount mailboxes." -ForegroundColor Yellow
        }
        if ($UAMBCount -eq 0){} # Do nothing, all mailboxes have auditing enabled.
        New-PIELogger -logSev "s" -Message "End Inbox Audit Update" -LogFile $runLog
    }

    #Create phishLog if file does not exist.
    if ( $(Test-Path $phishLog -PathType Leaf) -eq $false ) {
        Set-Content $phishLog -Value "MessageTraceId,Received,SenderAddress,RecipientAddress,FromIP,ToIP,Subject,Status,Size,MessageId"
        New-PIELogger -logSev "a" -Message "No phishlog detected.  Created new $phishLog"
    }

    # Search for Reported Phishing Messages
    Try {
        New-PIELogger -logSev "i" -Message "Loading previous reports to phishHistory" -LogFile $runLog
        $phishHistory = Get-Content $phishLog | ConvertFrom-Csv -Header "MessageTraceID","Received","SenderAddress","RecipientAddress","FromIP","ToIP","Subject","Status","Size","MessageID"
    } Catch {
        New-PIELogger -logSev "e" -Message "Unable to read file: $phishLog" -LogFile $runLog
        New-PIELogger -logSev "s" -Message "PIE Execution Halting" -LogFile $runLog
        Disconnect-ExchangeOnline -Confirm:$false
        exit 1
    }

    Try {
        New-PIELogger -logSev "i" -Message "Loading current reports to phishTrace" -LogFile $runLog
        $phishTrace = Get-MessageTrace -RecipientAddress $socMailbox -Status Delivered | Select-Object MessageTraceID,Received,SenderAddress,RecipientAddress,FromIP,ToIP,Subject,Status,Size,MessageID | Sort-Object Received
    } Catch {
        New-PIELogger -logSev "e" -Message "Unable to retrieve phishTrace from o365" -LogFile $runLog
        New-PIELogger -logSev "s" -Message "PIE Execution Halting" -LogFile $runLog
        Disconnect-ExchangeOnline -Confirm:$false
        exit 1
    }
    try {
        New-PIELogger -logSev "i" -Message "Writing phishTrace to $tmpLog" -LogFile $runLog
        $phishTrace | Export-Csv $tmpLog -NoTypeInformation
    } Catch {
        New-PIELogger -logSev "e" -Message "Unable to write file: $tmpLog" -LogFile $runLog
        New-PIELogger -logSev "s" -Message "PIE Execution Halting" -LogFile $runLog
        Disconnect-ExchangeOnline -Confirm:$false
        exit 1
    }
    
    Try {
        New-PIELogger -logSev "i" -Message "Loading phishNewReports" -LogFile $runLog
        $phishNewReports = Get-Content $tmpLog | ConvertFrom-Csv -Header "MessageTraceID","Received","SenderAddress","RecipientAddress","FromIP","ToIP","Subject","Status","Size","MessageID"
    } Catch {
        New-PIELogger -logSev "e" -Message "Unable to read to: $tmpLog" -LogFile $runLog
        New-PIELogger -logSev "s" -Message "PIE Execution Halting" -LogFile $runLog
        Disconnect-ExchangeOnline -Confirm:$false
        exit 1
    }

    if ((get-item $tmpLog).Length -gt 0) {
        New-PIELogger -logSev "i" -Message "Populating newReports" -LogFile $runLog
        $newReports = Compare-Object $phishHistory $phishNewReports -Property MessageTraceID -PassThru -IncludeEqual | Where-Object {$_.SideIndicator -eq '=>' } | Select-Object MessageTraceID,Received,SenderAddress,RecipientAddress,FromIP,ToIP,Subject,Status,Size,MessageID
        New-PIELogger -logSev "d" -Message "NewReports Count: $($newReports.count)" -LogFile $runLog
    } 

    if ($null -eq $newReports) {
        New-PIELogger -logSev "i" -Message "No new reports detected" -LogFile $runLog
    } else {
        New-PIELogger -logSev "i" -Message "Connecting to local inbox" -LogFile $runLog
        # Connect to local inbox #and check for new mail
        $outlookInbox = 6
        $outlook = new-object -com outlook.application
        $ns = $outlook.GetNameSpace("MAPI")
        $olSaveType = "Microsoft.Office.Interop.Outlook.OlSaveAsType" -as [type]
        $rootFolders = $ns.Folders | ?{$_.Name -match $socMailbox}
        $inbox = $ns.GetDefaultFolder($outlookInbox)
        $inboxConfigCheck = $inbox.Folders.Count
        New-PIELogger -logSev "i" -Message "Outlook Inbox Folder Count: $inboxConfigCheck" -LogFile $runLog
        if ($inboxConfigCheck -ge 2 ) {
            New-PIELogger -logSev "d" -Message "Outlook Connection Test check successful" -LogFile $runLog
        } else {
            New-PIELogger -logSev "e" -Message "Outlook Connection Test check failed.  Validate Outlook inbox established and verify permissions" -LogFile $runLog
            New-PIELogger -logSev "s" -Message "PIE Execution Halting" -LogFile $runLog
            exit 1
        }
        New-PIELogger -logSev "i" -Message "Connecting to local inbox complete" -LogFile $runLog
        
        New-PIELogger -logSev "s" -Message "Begin processing newReports" -LogFile $runLog
        # Establish object for containing multiple completed reports
        $Reports = [list[object]]::new()
        :newReport ForEach ($NewReport in $NewReports) {
            $StartTime = (get-date).ToUniversalTime()

            # Establish Submission PSObject
            $Attachments = [list[object]]::new()

            # Add data for evaluated email
            $ReportEvidence = [PSCustomObject]@{
                Meta = [PSCustomObject]@{ 
                    GUID = $(New-Guid | Select-Object -ExpandProperty Guid)
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
                    Sender = $($NewReport.SenderAddress)
                    Recipient = $($NewReport.RecipientAddress)
                    Subject = [PSCustomObject]@{
                        Original = $($NewReport.Subject)
                        Modified = $null
                    }
                    Date = $($NewReport.Received)
                    MessageTraceId = $($NewReport.MessageTraceId)
                    Attachment = [PSCustomObject]@{
                        Name = $null
                        Type = $null
                        Hash = $null
                    }
                }
                EvaluationResults = [PSCustomObject]@{
                    ParsedFromFormat = $null
                    Sender = $null
                    SenderDisplayName = $null
                    Recipient = [PSCustomObject]@{
                        To = $null
                        CC = $null
                    }
                    Date = [PSCustomObject]@{
                        SentOn = $null
                        ReceivedOn = $null
                    }
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
                    Attachments = $Attachments
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
            New-PIELogger -logSev "i" -Message "Sent By: $($ReportEvidence.ReportSubmission.Sender)  Reported Subject: $($ReportEvidence.ReportSubmission.Subject.Original)" -LogFile $runLog
            #Access local inbox and check for new mail
            $OutlookMessages = $inbox.items
            $phishCount = $OutlookMessages.count

            New-PIELogger -logSev "s" -Message "Begin Phishing Analysis block" -LogFile $runLog
            New-PIELogger -logSev "d" -Message "Outlook Inbox Message Count: $phishCount" -LogFile $runLog
            # Analyze reported phishing messages, and scrape any other unreported messages    
            if ( $phishCount -gt 0 ) {
                # Extract reported messages
                New-PIELogger -logSev "i" -Message "Parse Outlook messages" -LogFile $runLog
                foreach($message in $OutlookMessages){
                    New-PIELogger -logSev "d" -Message "Outlook Message Subject: $($message.Subject)" -LogFile $runLog                   
                    
                    #Match known translation issues
                    New-PIELogger -logSev "i" -Message "Filtering known bad characters in `$message.Subject: $($message.Subject)" -LogFile $runLog
                        
                    #Created regex to identify any and all odd characters in subject and replace with ?
                    $specialPattern = "[^\u0000-\u007F]"
                    if ($($message.Subject) -Match "$specialPattern") { 
                        $ReportEvidence.ReportSubmission.Subject.Modified = $($message.Subject -Replace "$specialPattern","?")
                        New-PIELogger -logSev "i" -Message "Invalid characters identified, cleaning non-ASCII characters." -LogFile $runLog
                        New-PIELogger -logSev "d" -Message "Before filter: $($message.Subject)" -LogFile $runLog
                        New-PIELogger -logSev "d" -Message "After filter: $($ReportEvidence.ReportSubmission.Subject.Modified)" -LogFile $runLog
                        
                    }
                    New-PIELogger -logSev "i" -Message "Reported Subject: $($ReportEvidence.ReportSubmission.Subject.Original)" -LogFile $runLog
                    New-PIELogger -logSev "i" -Message "Post filter Outlook Message Original Subject: $($message.subject)" -LogFile $runLog
                    if ($($ReportEvidence.ReportSubmission.Subject.Modified)) {
                        New-PIELogger -logSev "i" -Message "Post filter Outlook Message Modified Subject: $($ReportEvidence.ReportSubmission.Subject.Modified)" -LogFile $runLog
                    }
                    

                    if ($($message.Subject) -eq $($ReportEvidence.ReportSubmission.Subject.Original) -OR $($ReportEvidence.ReportSubmission.Subject.Modified) -eq $($ReportEvidence.ReportSubmission.Subject.Original)) {
                        New-PIELogger -logSev "i" -Message "Outlook message.subject matched reported message Subject" -LogFile $runLog
                        #Add $newReport to $phishLog
                        New-PIELogger -logSev "i" -Message "Adding new report to phishLog for recipient $($NewReport.RecipientAddress)" -LogFile $runLog
                        Try {
                            echo "`"$($NewReport.MessageTraceID)`",`"$($NewReport.Received)`",`"$($NewReport.SenderAddress)`",`"$($NewReport.RecipientAddress)`",`"$($NewReport.FromIP)`",`"$($NewReport.ToIP)`",`"$($NewReport.Subject)`",`"$($NewReport.Status)`",`"$($NewReport.Size)`",`"$($NewReport.MessageID)`"" | Out-File $phishLog -Encoding utf8 -Append
                        } Catch {
                            New-PIELogger -logSev "e" -Message "Unable to write to: $phishLog" -LogFile $runLog
                            New-PIELogger -logSev "s" -Message "PIE Execution Halting" -LogFile $runLog
                            Disconnect-ExchangeOnline -Confirm:$false
                            exit 1
                        }
                        New-PIELogger -logSev "s" -Message "Parsing attachments" -LogFile $runLog
                        $message.attachments | ForEach-Object {
                            New-PIELogger -logSev "i" -Message "File $($_.filename)" -LogFile $runLog
                            $FileName = $_.filename
                            $attachmentFull = $tmpFolder+$FileName
                            $saveStatus = $null
                            If ($FileName -like "*.msg" -or $FileName -like "*.eml") {
                                $ReportEvidence.ReportSubmission.Attachment.Name = $FileName
                                $ReportEvidence.ReportSubmission.Attachment.Type = [System.IO.Path]::GetExtension($FileName).replace(".","")
                                
                                Try {
                                    $_.SaveAsFile($attachmentFull)
                                    New-PIELogger -logSev "i" -Message "Saving file: $attachmentFull" -LogFile $runLog
                                    $ReportEvidence.ReportSubmission.Attachment.Hash = @(Get-FileHash -Path $attachmentFull -Algorithm SHA256)
                                } Catch {
                                    New-PIELogger -logSev "e" -Message "Unable to write file: $attachmentFull" -LogFile $runLog
                                }
                            }
                        }
                        New-PIELogger -logSev "s" -Message "End Parsing attachments" -LogFile $runLog
                        New-PIELogger -logSev "i" -Message "Moving Outlook message to COMPLETED folder" -LogFile $runLog
                        $MoveTarget = $inbox.Folders.item("COMPLETED")
                        [void]$message.Move($MoveTarget)
                    }
                }

                New-PIELogger -logSev "i" -Message "Setting directoryInfo" -LogFile $runLog
                $directoryInfo = Get-ChildItem $tmpFolder | findstr "\.msg \.eml" | Measure-Object
                
                New-PIELogger -logSev "i" -Message "If .msg or .eml observed proceed" -LogFile $runLog
                if ( $directoryInfo.count -gt 0 ) {
                    $reportedMsgAttachments = @(@(Get-ChildItem $tmpFolder).Name)

                    if ( ($reportedMsgAttachments -like "*.msg*") )  {
                        New-PIELogger -logSev "s" -Message "Processing .msg e-mail format" -LogFile $runLog
                        # Set ReportEvidence ParsedFromFormat
                        $ReportEvidence.EvaluationResults.ParsedFromFormat = "msg"

                        foreach($attachment in $reportedMsgAttachments) {
                            New-PIELogger -logSev "d" -Message "Processing reported e-mail attachments: $tmpFolder$attachment" -LogFile $runLog
                            New-PIELogger -logSev "i" -Message "Loading submitted .msg e-mail" -LogFile $runLog
                            $msg = $outlook.Session.OpenSharedItem("$tmpFolder$attachment")
                                
                            $subject = $msg.ConversationTopic
                            New-PIELogger -logSev "d" -Message "Message subject: $subject" -LogFile $runLog
                            $ReportEvidence.EvaluationResults.Subject.Original = $msg.ConversationTopic

                            if ($($ReportEvidence.EvaluationResults.Subject.Original) -Match "$specialPattern") { 
                                $ReportEvidence.EvaluationResults.Subject.Modified = $ReportEvidence.EvaluationResults.Subject.Original -Replace "$specialPattern","?"
                            }

                            $ReportEvidence.EvaluationResults.Body.Original = $msg.Body

                            if ($($ReportEvidence.Body.Original) -Match "$specialPattern") {
                                New-PIELogger -logSev "i" -Message "Creating Message Body without Special Characters to support Case Note." -LogFile $runLog
                                $ReportEvidence.EvaluationResults.Body.Modified = $ReportEvidence.Body.Original -Replace "$specialPattern","?"
                            }
                            New-PIELogger -logSev "d" -Message "Processing Headers" -LogFile $runLog
                            $ReportEvidence.EvaluationResults.Headers = $msg.PropertyAccessor.GetProperty("http://schemas.microsoft.com/mapi/proptag/0x007D001E")
                            
                            
                            New-PIELogger -logSev "s" -Message "Begin Parsing URLs" -LogFile $runLog
                                
                            #Check if HTML Body exists else populate links from Text Body
                            New-PIELogger -logSev "i" -Message "Identifying URLs" -LogFile $runLog
                            if ( $($msg.HTMLBody.Length -gt 0) ) {
                                New-PIELogger -logSev "d" -Message "Processing URLs from HTML body" -LogFile $runLog
                                $ReportEvidence.EvaluationResults.HTMLBody.Original = $msg.HTMLBody.ToString()
                                $ReportEvidence.EvaluationResults.Links.Source = "HTML"
                                $ReportEvidence.EvaluationResults.Links.Value = Get-PIEURLsFromHTML -HTMLSource $ReportEvidence.EvaluationResults.HTMLBody.Original

                                # Create copy of HTMLBody with special characters removed.
                                if ($($ReportEvidence.EvaluationResults.HTMLBody.Original) -Match "$specialPattern") { 
                                    New-PIELogger -logSev "i" -Message "Creating HTMLBody without Special Characters to support Case Note." -LogFile $runLog
                                    $ReportEvidence.EvaluationResults.HTMLBody.Modified = $ReportEvidence.EvaluationResults.HTMLBody.Original -Replace "$specialPattern","?"
                                }
                            } 
                            else {
                                New-PIELogger -logSev "a" -Message "Processing URLs from Message body - Last Effort Approach" -LogFile $runLog
                                $ReportEvidence.EvaluationResults.Links.Source = "Text"
                                $ReportEvidence.EvaluationResults.Links.Value = Get-PIEURLsFromText -HTMLSource $ReportEvidence.EvaluationResults.Body.Original
                            }

                                
                            New-PIELogger -logSev "s" -Message "Begin .msg attachment block" -LogFile $runLog
                            $attachmentCount = $msg.Attachments.Count
                            New-PIELogger -logSev "i" -Message "Attachment Count: $attachmentCount" -LogFile $runLog
                            if ( $attachmentCount -gt 0 ) {
                                # Validate path tmpFolder\attachments exists
                                if (Test-Path "$tmpFolder\attachments" -PathType Container) {
                                    New-PIELogger -logSev "i" -Message "Folder $tmpFolder\attatchments\ exists" -LogFile $runLog
                                } else {
                                    New-PIELogger -logSev "i" -Message "Creating folder: $tmpFolder\attatchments\" -LogFile $runLog
                                    Try {
                                        New-Item -Path "$tmpFolder\attachments" -type Directory -Force | Out-Null
                                    } Catch {
                                        New-PIELogger -logSev "e" -Message "Unable to create folder: $tmpFolder\attatchments\" -LogFile $runLog
                                    }
                                }
                                # Get the filename and location
                                $attachedFileName = @(@($msg.Attachments | Select-Object Filename | findstr -v "FileName -") -replace "`n|`r").Trim() -replace '\s',''
                                New-PIELogger -logSev "i" -Message "Attached File Name: $attachedFileName" -LogFile $runLog
                                $msg.attachments | ForEach-Object {
                                    $attachmentName = $_.filename
                                    $attachmentFull = $tmpFolder + "attachments\" + $attachmentName
                                    New-PIELogger -logSev "i" -Message "Attachment Name: $attachmentName" -LogFile $runLog
                                    New-PIELogger -logSev "d" -Message "Checking attachment against interestingFilesRegex" -LogFile $runLog
                                    $saveStatus = $null
                                    If ($attachmentName -match $interestingFilesRegex) {
                                        Try {
                                            New-PIELogger -logSev "i" -Message "Saving Attachment to destination: $tmpFolder\attachments\$attachmentName" -LogFile $runLog
                                            $_.saveasfile($attachmentFull)
                                            $Attachment = [PSCustomObject]@{
                                                Name = $_.filename
                                                Type = [System.IO.Path]::GetExtension($_).replace(".","")
                                                Hash = @(Get-FileHash -Path $attachmentFull -Algorithm SHA256)
                                                Plugins = [pscustomobject]@{
                                                    VirusTotal = $null
                                                }
                                            }
                                            # Add Attachment object to Attachments list
                                            if ($Attachments -notcontains $attachment) {
                                                $Attachments.Add($Attachment)
                                            }
                                        } Catch {
                                            New-PIELogger -logSev "e" -Message "Unable to save Attachment to destination: $tmpFolder\attachments\$attachmentName" -LogFile $runLog
                                        }
                                    }
                                }
                            }

                            # Clean Up the SPAM
                            New-PIELogger -logSev "d" -Message "Moving e-mail message to SPAM folder" -LogFile $runLog
                            $MoveTarget = $inbox.Folders.item("SPAM")
                            [void]$msg.Move($MoveTarget)
                            $spammer = $msg.SenderEmailAddress
                            $ReportEvidence.EvaluationResults.Sender = $msg.SenderEmailAddress

                            New-PIELogger -logSev "i" -Message "Spammer set to: $spammer" -LogFile $runLog
                            $spammerDisplayName = $msg.SenderName
                            $ReportEvidence.EvaluationResults.SenderDisplayName = $msg.SenderName
                            New-PIELogger -logSev "i" -Message "Spammer Display Name set to: $spammerDisplayName" -LogFile $runLog
                        }
                    } elseif ( ($reportedMsgAttachments -like "*.eml*") )  {
                        New-PIELogger -logSev "s" -Message "Processing .eml e-mail format" -LogFile $runLog
                        # Set ReportEvidence ParsedFromFormat
                        $ReportEvidence.EvaluationResults.ParsedFromFormat = "eml"

                        $emlAttachment = $reportedMsgAttachments -like "*.eml*"
                        New-PIELogger -logSev "d" -Message "Processing reported e-mail attachments: $emlAttachment" -LogFile $runLog
                        New-PIELogger -logSev "i" -Message "Loading submitted .eml e-mail to variable msg" -LogFile $runLog
                        $Eml = Load-EmlFile("$tmpFolder$emlAttachment")


                        $ReportEvidence.EvaluationResults.Subject.Original = $Eml.Subject
                        if ($($ReportEvidence.EvaluationResults.Subject.Original) -Match "$specialPattern") {
                            New-PIELogger -logSev "i" -Message "Creating Message Subject without Special Characters to support Case Note." -LogFile $runLog
                            $ReportEvidence.EvaluationResults.Subject.Modified = $ReportEvidence.EvaluationResults.Subject.Original -Replace "$specialPattern","?"
                        }
                        $subject = $Eml.Subject
                        New-PIELogger -logSev "d" -Message "Message subject: $($ReportEvidence.EvaluationResults.Subject)" -LogFile $runLog

                        
                        #Plain text Message Body
                        $ReportEvidence.EvaluationResults.Body.Original = $Eml.BodyPart.Fields | Select-Object Name, Value | Where-Object name -EQ "urn:schemas:httpmail:textdescription" | Select-Object -ExpandProperty Value
                        
                        if ($($ReportEvidence.EvaluationResults.Body.Original) -Match "$specialPattern") {
                            New-PIELogger -logSev "i" -Message "Creating Message Body without Special Characters to support Case Note." -LogFile $runLog
                            $ReportEvidence.EvaluationResults.Body.Modified = $ReportEvidence.EvaluationResults.Body.Original -Replace "$specialPattern","?"
                        }                     

                        #Headers
                        New-PIELogger -logSev "d" -Message "Processing Headers" -LogFile $runLog
                        $ReportEvidence.EvaluationResults.Headers = $Eml.BodyPart.Fields | Select-Object Name, Value | Where-Object name -Like "*header*"

                        New-PIELogger -logSev "d" -Message "Writing Headers: $tmpFolder\headers.txt" -LogFile $runLog
                        Try {
                            Write-Output $ReportEvidence.EvaluationResults.Headers > "$tmpFolder\headers.txt"
                        } Catch {
                            New-PIELogger -logSev "e" -Message "Unable to write Headers to path $tmpFolder\headers.txt" -LogFile $runLog
                        }

                        
                        New-PIELogger -logSev "s" -Message "Begin Parsing URLs" -LogFile $runLog                  
                        #Load links
                        #Check if HTML Body exists else populate links from Text Body
                        New-PIELogger -logSev "i" -Message "Identifying URLs" -LogFile $runLog
                        
                        if ( $($Eml.HTMLBody.Length -gt 0) ) {
                            # Set ReportEvidence HTMLBody Content
                            #HTML Message Body
                            $ReportEvidence.EvaluationResults.HTMLBody.Original = $Eml.HTMLBody.ToString()
                            # Pull URL data from HTMLBody Content
                            New-PIELogger -logSev "d" -Message "Processing URLs from message HTML body" -LogFile $runLog
                            $ReportEvidence.EvaluationResults.Links.Source = "HTML"
                            $ReportEvidence.EvaluationResults.Links.Value = Get-PIEURLsFromHTML -HTMLSource $($ReportEvidence.EvaluationResults.HTMLBody.Original)

                            # Create copy of HTMLBody with special characters removed.
                            if ($($ReportEvidence.EvaluationResults.HTMLBody.Original) -Match "$specialPattern") {
                                New-PIELogger -logSev "i" -Message "Creating HTMLBody without Special Characters to support Case Note." -LogFile $runLog
                                $ReportEvidence.EvaluationResults.HTMLBody.Modified = $ReportEvidence.EvaluationResults.HTMLBody.Original -Replace "$specialPattern","?"
                            }
                        } else {
                            New-PIELogger -logSev "a" -Message "Processing URLs from Text body - Last Effort Approach" -LogFile $runLog
                            $ReportEvidence.EvaluationResults.Links.Source = "Text"
                            $ReportEvidence.EvaluationResults.Links.Value = $(Get-PIEURLsFromText -Text $($ReportEvidence.EvaluationResults.Body.Original))
                        }
                        New-PIELogger -logSev "s" -Message "End Parsing URLs" -LogFile $runLog

                        New-PIELogger -logSev "s" -Message "Begin .eml attachment block" -LogFile $runLog
                        $attachmentCount = $Eml.Attachments.Count
                        New-PIELogger -logSev "i" -Message "Attachment Count: $attachmentCount" -LogFile $runLog

                        if ( $attachmentCount -gt 0 ) {
                            # Validate path tmpFolder\attachments exists
                            if (Test-Path "$tmpFolder\attachments" -PathType Container) {
                                New-PIELogger -logSev "i" -Message "Folder $tmpFolder\attatchments\ exists" -LogFile $runLog
                            } else {
                                New-PIELogger -logSev "i" -Message "Creating folder: $tmpFolder\attatchments\" -LogFile $runLog
                                Try {
                                    New-Item -Path "$tmpFolder\attachments" -type Directory -Force | Out-null
                                } Catch {
                                    New-PIELogger -logSev "e" -Message "Unable to create folder: $tmpFolder\attatchments\" -LogFile $runLog
                                }
                            }                
                            # Get the filename and location
                            $Eml.attachments | ForEach-Object {
                                $attachmentName = $_.filename
                                $attachmentFull = $tmpFolder+"attachments\"+$attachmentName
                                New-PIELogger -logSev "d" -Message "Attachment Name: $attachmentName" -LogFile $runLog
                                New-PIELogger -logSev "i" -Message "Checking attachment against interestingFilesRegex" -LogFile $runLog
                                $saveStatus = $null
                                If ($attachmentName -match $interestingFilesRegex) {
                                    New-PIELogger -logSev "d" -Message "Saving Attachment to destination: $tmpFolder\attachments\$attachmentName" -LogFile $runLog
                                    Try {
                                        $($_).SaveToFile($attachmentFull)

                                        $Attachment = [PSCustomObject]@{
                                            Name = $_.filename
                                            Type = [System.IO.Path]::GetExtension($_.filename).replace(".","")
                                            Hash = @(Get-FileHash -Path $attachmentFull -Algorithm SHA256)
                                            Plugins = [pscustomobject]@{
                                                VirusTotal = $null
                                            }
                                        }
                                        # Add Attachment object to Attachments list
                                        if ($Attachments -notcontains $attachment) {
                                            $Attachments.Add($Attachment)
                                        }
                                    } Catch {
                                        New-PIELogger -logSev "e" -Message "Unable to save Attachment to destination: $tmpFolder\attachments\$attachmentName" -LogFile $runLog
                                    }
                                }
                            }
                        }

                        $spammer = $Eml.From.Split("<").Split(">")[1]
                        $ReportEvidence.EvaluationResults.Sender = $Eml.From.Split("<").Split(">")[1]
                        New-PIELogger -logSev "i" -Message "Origin sender set to: $($ReportEvidence.EvaluationResults.Sender )" -LogFile $runLog
                        $ReportEvidence.EvaluationResults.SenderDisplayName = $Eml.From.Split("<").Split(">")[0].replace('"',"")
                        $spammerDisplayName = $Eml.From.Split("<").Split(">")[0]
                        $ReportEvidence.EvaluationResults.Recipient.To = $Eml.To
                        $ReportEvidence.EvaluationResults.Recipient.CC = $Eml.CC
                        $ReportEvidence.EvaluationResults.Date.SentOn = $Eml.SentOn
                        $ReportEvidence.EvaluationResults.Date.ReceivedOn = $Eml.ReceivedTime
                        New-PIELogger -logSev "i" -Message "Origin Sender Display Name set to: $($ReportEvidence.EvaluationResults.SenderDisplayName)" -LogFile $runLog
                    }
                } else {
                    # No PhishReport attachment, move e-mail to completed folder and move to next reported e-mail
                    New-PIELogger -logSev "s" -Message "Non .eml or .msg format" -LogFile $runLog
                    #$targetFolder = $searchMailboxResults.TargetFolder
                    $MoveTarget = $inbox.Folders.item("SPAM")
                    [void]$msg.Move($MoveTarget)
                    continue newReport
                }
            
                New-PIELogger -logSev "s" -Message "Begin Link Processing" -LogFile $runLog
                
                $EmailUrls = [list[string]]::new()
                $EmailDomains = [list[string]]::new()

                if ($ReportEvidence.EvaluationResults.Links.Value) {
                    $UrlDetails = [list[pscustomobject]]::new()
                    if ($ReportEvidence.EvaluationResults.Links.Source -like "HTML") {
                        New-PIELogger -logSev "i" -Message "Link processing from HTML Source" -LogFile $runLog
                        $EmailUrls = $($ReportEvidence.EvaluationResults.Links.Value | Where-Object -Property Type -like "Url")
                        $DomainGroups = $EmailUrls.hostname | group
                        $UniqueDomains = $DomainGroups.count
                        New-PIELogger -logSev "i" -Message "Links: $($EmailUrls.count) Domains: $UniqueDomains" -LogFile $runLog
                        ForEach ($UniqueDomain in $DomainGroups) {
                            $ScanTarget = $EmailUrls | Where-Object -Property hostname -like $UniqueDomain.Name | Select-Object -ExpandProperty Url
                            New-PIELogger -logSev "i" -Message "Domain: $($UniqueDomain.Name) Url: $ScanTarget" -LogFile $runLog
                            if ($UniqueDomain.count -gt 1) {
                                New-PIELogger -logSev "i" -Message "Retrieve Domain Details - Url: $ScanTarget" -LogFile $runLog
                                $DetailResults = Get-PIEUrlDetails -Url $ScanTarget -EnablePlugins -VTDomainScan
                            } else {
                                New-PIELogger -logSev "i" -Message "Retrieve URL Details - Url: $ScanTarget" -LogFile $runLog
                                $DetailResults = Get-PIEUrlDetails -Url $ScanTarget -EnablePlugins
                            }
                            if ($UrlDetails -NotContains $DetailResults) {
                                $UrlDetails.Add($DetailResults)
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
                    New-PIELogger -logSev "d" -Message "Writing list of unique domains to $tmpFolder`domains.txt" -LogFile $runLog
                    Try {
                        $($ReportEvidence.EvaluationResults.Links.Details.ScanTarget | Select-Object -ExpandProperty Domain -Unique) > "$tmpFolder`domains.txt"
                    } Catch {
                        New-PIELogger -logSev "e" -Message "Unable to write to file $tmpFolder`domains.txt" -LogFile $runLog
                    }

                    
                    New-PIELogger -logSev "d" -Message "Writing list of unique urls to $tmpFolder`links.txt" -LogFile $runLog
                    Try {
                        $($ReportEvidence.EvaluationResults.Links.Details.ScanTarget | Select-Object -ExpandProperty Url -Unique) > "$tmpFolder`domains.txt"
                    } Catch {
                        New-PIELogger -logSev "e" -Message "Unable to write to file $tmpFolder`links.txt" -LogFile $runLog
                    }
                    
                    
                    $CountLinks = $($ReportEvidence.EvaluationResults.Links.Details.ScanTarget | Select-Object -ExpandProperty Url -Unique | Measure-Object | Select-Object -ExpandProperty Count)
                    New-PIELogger -logSev "i" -Message "Total Unique Links: $countLinks" -LogFile $runLog

                    $CountDomains = $($ReportEvidence.EvaluationResults.Links.Details.ScanTarget | Select-Object -ExpandProperty Domain -Unique | Measure-Object | Select-Object -ExpandProperty Count)
                    New-PIELogger -logSev "i" -Message "Total Unique Domains: $countDomains" -LogFile $runLog
                }
                New-PIELogger -logSev "s" -Message "End Link Processing" -LogFile $runLog

                New-PIELogger -logSev "s" -Message "Begin Attachment Processing" -LogFile $runLog
                ForEach ($Attachment in $ReportEvidence.EvaluationResults.Attachments) {
                    New-PIELogger -logSev "i" -Message "Attachment: $($Attachment.Name)" -LogFile $runLog
                    if ($LrtConfig.VirusTotal.ApiKey) {
                        New-PIELogger -logSev "i" -Message "VirusTotal - Submitting Hash: $($Attachment.Hash.Hash)" -LogFile $runLog
                        $VTResults = Get-VtHashReport -Hash $Attachment.Hash.Hash
                        # Response Code 0 = Result not in dataset
                        if ($VTResults.response_code -eq 0) {
                            New-PIELogger -logSev "i" -Message "VirusTotal - Result not in dataset." -LogFile $runLog
                            $VTResponse = [PSCustomObject]@{
                                Status = $true
                                Note = $VTResults.verbose_msg
                                Results = $VTResults
                            }
                            $Attachment.Plugins.VirusTotal = $VTResponse
                        } elseif ($VTResults.response_code -eq 1) {
                            # Response Code 1 = Result in dataset
                            New-PIELogger -logSev "i" -Message "VirusTotal - Result in dataset." -LogFile $runLog
                            $VTResponse = [PSCustomObject]@{
                                Status = $true
                                Note = $VTResults.verbose_msg
                                Results = $VTResults
                            }
                            $Attachment.Plugins.VirusTotal = $VTResults
                        } else {
                            New-PIELogger -logSev "i" -Message "VirusTotal - Request failed." -LogFile $runLog
                            $VTResponse = [PSCustomObject]@{
                                Status = $false
                                Note = "Requested failed."
                                Results = $VTResults
                            }
                            $Attachment.Plugins.VirusTotal = $VTResponse
                        }
                    }
                }
                New-PIELogger -logSev "s" -Message "End Attachment Processing" -LogFile $runLog
                # Create a case folder
                New-PIELogger -logSev "s" -Message "Creating Evidence Folder" -LogFile $runLog
                # - Another shot
                $caseID = Get-Date -Format M-d-yyyy_h-m-s
                if ( $spammer.Contains("@") -eq $true) {
                    $spammerName = $spammer.Split("@")[0]
                    $spammerDomain = $spammer.Split("@")[1]
                    New-PIELogger -logSev "d" -Message "Spammer Name: $spammerName Spammer Domain: $spammerDomain" -LogFile $runLog
                    $caseID = Write-Output $caseID"_Sender_"$spammerName".at."$spammerDomain
                } else {
                    New-PIELogger -logSev "d" -Message "Case created as Fwd Message source" -LogFile $runLog
                    $caseID = Write-Output $caseID"_Sent-as-Fwd"
                }
                try {
                    New-PIELogger -logSev "i" -Message "Creating Directory: $caseFolder$caseID" -LogFile $runLog
                    mkdir $caseFolder$caseID | out-null
                } Catch {
                    New-PIELogger -logSev "e" -Message "Unable to create directory: $caseFolder$caseID" -LogFile $runLog
                }
                # Support adding Network Share Location to the Case
                $hostname = hostname
                $networkShare = "\\$hostname\PIE\cases\$caseID\"

                # Check for Attachments
                if ($attachmentCount -gt 0) {
                    Try {
                        mkdir "$caseFolder$caseID\attachments\" | out-null
                    } Catch {
                        New-PIELogger -logSev "e" -Message "Unable to create directory: $caseFolder$caseID\attachments\" -LogFile $runLog
                    }
                
                    New-PIELogger -logSev "i" -Message "Moving interesting files to case folder" -LogFile $runLog
                    # Make sure those files are moved
                    Copy-Item "$tmpFolder\attachments\*" "$caseFolder$caseID\attachments\" | Out-Null
                }



                # Gather and count evidence
                New-PIELogger -logSev "s" -Message "Begin gather and count evidence block" -LogFile $runLog
                if ( $spammer.Contains("@") -eq $true) {
                    Start-Sleep 5
                    New-PIELogger -logSev "i" -Message "365 - Collecting interesting messages" -LogFile $runLog
                    Get-MessageTrace -SenderAddress $spammer -StartDate $96Hours -EndDate $date | Select-Object MessageTraceID,Received,*Address,*IP,Subject,Status,Size,MessageID | Export-Csv $analysisLog -NoTypeInformation
                }

                #Update here to remove onmicrosoft.com addresses for recipients
                New-PIELogger -logSev "d" -Message "365 - Determining Recipients" -LogFile $runLog
                $recipients = Get-Content $analysisLog | ForEach-Object { $_.split(",")[3] }
                $recipients = $recipients -replace '"', "" | Sort-Object | Get-Unique | findstr -v "RecipientAddress"
                if ( $onMicrosoft -eq $true ) {
                    New-PIELogger -logSev "d" -Message "365 - Permitting onMicrosoft addresses" -LogFile $runLog
                    $messageCount = Get-Content $analysisLog | findstr -v "MessageTraceId" | Measure-Object | Select-Object Count | findstr -v "Count -"
                    $deliveredMessageCount = Get-Content $analysisLog | findstr "Delivered Resolved" | Measure-Object | Select-Object Count | findstr -v "Count -"
                    $failedMessageCount = Get-Content $analysisLog | findstr "Failed" | Measure-Object | Select-Object Count | findstr -v "Count -"
                } else {
                    New-PIELogger -logSev "d" -Message "365 - Filtering out onMicrosoft addresses onMicrosoft addresses" -LogFile $runLog
                    $messageCount = Get-Content $analysisLog | Where-Object {$_ -notmatch 'onmicrosoft.com'} | findstr -v "MessageTraceId" | Measure-Object | Select-Object Count | findstr -v "Count -"
                    $deliveredMessageCount = Get-Content $analysisLog | Where-Object {$_ -notmatch 'onmicrosoft.com'} | findstr "Delivered Resolved" | Measure-Object | Select-Object Count | findstr -v "Count -"
                    $failedMessageCount = Get-Content $analysisLog | Where-Object {$_ -notmatch 'onmicrosoft.com'} | findstr "Failed" | Measure-Object | Select-Object Count | findstr -v "Count -"
                    $recipients = $recipients | Where-Object {$_ -notmatch 'onmicrosoft.com'}
                }

                $messageCount = $messageCount.Trim()
                $deliveredMessageCount = $deliveredMessageCount.Trim()
                $failedMessageCount = $failedMessageCount.Trim()
                New-PIELogger -logSev "d" -Message "365 - Message Count: $messageCount Delivered: $deliveredMessageCount Failed: $failedMessageCount" -LogFile $runLog
                $subjects = Get-Content $analysisLog | ForEach-Object { $_.split(",")[6] } | Sort-Object | Get-Unique | findstr -v "Subject"
                New-PIELogger -logSev "d" -Message "365 - Subject Count: $($subjects.Count)" -LogFile $runLog


                Try {
                    Get-Content $analysisLog >> "$caseFolder$caseID\message-trace-logs.csv"
                } Catch {
                    New-PIELogger -logSev "e" -Message "Error writing analysisLog to $caseFolder$caseID\message-trace-logs.csv" -LogFile $runLog
                }
                
                Try {
                    Remove-Item "$tmpFolder\*" -Force -Recurse | Out-Null
                } Catch {
                    New-PIELogger -logSev "e" -Message "Unable to purge contents from $tmpFolder" -LogFile $runLog
                }  


                New-PIELogger -logSev "s" -Message "LogRhythm API - Create Case" -LogFile $runLog
                if ( $spammer.Contains("@") -eq $true) {
                    New-PIELogger -logSev "d" -Message "LogRhythm API - Create Case with Sender Info" -LogFile $runLog
                    $caseSummary = "Phishing email from $spammer was reported on $date by $($ReportEvidence.ReportSubmission.Sender). The subject of the email is ($subject). Initial analysis shows that $messageCount user(s) received this email in the past 96 hours."
                    $CaseDetails = New-LrCase -Name "Phishing : $spammerName [at] $spammerDomain" -Priority 3 -Summary $caseSummary -PassThru
                } else {
                    New-PIELogger -logSev "d" -Message "LogRhythm API - Create Case without Sender Info" -LogFile $runLog
                    $caseSummary = "Phishing email was reported on $date by $($ReportEvidence.ReportSubmission.Sender). The subject of the email is ($subject). Initial analysis shows that $messageCount user(s) received this email in the past 96 hours."
                    $CaseDetails = New-LrCase -Name "Phishing Message Reported" -Priority 3 -Summary $caseSummary -PassThru
                 
                }
                Start-Sleep .2

                # Set ReportEvidence CaseNumber
                $ReportEvidence.LogRhythmCase.Number = $CaseDetails.number

                Try {
                    $ReportEvidence.LogRhythmCase.Number | Out-File "$caseFolder$caseID\case.txt"
                } Catch {
                    New-PIELogger -logSev "e" -Message "Unable to move $pieFolder\plugins\case.txt to $caseFolder$caseID\" -LogFile $runLog
                }
                
                # Establish Case URL to ReportEvidence Object
                $ReportEvidence.LogRhythmCase.Url = "https://$LogRhythmHost/cases/$($ReportEvidence.LogRhythmCase.Number)"
                New-PIELogger -logSev "i" -Message "Case URL: $($ReportEvidence.LogRhythmCase.Url)" -LogFile $runLog

                # Update case Earliest Evidence
                if ($ReportEvidence.EvaluationResults.Date.ReceivedOn) {
                    # Based on recipient's e-mail message recieve timestamp from origin sender
                    Update-LrCaseEarliestEvidence -Id $($ReportEvidence.LogRhythmCase.Number) -Timestamp $ReportEvidence.EvaluationResults.Date.ReceivedOn
                } else {
                    # Based on report submission for evaluation
                    Update-LrCaseEarliestEvidence -Id $($ReportEvidence.LogRhythmCase.Number) -Timestamp $ReportEvidence.ReportSubmission.Date
                }
                
            
                # Tag the case as phishing
                New-PIELogger -logSev "i" -Message "LogRhythm API - Applying case tag" -LogFile $runLog
                if ( $defaultCaseTag ) {
                    $TagStatus = Get-LrTags -Name $defaultCaseTag -Exact
                    Start-Sleep 0.2
                    if (!$TagStatus) {
                         $TagStatus = New-LrTag -Name $defaultCaseTag -PassThru
                         Start-Sleep 0.2
                    }
                    if ($TagStatus) {
                         Add-LrCaseTags -Id $ReportEvidence.LogRhythmCase.Number -Tags $TagStatus.Number
                         New-PIELogger -logSev "i" -Message "LogRhythm API - Adding tag $defaultCaseTag Tag Number $($TagStatus.number)" -LogFile $runLog
                         Start-Sleep 0.2
                    }
                }

                # Adding and assigning other users
                New-PIELogger -logSev "i" -Message "LogRhythm API - Assigning case collaborators" -LogFile $runLog
                if ( $caseCollaborators ) {
                    Add-LrCaseCollaborators -Id $ReportEvidence.LogRhythmCase.Number -Names $caseCollaborators
                }
        

# ================================================================================
# Case Closeout
# ================================================================================
                
                New-PIELogger -logSev "s" -Message "Begin LogRhythm Playbook Block" -LogFile $runLog
                if ($casePlaybook) {
                    New-PIELogger -logSev "i" -Message "LogRhythm API - Adding Playbook:$casePlaybook to Case:$($ReportEvidence.LogRhythmCase.Number)" -LogFile $runLog
                    Add-LrCasePlaybook -Id $ReportEvidence.LogRhythmCase.Number -Playbook $casePlaybook
                } else {
                    New-PIELogger -logSev "i" -Message "LogRhythm API - Playbook Omision - Playbook not defined" -LogFile $runLog
                }
                New-PIELogger -logSev "s" -Message "End LogRhythm Playbook Block" -LogFile $runLog
                New-PIELogger -logSev "i" -Message "Spam-report Case closeout" -LogFile $runLog

                # Copy E-mail Message text body to case
                New-PIELogger -logSev "i" -Message "LogRhythm API - Copying e-mail body text to case" -LogFile $runLog
                if ( $ReportEvidence.EvaluationResults.Body.Original ) {
                    $DefangBody = $ReportEvidence.EvaluationResults.Body.Original.replace('http://','hxxp://')
                    $DefangBody = $DefangBody.replace('https://','hxxps://')
                    $NoteStatus = Add-LrNoteToCase -Id $ReportEvidence.LogRhythmCase.Number -Text "Reported Message Body:`r`n$DefangBody" -PassThru
                    if ($NoteStatus.Error) {
                        New-PIELogger -logSev "e" -Message "LogRhythm API - Unable to add ReportEvidence.EvaluationResults.Body to LogRhythm Case." -LogFile $runLog
                        New-PIELogger -logSev "d" -Message "LogRhythm API - Code: $($NoteStatus.Error.Code) Note: $($NoteStatus.Error.Note)" -LogFile $runLog
                    }
                }

                # Add Link plugin output to Case
                ForEach ($UrlDetails in $ReportEvidence.EvaluationResults.Links.Details) {
                    if ($shodan) {
                        if ($UrlDetails.Plugins.Shodan) {
                            Add-LrNoteToCase -id $ReportEvidence.LogRhythmCase.Number -Text $($UrlDetails.Plugins.Shodan | Format-ShodanTextOutput)
                        }
                    }
                    if ($urlscan) {
                        if ($UrlDetails.Plugins.urlscan) {
                            Add-LrNoteToCase -id $ReportEvidence.LogRhythmCase.Number -Text $($UrlDetails.Plugins.urlscan | Format-UrlscanTextOutput)
                        }
                    }
                    if ($virusTotal) {
                        if ($UrlDetails.Plugins.VirusTotal) {
                            Add-LrNoteToCase -id $ReportEvidence.LogRhythmCase.Number -Text $($UrlDetails.Plugins.VirusTotal | Format-VTTextOutput)
                        }
                    }
                }

                # Add Attachment plugin output to Case
                ForEach ($AttachmentDetails in $ReportEvidence.EvaluationResults.Attachments) {
                    if ($virusTotal) {
                        if ($AttachmentDetails.Plugins.VirusTotal.Status) {
                            Add-LrNoteToCase -id $ReportEvidence.LogRhythmCase.Number -Text $($AttachmentDetails.Plugins.VirusTotal.Results | Format-VTTextOutput)
                        }
                    }
                }

                # Add Link/Attachment Summary as second Case note
                $CaseEvidenceSummaryNote = Format-PIEEvidenceSummary -EvaluationResults $ReportEvidence.EvaluationResults
                Add-LrNoteToCase -Id $ReportEvidence.LogRhythmCase.Number -Text $CaseEvidenceSummaryNote

                # Conclude runtime metrics
                $EndTime = (get-date).ToUniversalTime()
                $ReportEvidence.Meta.Metrics.End = $EndTime.ToString("yyyy-MM-ddTHHmmssffZ")
                $Duration = New-Timespan -Start $StartTime -End $EndTime
                $ReportEvidence.Meta.Metrics.Duration = $Duration

                # Add overall summary as last, top most case note.
                $CaseSummaryNote = Format-PIECaseSummary -ReportEvidence $ReportEvidence
                Add-LrNoteToCase -Id $ReportEvidence.LogRhythmCase.Number -Text $CaseSummaryNote

                $ReportEvidence.LogRhythmCase.Details = Get-LrCaseById -Id $ReportEvidence.LogRhythmCase.Number

                $Reports.Add($ReportEvidence)

                # Write PIE Report Json object out to Case as Evidence
                $ReportEvidence | ConvertTo-Json -Depth 50 | Out-File -FilePath "$caseFolder$caseID\PIE_Report.json"
            }
            #Cleanup Variables prior to next evaluation
            New-PIELogger -logSev "s" -Message "Resetting analysis varaiables" -LogFile $runLog
            $spammer = $null
            $spammerDisplayName = $null
            $message = $null
            $msg = $null
            $subject = $null
            $subjects = $null
            $recipients = $null
            $messageCount = $null
            $deliveredMessageCount = $null
            $failedMessageCount = $null
            $attachmentCount = $null
            $attachmentFull = $null
            $attachment = $null
            $attachments = $null
            $directoryInfo = $null
            $caseID = $null
            $summary = $null
        }
        
        #Close Outlook
        New-PIELogger -logSev "s" -Message "Closing Outlook" -LogFile $runLog
        $processOutlook = Get-Process OUTLOOK
        if ($processOutlook) {
            New-PIELogger -logSev "i" -Message "Stopping Outlook PID:$($processOutlook.Id)" -LogFile $runLog
            Try {
                Stop-Process $processOutlook.Id -Force
            } Catch {
                New-PIELogger -logSev "e" -Message "Unable Stop-Process for Outlook PID:$($processOutlook.Id)" -LogFile $runLog
            }
        } else {
            New-PIELogger -logSev "i" -Message "Unable to identify Outlook PID.  Is Outlook running?" -LogFile $runLog
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

New-PIELogger -logSev "s" -Message "Begin Reset-Log block" -LogFile $runLog
Reset-Log -fileName $phishLog -filesize 25mb -logcount 10
Reset-Log -fileName $runLog -filesize 50mb -logcount 10
New-PIELogger -logSev "s" -Message "End Reset-Log block" -LogFile $runLog
New-PIELogger -logSev "i" -Message "Close Office 365 connection" -LogFile $runLog
# Kill Office365 Session and Clear Variables
Disconnect-ExchangeOnline -Confirm:$false
New-PIELogger -logSev "s" -Message "PIE Execution Completed" -LogFile $runLog
return $Reports