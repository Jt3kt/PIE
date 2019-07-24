    365 SafeTracer
    Jtekt
    v1.0  --  July, 2019

Licensed under the MIT License. See LICENSE file in the project root for full license information.


## [About]
    
Enables direct query to Microsoft Advance Threat Protection UrlTrace cmdlet.  Through this use response 

URL click reports can be retrieved and populated into SIEM case reports.

This script is designed to integrated directly into the LogRhythm SIEM as a [SmartResponse](/SmartResponse).




## [Usage]

#### Run the following command for a list of options associated with this script:

    PS C:\> .\365_SafeTracer.ps1 -recipientlist "user1@example.com, user2@example.com"
		
		Initiates Office 365 search through ATP URLTrace for the list of internal e-mail addresses over a default time assessment period of 7 days.
	
	        
    PS C:\> .\365_SafeTracer.ps1 -urllist "http://example.com, https://example.com"
	
		Initiates Office 365 search through ATP URLTrace for the list of URLs over a default time assessment period of 7 days.  Any users who have accessed the URLs listed will be reported.
	
    PS C:\> .\365_SafeTracer.ps1 -urllist "http://example.com, https://example.com" -recipientlist "user1@example.com, user2@example.com, user3@example.com"
	
		Combines the two search functionalities into a single report.  
		
#### Inputs
	1) URL List.  Comma seperated list of URLs
	
	2 RecipientList.  Comma seperated list of e-mail addresses

	3) Username.  If being executed manually a prompt will be provided.

	4) Password.  If being executed manually a prompt will be provided.
	 
	Optional - Update LogRhythm Case
	a) id. - ID should be equal to the LogRhythm Case ID #.

	b) LogRhythm Case API key - The Actions.xml should be updated to include the LogRhythm Case API key
	
	c) LogRhythm Web Console URL - The Actions.xml should be updated to include the LogRhythm Web Console URL

		
## [Requirements]
	365 Exchange Permissions required:
		View-Only Recipients
		Message Tracking
