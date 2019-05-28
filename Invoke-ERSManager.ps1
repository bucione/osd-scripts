<#
.SYNOPSIS
Interfaces with Cisco ISE 2.2 External RESTful Service (ERS)
.DESCRIPTION
Manages Cisco ISE Whitelist resources
Author
    Arthur Bucione <arthur-octavio.bucione@dxc.com>

Version Information
    1.0 - Initial version
.PARAMETER ServerName
Name or IP Address of the ISE Server
.PARAMETER List
List the endpoints associated with the provided group
.PARAMETER Add
Add the endpoint to the provided group
.PARAMETER Remove
Remove the endpoint from ISE
.PARAMETER Description
Optional. Use the provided description when adding an endpoint resource
.PARAMETER GroupName
Name of the endpoint group associated with endpoint resources
.PARAMETER AuthToken
Optional. Basic authentication string to access ISE resources
.PARAMETER Credential
Optional. Credentials object to acess ISE resources
.PARAMETER HashAuth
Optional. Hashtable with UserName/Password credentials to access ISE resources
.PARAMETER MacAddress
Optional. When specified, this value is used instead of the MAC address for the device where the script is being run.
.EXAMPLE
.\Invoke-ERSManager.ps1 -ServerName "ERSServer" -GroupName "WhiteListGroup" -Add 
Add current device to "WhiteListGroup"
.EXAMPLE
.\Invoke-ERSManager.ps1 -ServerName "ERSServer" -Credential (Get-Credential) -GroupName "WhiteListGroup" -Add -MACAddress "11:22:33:44:55:66"
Add specific device to "WhiteListGroup" with credentials prompt
.EXAMPLE
.\Invoke-ERSManager.ps1 -ServerName "ERSServer" -GroupName "WhiteListGroup" -List
List all resources associated with the group "WhiteListGroup"
.EXAMPLE
.\Invoke-ERSManager.ps1 -ServerName "ERSServer" -HashAuth @{ UserName = "User"; Password="Pass" } -Remove
Delete current device from Cisco ISE using an authentication hashtable
.LINK
https://community.cisco.com/t5/security-documents/ise-ers-api-examples/ta-p/3622623
https://www.cisco.com/c/en/us/td/docs/security/ise/1-3/api_ref_guide/api_ref_book/ise_api_ref_ers1.html
https://docs.microsoft.com/en-us/dotnet/api/system.net.http.httpclient?view=netframework-4.5.2
.NOTES
Requires System.Net.Http assembly
Script does not check for valid server certificates
#>

[CmdletBinding()]
Param
(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$ServerName,

    [Parameter(ParameterSetName='Remove')]
    [switch]$Remove,

    [Parameter(ParameterSetName='List')]
    [switch]$List,

    [Parameter(ParameterSetName='Add')]
    [switch]$Add,

    [Parameter(ParameterSetName='Add')]
    [ValidateNotNullOrEmpty()]
    [string]$Description,

    [Parameter(Mandatory=$true, ParameterSetName='Add')]
    [Parameter(Mandatory=$true, ParameterSetName='List')]
    [ValidateNotNullOrEmpty()]
    [string]$GroupName,

    [ValidateNotNullOrEmpty()]
    [string]$AuthToken,

    [ValidateNotNullOrEmpty()]
    [pscredential]$Credential,

    [hashtable]$HashAuth,

    [ValidatePattern("([0-9a-fA-F]{2}[\-:]){5}[0-9a-fA-F]{2}")]
    [string]$MacAddress
)

function Invoke-ISERequestEx
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true)]
        [string]$URI,

        [Parameter(Mandatory=$true)]
        [ValidateSet("GET","PUT","POST","DELETE")]
        [string]$Method,

        [Parameter(Mandatory=$true)]
        [ValidateSet("endpoint","group")]
        [string]$Type,

        [ValidateNotNullOrEmpty()]
        [string]$Body
    )

    # Do not wait after requests by default
    $Wait = 0

    # Determine media type for request header
    $ERSMediaType = switch($Type)
    {
        "endpoint" {"identity.endpoint.1.2"; break;}
        "group" {"identity.endpointgroup.1.0"; break;}
    }

    # Create request message
    $message = New-Object System.Net.Http.HttpRequestMessage -ArgumentList $Method, $URI
    $message.Headers.Add('ERS-Media-Type', $ERSMediaType)

    # Add message content if required
    if ($Method -eq 'PUT' -or $Method -eq 'POST') {
            $message.Content = New-Object System.Net.Http.StringContent -ArgumentList $Body
            $message.Content.Headers.ContentType = 'application/json'
            # PUT and POST requests start a 5 seconds wait
            $Wait = 5
    }
 
    # Return the request result (synchronous)
    Write-Verbose -Message ("HttpClient SendAsync(): {0} {1}" -f $message.Method, $message.RequestUri)
    $result = $script:HTTPClient.SendAsync($message).Result

    # Synchronous calls do not raise underlying connection exceptions, so we raise a custom exception on failed requests
    if (-not $result) { Throw "Cannot connect to ERS. Check ServerName settings"}

    # Check for response errors. Abort script on unsuccessful server responses (StatusCode >= 400)
    Write-Verbose -Message ("ERS Response: HTTP [{0}] {1}" -f $result.StatusCode.value__, $result.ReasonPhrase)
    if (-not $result.IsSuccessStatusCode) { Throw $result.ReasonPhrase }

    # if wait time is required, wait now
    if ($Wait)
    {
        Write-Verbose ("Waiting {0} seconds" -f $Wait)
        Start-Sleep -Seconds $Wait
    }

    return $result
}

function Get-ERSEndpoint
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$MacAddress
    )

    # Search endpoint by MacAddress
    $response = Invoke-ISERequestEx -URI ("{0}/endpoint?filter=mac.EQ.{1}" -f $script:baseuri, $MacAddress) `
    -Method GET -Type endpoint

    $result = $response.Content.ReadAsStringAsync().Result | ConvertFrom-Json

    if ($result.SearchResult.total -eq 1)
    {
        # Get the endpoint from the result
        $response = Invoke-ISERequestEx -URI $result.SearchResult.resources[0].link.href `
        -Method GET -Type endpoint

        # return endpoint as an object
        Write-Verbose -Message ("Found endpoint {0} id: {1}" -f $result.SearchResult.resources[0].name, $result.SearchResult.resources[0].id)
        return ($response.Content.ReadAsStringAsync().Result | ConvertFrom-Json)
    }

    Write-Warning -Message ("Endpoint {0} not found" -f $MacAddress)
}

function New-ERSEndpoint
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$MacAddress,

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [System.Object]$Group,

        [string]$Description
    )

    # Convert JSON template to object and edit information
    $jEndpoint = $script:ERSJsonTemplate | ConvertFrom-Json
    $jEndpoint.ERSEndPoint.name = $MacAddress
    $jEndpoint.ERSEndPoint.mac = $MacAddress
    if ($Description) { $jEndpoint.ERSEndPoint.description = $Description }
    $jEndpoint.ERSEndPoint.groupId = $Group.EndPointGroup.id
    $jEndpoint.ERSEndPoint.staticGroupAssignment = "false"
    $jEndpoint.ERSEndPoint.staticProfileAssignment = "false"

    # Send request to add the endpoint
    $addresponse = Invoke-ISERequestEx -URI ("{0}/endpoint" -f $script:baseuri) `
    -Method POST -Type endpoint -Body ($jEndpoint | ConvertTo-Json)

    # Get the new endpoint information
    $qryresponse = Invoke-ISERequestEx -URI $addresponse.Headers.Location.AbsoluteURI `
    -Method GET -Type endpoint

    # return new endpoint as an object
    return ($qryresponse.Content.ReadAsStringAsync().Result | ConvertFrom-Json)
}

function Get-ERSEndpointGroup
{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$GroupName
    )
    
    # Search endpoint group by name
    $response = Invoke-ISERequestEx -URI ("{0}/endpointgroup?filter=name.EQ.{1}" -f $script:baseuri, $GroupName) `
    -Method GET -Type group

    $result = $response.Content.ReadAsStringAsync().Result | ConvertFrom-Json

    if ($result.SearchResult.total -eq 1)
    {
        # Get endpoint group information
        $response = Invoke-ISERequestEx -URI $result.SearchResult.resources[0].link.href `
        -Method GET -Type group

        # Return endpoint group as an object
        return ($response.Content.ReadAsStringAsync().Result | ConvertFrom-Json)
    }

    # Fail if group not found
    Throw ("Unable to find Group {0}" -f $GroupName)
}

function Get-ERSEndpoints
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [System.Object]$Group
    )

    # Search all endpoints in the group
    $response = Invoke-ISERequestEx -URI ("{0}/endpoint?filter=groupId.EQ.{1}" -f $script:baseuri, $Group.EndPointGroup.id) `
    -Method GET -Type endpoint

    $result = $response.Content.ReadAsStringAsync().Result | ConvertFrom-Json

    # Return endpoint objects
    foreach ($resource in $result.SearchResult.resources)
    {
        [PSCustomObject]@{
            Name = $resource.name
            Id = $resource.id
            Description = $resource.description
        }
    }
}

<#
#  Main Block Start
#>

Write-Verbose "Script started"
$script:ISEGroup = $null
$script:ISEEndPoint = $null

# Server certificate validation delegate function type definition
$script:SSLValidatorClassType = @"
using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

public static class SSLValidator {
    public static bool ReturnTrue(object sender,
        X509Certificate certificate,
        X509Chain chain,
        SslPolicyErrors sslPolicyErrors) { return true; }

        public static RemoteCertificateValidationCallback GetDelegate() {
            return new RemoteCertificateValidationCallback(SSLValidator.ReturnTrue);
        }
}
"@

# JSON template for new endpoints
$script:ERSJsonTemplate = @"
{
    "ERSEndPoint" : {
        "id" : "",
        "name" : "",
        "description" : "",
        "mac" : "",
        "profileId" : "",
        "staticProfileAssignment" : "",
        "groupId" : "",
        "staticGroupAssignment" : "",
        "portalUser" : "",
        "identityStore" : "",
        "identityStoreId" : ""
    }
}
"@

<#
    Command line parameter processing
#>

# Process the Authentication information
if (-not $PSBoundParameters.ContainsKey("AuthToken"))
{
    if ($PSBoundParameters.ContainsKey("Credential"))
    {
        Write-Verbose ("Credential = {0}" -f $Credential.ToString())
        $oCred = $Credential.GetNetworkCredential()
        $AuthToken = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $oCred.UserName,$oCred.Password)))
    }
    elseif ($PSBoundParameters.ContainsKey('HashAuth'))
    {
        Write-Verbose ("HashAuth = {0}" -f $HashAuth.ToString())
        if (-not $HashAuth.ContainsKey("username")) { Write-Warning -Message "UserName not found"}
        if (-not $HashAuth.ContainsKey("password")) { Write-Warning -Message "Password not found"}
        $AuthToken = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $HashAuth.Item("username"),$HashAuth.Item("password"))))
    }
}
# DEBUG 
if ($AuthToken) { Write-Verbose -Message ("Using AuthToken: {0}" -f $AuthToken) }

# Process the MacAddress parameter
if (-not $PSBoundParameters.ContainsKey('MacAddress'))
{
    # Autodetect MacAddress based on the connected adapter
    $MacAddress = Get-WmiObject -Namespace root/cimv2 -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=true" | `
    Where-Object { $_.DefaultIPGateway.Count -gt 0 -and -not $_.DefaultIPGateway.Contains("0.0.0.0")}| `
    Select-Object -First 1 -ExpandProperty MacAddress

    if (-not $MacAddress) { Throw "Unable to autodetect MacAddress " }
}

# Format the MacAddress (uppercase and colon separated)
$MacAddress = [string]$MacAddress.Replace('-',':').ToUpper()
Write-Verbose -Message ("Using MAC Address: {0}" -f $MacAddress)

# Initialize the base objects (System.Net.HttpClient)
Write-Verbose -Message "HttpClient initialization started"

# Load the System.Net.Http assembly if not already loaded
if (-not ("System.Net.Http.HttpClient" -as [type])) { Add-Type -AssemblyName System.Net.Http -ErrorAction Stop }

# Create an instance of the HttpClient Object
$script:HTTPClient = New-Object System.Net.Http.HttpClient -ErrorAction Stop

# Set a timeout for HttpClient operations
$script:HTTPClient.Timeout = [timespan]::FromSeconds(100)

# if authentication is provided, add it to the default request headers
if ($AuthToken) { $script:HTTPClient.DefaultRequestHeaders.Authorization = ("Basic {0}" -f $AuthToken) }

# always request JSON responses
$script:HTTPClient.DefaultRequestHeaders.Accept.Add("application/json")

Write-Verbose -Message "HttpClient initialization complete"

# use TLS 1.2 security protocol
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# create a dummy class to override the certificate check on the .NET service point manager
if (-not("SSLValidator" -as [type]))
{
    Add-Type -TypeDefinition $script:SSLValidatorClassType -ErrorAction Stop
}

# Override server certificate check (allow self signed certificates)
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = [SSLValidator]::GetDelegate()

# Base URL for ERS requests
$script:baseuri = "https://{0}:9060/ers/config" -f $ServerName

# Get endpoint object
$script:ISEEndPoint = Get-ERSEndpoint -MacAddress $MacAddress

# Get endpoint group object
if ($GroupName) { $script:ISEGroup = Get-ERSEndpointGroup -GroupName $GroupName }

# Remove operation
if ($Remove) {
    if ($script:ISEEndPoint)
    {
        Write-Verbose -Message "Removing endpoint..."
        $response = Invoke-ISERequestEx -URI $script:ISEEndPoint.ERSEndPoint.link.href -Method DELETE -Type endpoint
        Write-Verbose -Message ("Endpoint {0} removed" -f $script:ISEEndPoint.ERSEndPoint.mac)
        $script:ISEEndPoint = $null
    }
}

# List operation
if ($List)
{
    Get-ERSEndpoints -Group $script:ISEGroup
    $script:ISEEndPoint = $null
}

# Add operation
if ($Add)
{
    # if endpoint is not found, add it
    if (-not $script:ISEEndPoint)
    {
        Write-Verbose -Message ("Adding new endpoint on {0}" -f $script:ISEGroup.EndPointGroup.name)
        $script:ISEEndPoint = New-ERSEndpoint -MacAddress $MacAddress -Group $script:ISEGroup -Description $Description
    }

    # if endpoint is not in the correct group, change group assignment
    if ($script:ISEEndPoint.ERSEndPoint.groupId -ne $script:ISEGroup.EndPointGroup.id)
    {
        Write-Warning -Message ("Endpoint {0} not on {1}" -f $script:ISEEndPoint.ERSEndPoint.mac, $script:ISEGroup.EndPointGroup.name)
        # Set endpoint group properties
        $script:ISEEndPoint.ERSEndPoint.groupId = $script:ISEGroup.EndPointGroup.id
        $script:ISEEndPoint.ERSEndPoint.staticGroupAssignment = "true"

        # Attempt to change group assignment
        Write-Verbose -Message "Adding endpoint to correct group"
        $response = Invoke-ISERequestEx -URI $script:ISEEndPoint.ERSEndPoint.link.href `
        -Method PUT -Type endpoint -Body ($script:ISEEndPoint | ConvertTo-Json)

        # Double check group assignment
        Write-Verbose -Message "Verifying group assignment"
        $response = Invoke-ISERequestEx -URI $script:ISEEndPoint.ERSEndPoint.link.href `
        -Method GET -Type endpoint

        $script:ISEEndPoint = ($response.Content.ReadAsStringAsync().Result | ConvertFrom-Json)

        # if still incorrect, fail script
        if ($script:ISEEndPoint.ERSEndPoint.groupId -ne $script:ISEGroup.EndPointGroup.id) {
            Throw "Unable to assign endpoint to correct group"
        } 
    }

    Write-Verbose -Message "Endpoint added sucessfuly"
}

# if endpoint exists, return object to pipeline
if ($script:ISEEndPoint)
{
    [PSCustomObject]@{
        Name = $script:ISEEndPoint.ERSEndPoint.name
        Id = $script:ISEEndPoint.ERSEndPoint.id
        Description = $script:ISEEndPoint.ERSEndPoint.description
    }
}

# Cleanup and exit
$script:HTTPClient.Dispose()
Exit 0