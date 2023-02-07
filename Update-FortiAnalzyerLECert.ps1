<#
.SYNOPSIS
This is a simple Powershell Core script to update FortiAnalyzer SSL certificate with a LetsEncrypt cert
.DESCRIPTION
This script uses the Posh-Acme module to RENEW a LetsEncrypt certificate, and then adds it to a Fortigate over SSH. This is designed to be ran consistently, and will not update the cert if Posh-Acme hasn't been setup previously.
.EXAMPLE
./Update-FortiAnalyzerLECert.ps1 -FortiAnalyzer 10.0.0.1 -Credential (new-credential admin admin) -MainDomain fa.example.com
.NOTES
This requires Posh-Acme to be preconfigured. The easiest way to do so is with the following command:
    New-PACertificate -Domain fg.example.com,fgt.example.com,vpn.example.com -AcceptTOS -Contact me@example.com -DnsPlugin Cloudflare -PluginArgs @{CFAuthEmail="me@example.com";CFAuthKey='xxx'}
.LINK
Adapted from: https://github.com/SoarinFerret/Posh-FGT-LE
#>



Param(
    [String]$FortiAnalyzer,
    [Parameter(ParameterSetName = "SecureCreds")]
    [pscredential]$Credential,
    [Parameter(ParameterSetName = "PlainTextPassword")]
    [string]$Username,
    [Parameter(ParameterSetName = "PlainTextPassword")]
    [String]$Password,
    [Boolean]$Status = $false,
    [String]$MainDomain,
    [Switch]$ForceRenew,
    [Switch]$UseExisting

)



function Connect-FortiAnalyzer {
    [CmdletBinding()]
    Param(
        $FortiAnalyzer,
        $Credential
    )
    $guid = (new-guid).guid
    $postParams = @{
        method = 'exec';
        params = @(@{
                    data = @{
                passwd=$Credential.GetNetworkCredential().Password;
                user=$Credential.UserName
            };
            url = '/sys/login/user'
        });
        #session = 'session';
        id = $guid
    } | ConvertTo-Json -Depth 4
    try{
        Update-Logs -Message "Authenticating to 'https://$FortiAnalyzer/jsonrpc' with username: $($Credential.UserName)"
        #splat arguments
        $splat = @{
            Uri = "https://$FortiAnalyzer/jsonrpc";
            Method = 'POST';
            Body = $postParams
            headers = @{"Content-Type" = "application/json"}
        }
        if($PSEdition -eq "Core"){$splat.Add("SkipCertificateCheck",$true)}

        $authRequest = Invoke-RestMethod @splat
        Update-Logs -Message "Login Result: $($authRequest.result.status)"
    }catch{
        Update-Logs -Message "Failed to authenticate to FortiAnalyzer with error: `n`t$_" 
        throw "Failed to authenticate to FortiAnalyzer with error: `n`t$_"
    }
    Update-Logs -Message "Authentication successful!" 

    Set-Variable -Scope Global -Name "FASession" -Value $authRequest.session
    return $guid
}

function Upload-FACertificate {
    Param(
        $CertificatePath,
        $keyPath,
        $CertName
    )

    $postParams = @{
        method = 'add';
        params = @(@{
                    data = @(@{
                "private-key"=$(gc $keyPath -raw).ToString();
                name=$CertName;
                certificate = $(gc $CertificatePath -raw).ToString()
            });
            url='/cli/global/system/certificate/local'
        });
        session = $FASession;
        id = $guid
    } | ConvertTo-Json -Depth 4

    try{
        Update-Logs -Message "Uploading Certificate $($CertName)"
        #splat arguments
        $splat = @{
            Uri = "https://$FortiAnalyzer/jsonrpc";
            SessionVariable = $FASession;
            Method = 'POST';
            Body = $postParams
            headers = @{"Content-Type" = "application/json"}
        }
        #Write-Host @splat
        $UploadResult = Invoke-RestMethod @splat
        #Write-Host $UploadResult.result.status
    }catch{
        Write-Verbose "Failed to upload certificate with error: `n`t$_" | Out-File $LogFile -Append
        throw "Failed to upload certificate with error:`n`t$_"
    }
    if($PSEdition -eq "Core"){$splat.Add("SkipCertificateCheck",$true)}
    #return $UploadResult
}

function Set-FACertificate {
    Param(
        $CertName
    )

    $postParams = @{
        method = 'set';
        params = @(@{
                    data = @{
                admin_server_cert=$CertName;
            };
            url='/cli/global/system/admin/setting'
        });
        session = $FASession;
        id = $guid
    } | ConvertTo-Json -Depth 4
    
    try{
        Update-Logs -Message "Set Certificate $($CertName)"
        #splat arguments
        $splat = @{
            Uri = "https://$FortiAnalyzer/jsonrpc";
            SessionVariable = $FASession;
            Method = 'POST';
            Body = $postParams
            headers = @{"Content-Type" = "application/json"}
        }
        
        #Write-Host @splat
        $SetCertificateResult = Invoke-RestMethod @splat
        #Write-Host $SetCertificateResult.result.status
    }catch{
        Write-Verbose "Failed to set certificate with error: `n`t$_" | Out-File $LogFile -Append
        throw "Failed to set certificate with error:`n`t$_"
    }
}

function Disconnect-FortiAnalyzer {
    [CmdletBinding()]
    Param(
        $guid,
        $FortiAnalyzer
    )
    $postParams = @{
        method = 'exec';
        params = @{
            url = '/sys/logout'
        };
        session = $FASession;
        id = $guid
    } | ConvertTo-Json

    Update-Logs -Message "Disconnect - Building Splat" 
    
    # logout
    $splat = @{
        headers = @{"Content-Type" = "application/json"}
        Uri = "https://$FortiAnalyzer/jsonrpc";
        SessionVariable = $FASession;
        Method = "POST";
        Body = $postParams
    }
    if($PSEdition -eq "Core"){$splat.Add("SkipCertificateCheck",$true)}
    $logoutRequest = Invoke-RestMethod @splat

    Remove-Variable -Scope Global -Name "FASession" 
    #return $logoutRequest
}

function Update-Logs {
    Param (
        [String]$Message
    )
    $Time = Get-Date -Format "HH:mm:ss.f"
    $Line = "[$($Time)]  $($Message)"
    $Line | Out-File $LogFile -Append
    #Write-Output $Message
}

Import-Module Posh-Acme
$LogFile = '.\FortiAnalyzer-LERenewal.log'
Get-Date | Out-File $LogFile -Append
Write-Output "Starting Certificate Renewal for $($FortiAnalyzer)" | Out-File $LogFile -Append

if($UseExisting){
    $cert = Get-PACertificate -MainDomain $MainDomain
}else{
    $splat = @{
        MainDomain = $MainDomain
    }
    if($ForceRenew){$splat.add("Force",$true)}
    $cert = Submit-Renewal @splat
}

if($cert){
    Write-Output "...Renewal Complete!" | Out-File $LogFile -Append

    if($PSCmdlet.ParameterSetName -eq "PlainTextPassword"){
        Write-Warning "You shouldn't use plaintext passwords on the commandline" | Out-File $LogFile -Append
        #$Credential = New-Credential -Username $env:FGT_USER -Password $env:FGT_PASS
        [securestring]$secStringPassword = ConvertTo-SecureString $Password -AsPlainText -Force
        $Credential = New-Object System.Management.Automation.PSCredential ($Username, $secStringPassword)
    }

    $certname = "LetsEncrypt_$(get-date -Format 'yyyy-MM-dd')"

    $guid = Connect-FortiAnalyzer -FortiAnalyzer $FortiAnalyzer -Credential $Credential 

    Upload-FACertificate -CertificatePath $cert.FullChainFile -keyPath $cert.KeyFile -CertName $certname 

    Set-FACertificate -CertName $certname
}

Disconnect-FortiAnalyzer -guid $guid -FortiAnalyzer $FortiAnalyzer
