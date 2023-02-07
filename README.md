# Update-FortiAnalyzerLECert

This script uses Posh-ACME and Let's Encrypt to update SSL certificate for HTTPS remote access and SSL-VPN access.  
## How To Use:

### Script Platform

This script utilizes the FortiAnalyzer API. Therefore, it should be compatible with any current operating system capable in running Powershell.  For testing and it's production use, only Windows machines have actively been used.
If running Windows 7 SP1, 8.1 2008 R2 SP1, 2012, or 2012 R2, you must first install PowerShell 5.1, available at [https://aka.ms/WMF5Download](https://aka.ms/WMF5Download).

#### PowerShell version

This script is designed to run on PowerShell 5.1 or greater.  There have been issues on some PowerShell Core, so it is recommended not to use PowerShell Core at this time.  

#### Install Posh-ACME module

Run command to install Posh-ACME:
```powershell
Install-Module -Name Posh-ACME -Scope AllUsers
```

#### Request initial certificate
The script is designed to handle the renewals automatically, so you need to request the initial certificate manually.  (For a list of currently supported DnsPlugins, visit https://github.com/rmbolger/Posh-ACME/wiki/List-of-Supported-DNS-Providers.)  In PowerShell:

```powershell
New-PACertificate -Domain sts.example.com -AcceptTOS -Contact me@example.com -DnsPlugin Cloudflare -PluginArgs @{CFAuthEmail="me@example.com";CFAuthKey='xxx'}

# the '-UseExisting' flag is useful when the certifcate is not yet expired
./Update-FortiAnalyzerLECert.ps1 -FortiAnalyzer fa.example.com -MainDomain fa.example.com -Credential $(New-Object pscredential 'username',(gc .\password.txt | ConvertTo-SecureString)) -UseExisting
```
### Create Secure Password
Powershell allows you to create a secure string that can only be decoded on the same machine it was encoded on.  This provides a little more security than just saving the password in plain text on the device.  This only needs to be done once.

```powershell
Read-Host "Enter Password" -AsSecureString | ConvertFrom-SecureString | Out-File ".\password.txt"
```

### Normal Use
To normally run it, where:
FDQN or IP - needs to be either the IP address of the FortiAnalyzer or a resolvable FQDN
username - needs to be a user with administrative-level access
.\password.txt - needs to reference the same file created earlier
fa.example.com - needs to be the same FQDN that the certificate is created for

```powershell
.\Update-FortigateLECert.ps1 -MainDomain 'fa.example.com' -FortiAnalyzer '10.0.0.1' -Credential $(New-Object pscredential 'username',(gc .\password.txt | ConvertTo-SecureString))
.\Update-FortigateLECert.ps1 -FortiAnalyzer <FQDN or IP> -Credential $(New-Object pscredential 'username',(gc .\password.txt | ConvertTo-SecureString)) -MainDomain fa.example.com"
```

### Force Renewals

You can force a renewal with the '-ForceRenew' switch:

```powershell
./Update-FortiAnalyzerLECert.ps1 -MainDomain fa.example.com -FortiAnalyzer '10.0.0.1' -Credential $(New-Object pscredential 'username',(gc .\password.txt | ConvertTo-SecureString)) -ForceRenew
```
### Other Notes

#### Switch Mutual Exclusivity

The '-ForceRenew' and '-UseExisting' switches are mutually exclusive, with '-UseExisting' superceeding '-ForceRenew'.

#### Logging

This script is set to automatically log the process and create a persistent log file in the same directory the script is located.  The name of the log file is FortiAnalyzer-LERenewal.log

#### Accessing the certificate(s) directly

Upon a successful request, you can directly access the certificates by visiting the following directory

```powershell
# Issue this command to enter into the Let's Encrypt directory
cd ~\appdata\Local\Posh-ACME\acme-v02.api.letsencrypt.org\

# Next, do a 'cd', then press Tab to auto populate the next directory.  This directory represents your account number.
cd [Tab]

# Perform the 'cd' - Tab again, which will enter into the next directory, which should be the name of the certificate you requested.
cd [Tab]

# Open Windows Explorer to access the certificates via GUI, if desired
start .\
```
If needing to manually install the certificate, the password by default is 'poshacme'

### Fortigate-LetsEncrypt-Renewal.xml

This XML file is a sample scheduled task that can be imported into the Windows Task Scheduler to handle the automatic renewal process.  There are a few modifications that will need to be made following the import:
- General Tab
    - Change User or Group
        - Use administrator account, either local or domain
- Triggers
    - Change date / time (optional)
- Actions
    - Edit Task
        - Add arguments
            - Change sts.example.com to FQDN of ADFS server
        - Start in
            - Replace with path of actual location of the script
