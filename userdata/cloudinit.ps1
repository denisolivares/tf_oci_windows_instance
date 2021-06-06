#ps1_sysnative

# Template variables
$user='${instance_user}'
$password='${instance_password}'
$computerName='${instance_name}'

Write-Output "Changing $user password"
net user $user $password
Write-Output "Changed $user password"

Write-Output "Configuring WinRM"
# Allow unencrypted if you wish to use http 5985 endpoint
winrm set winrm/config/service '@{AllowUnencrypted="true"}'

# Create a self-signed certificate to configure WinRM for HTTPS
$cert = New-SelfSignedCertificate -CertStoreLocation 'Cert:\LocalMachine\My' -DnsName $computerName
Write-Output "Self-signed SSL certificate generated with details: $cert"

$valueSet = @{
    Hostname = $computerName
    CertificateThumbprint = $cert.Thumbprint
}

$selectorSet = @{
    Transport = "HTTPS"
    Address = "*"
}

# Remove any prior HTTPS listener
$listeners = Get-ChildItem WSMan:\localhost\Listener
If (!($listeners | Where {$_.Keys -like "TRANSPORT=HTTPS"}))
{
    Remove-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet $selectorSet
}

Write-Output "Enabling HTTPS listener"
New-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet $selectorSet -ValueSet $valueSet
Write-Output "Enabled HTTPS listener"

Write-Output "Configured WinRM"

#Denis

# Usando Sysprep

# Generic Parameters
$hostname = hostname
$domainName = "example.com"
$serverUser = "Administrator"
$safePassword = "Trov@dor3nses"
$domainUser = "johndoe"
$Firstname = "John"
$Lastname = "Doe"
$Department = "IC"
$SecretOCID = "ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaa527wpsqaclqo3ioudvp6id7a4fh2hhbgzb3g2kttnbhmibzkedzq"

try {
    Log "Retrieving the secret from Vault..."
    $Secret = Get-OCISecretsSecretBundle -SecretId $secretOCID -AuthType InstancePrincipal -ErrorAction Stop
    $SecretDecoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Secret.SecretBundleContent.Content))
    $safePassword = $SecretDecoded | ConvertTo-SecureString -AsPlainText -Force
    $cred = New-Object -typename System.Management.Automation.PSCredential($serverUser, $safePassword)
    Log "Secret succesfully retrieved from Vault..."
} Catch {
    $ErrorMessage = $_.Exception.Message
    Log "ERROR - Retrieving Secret from Vault. Error message: $ErrorMessage"
}

Log "Changing $serverUser password"
net user $serverUser $safePassword
Log "Changed $serverUser password"

Log "Installing AD Domain Services feature"
Install-WindowsFeature –Name AD-Domain-Services –IncludeManagementTools
Log "Installed AD Domain Services feature"


Log "Verifying if it is an instance..."
if ($hostname -eq 'winmachine') {
        Log "... aaaand IT IS! =) Starting the instance setup"
        # Load PS5 Module to get Add-Computer Command
        import-module Microsoft.PowerShell.Management -UseWindowsPowerShell

        # Get Instance Metadata
        $hostname = hostname
        $metadata = (Invoke-WebRequest http://169.254.169.254/opc/v1/instance/).content | ConvertFrom-Json
        # Limit Name to 15 characters
        $NameTag = $metadata.displayname.toLower()
        if ($NameTag.length -gt 15) {
            $NameTag = $NameTag.substring(0,15)
        }
        
        # Set flags 
        $isDomainMember = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
        if ($hostname.toLower() -eq $NameTag) {
            $isRenamed = $true
        } else {
            $isRenamed = $false
        }
        Log "Flags: isDomainMember=$isDomainMember isRenamed=$isRenamed"
        
        # Remove from domain - Keep domain account
        # if server is part of Domains but wasn't renamed, it is probably
        # the first image boot, so remove it from the domain.
        $isDomainMember = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
        if ($isDomainMember) {
            if (-not $isRenamed) {
                C:\Windows\System32\Sysprep\sysprep.exe /generalize /quiet /oobe /reboot /unattend:c:\windows\system32\sysprep\autounattend.xml
                Log "Rodando SYSPREP"
                Break Script
            }
        }

        # If SYSPREP was not finished exit script
        $ImageState = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State | Select-Object -ExpandProperty ImageState
        if ($ImageState -ne "IMAGE_STATE_COMPLETE") {
            Log "Sysprep state is $ImageState. Skiping script execution."
            Break Script
        } else {
            Log "Sysprep state is $ImageState. Moving on."
        }

        # Check if machine is in Autoscaling Group by looking at name tag
        if ($NameTag.StartsWith("inst-")) {
            # Rename hostname and reboot first (if not done yet)
            if (-not $isRenamed) {
                write-host Renaming Computer and Rebooting...
                try {
                    Rename-Computer $NameTag -Force -ErrorAction Stop
                    Log "Host renamed from $hostname to $($NameTag)"
                    Log "Iniciando $hostname "
                    restart-computer -ComputerName localhost -Force
                    Break Script
                } Catch {
                    $ErrorMessage = $_.Exception.Message
                    Log "Rename Computer: $ErrorMessage"
                }
            }

            # Domain join with credentials
            if (-not $isDomainMember) {
                # Load PS5 Module to get Add-Computer Command
                import-module Microsoft.PowerShell.Management -UseWindowsPowerShell
                # Domain Join
                try {
                    Log "Joining domain $domainName"
                    Add-Computer -DomainName $domainName -OUPath $OUPath -Options JoinWithNewName,AccountCreate -Credential $cred -Force -Restart
                } Catch {
                    $ErrorMessage = $_.Exception.Message
                    Log "Domain Join: $ErrorMessage"
                }
            }
        <# # Auto-Delete script if all is done
        $isDomainMember = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
        if ($isDomainMember -and $isRenamed) {
            try {
                Log "All set. Removing Script $($MyInvocation.MyCommand.Definition)"
                Remove-Item $MyInvocation.MyCommand.Definition -force
            } Catch {
                $ErrorMessage = $_.Exception.Message
                Log "Auto-delete: $ErrorMessage"
            }
        } #>
    }
} 