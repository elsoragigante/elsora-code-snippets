#Download/install required files and connect instance to AWS SSM
param (
    [string]$ProxyServer = $(Read-Host -Prompt "Proxy server"),
    [string]$SSMRegion = $(Read-Host -Prompt "AWS Region"),
    [string]$SSMActivationID = $(Read-Host -Prompt "SSM Activation ID"),
    [securestring]$SSMActivationCode = $(Read-Host -Prompt "SSM activation code" -AsSecureString)
)

function Install-SSMAgent{
    param (
        [string]$region,
        [string]$id,
        [string]$code

    )

    $dir = $env:TEMP + "\ssm"
    New-Item -ItemType directory -Path $dir -Force
    Set-Location $dir
    (New-Object System.Net.WebClient).DownloadFile("https://amazon-ssm-$region.s3.amazonaws.com/latest/windows_amd64/AmazonSSMAgentSetup.exe", $dir + "\AmazonSSMAgentSetup.exe")
    Start-Process .\AmazonSSMAgentSetup.exe -ArgumentList @("/q", "/log", "install.log", "CODE=$code", "ID=$id", "REGION=$region") -Wait
    Get-Content ($env:ProgramData + "\Amazon\SSM\InstanceData\registration")
    Get-Service -Name "AmazonSSMAgent"
}

function Set-SSMProxy {
    param (
        [string]$proxyServer
    )

    $serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\AmazonSSMAgent"
    $keyInfo = (Get-Item -Path $serviceKey).GetValue("Environment")
    $proxyVariables = @("http_proxy=$proxyServer", "no_proxy=169.254.169.254")

    If ($keyInfo -eq $null) {
        New-ItemProperty -Path $serviceKey -Name Environment -Value $proxyVariables -PropertyType MultiString -Force
    } 
    else {
        Set-ItemProperty -Path $serviceKey -Name Environment -Value $proxyVariables
    }
}


#Set OS proxy
$command = "cmd.exe /C netsh winhttp set proxy $ProxyServer"
Invoke-Expression -Command:$command

#Install AWS CLI
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module -Name AWSPowerShell -Force

#Decrypt activation code
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SSMActivationCode)
$PlainCode = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

#Install SSM agent
Install-SSMAgent -region $SSMRegion -id $SSMActivationID -code $PlainCode

#Set SSM proxy
Set-SSMProxy -proxyServer $ProxyServer
