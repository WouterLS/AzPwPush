function Cleanup-AzPasswords {
    Get-Item "PasswordFile_*" | ForEach-Object {If($_.LastWriteTime -lt (get-date).AddDays(-$ENV:MaximumPasswordAge)){ Remove-Item $_.FullName -Force } }
}

function Create-AzPassword {
    param($Password, $MaxViews = 0)
    
    [Byte[]] $key = (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16)

    if ([string]::IsNullOrEmpty($Password)) {
        $Password = Generate-AzPassword
    }

    $EncPassword = "$($MaxViews)|$(($Password | ConvertTo-SecureString -Force -AsPlainText) | ConvertFrom-SecureString -Key $key)"
   
    while ($true) {
        try {
            $bytes = new-object 'System.Byte[]' (200/8)
            (new-object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($bytes)
            $RandomID = [System.BitConverter]::ToString($bytes).Replace('-', '')
            new-item "PasswordFile_$($RandomID)" -Value ($EncPassword) -ErrorAction Stop | Out-Null
            break
        }
        catch{}
    }

    return $RandomID
}

function Delete-AzPassword {
    param($ID)
    try {
        Remove-Item -Force -path "PasswordFile_$($ID)" -ErrorAction Stop| Out-Null
        return $true
    }
    catch {
        return $false
    }
}

function Get-AzPassword {
    param($ID)
    [Byte[]] $key = (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16)

    try 
    {
        $Data = Get-Content "PasswordFile_$($ID)" -ErrorAction Stop

        $EncPassword = $Data.Split('|')[1]
        $MaxViews = $Data.Split('|')[0] -as [int]

        if($MaxViews -eq 1) {
            Delete-AzPassword -ID $ID
        }
        else {
            "$($MaxViews - 1)|$($EncPassword)" | Out-File -FilePath "PasswordFile_$($ID)"
        }

        $Password = [System.Net.NetworkCredential]::new("", ($EncPassword | ConvertTo-SecureString -Key $key)).Password
    }
    catch {
        $Password = $false
    }

    return $Password
}

function Generate-AzPassword {
    $CharSet = ('0123456789{]+-[*=@:)}$^%;(_!&#?>/|').ToCharArray() 
    $RandSymbol = (Get-Random -InputObject $CharSet -Count 5) -Join ''
    $words = [System.IO.file]::ReadAllLines('wordlist.txt') 
    return ($words |  Get-Random -Count 3) + $RandSymbol -Join ''
}
