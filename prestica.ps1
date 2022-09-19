#Credit to https://gist.github.com/indented-automation/2093bd088d59b362ec2a5b81a14ba84e it can be done by using get-random but i think that is much more elegant.
function New-Password {
    <#
    .SYNOPSIS
        Generate a random password.
    .DESCRIPTION
        Generate a random password.
    .NOTES
        Change log:
            27/11/2017 - faustonascimento - Swapped Get-Random for System.Random.
                                            Swapped Sort-Object for Fisher-Yates shuffle.
            17/03/2017 - Chris Dent - Created.
    #>
    [CmdletBinding()]
    [OutputType([String])]
    param (
        # The length of the password which should be created.
        [Parameter(ValueFromPipeline)]
        [ValidateRange(8, 255)]
        [Int32]$Length = 10,
        # The character sets the password may contain. A password will contain at least one of each of the characters.
        [String[]]$CharacterSet = ('abcdefghijklmnopqrstuvwxyz',
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
            '0123456789',
            '!$%&^.#'),
        # The number of characters to select from each character set.
        [Int32[]]$CharacterSetCount = (@(1) * $CharacterSet.Count)
    )
    begin {
        $bytes = [Byte[]]::new(4)
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $rng.GetBytes($bytes)
        $seed = [System.BitConverter]::ToInt32($bytes, 0)
        $rnd = [Random]::new($seed)
        if ($CharacterSet.Count -ne $CharacterSetCount.Count) {
            throw "The number of items in -CharacterSet needs to match the number of items in -CharacterSetCount"
        }
        $allCharacterSets = [String]::Concat($CharacterSet)
    }
    process {
        try {
            $requiredCharLength = 0
            foreach ($i in $CharacterSetCount) {
                $requiredCharLength += $i
            }
            if ($requiredCharLength -gt $Length) {
                throw "The sum of characters specified by CharacterSetCount is higher than the desired password length"
            }
            $password = [Char[]]::new($Length)
            $index = 0
            for ($i = 0; $i -lt $CharacterSet.Count; $i++) {
                for ($j = 0; $j -lt $CharacterSetCount[$i]; $j++) {
                    $password[$index++] = $CharacterSet[$i][$rnd.Next($CharacterSet[$i].Length)]
                }
            }
            for ($i = $index; $i -lt $Length; $i++) {
                $password[$index++] = $allCharacterSets[$rnd.Next($allCharacterSets.Length)]
            }
            # Fisher-Yates shuffle
            for ($i = $Length; $i -gt 0; $i--) {
                $n = $i - 1
                $m = $rnd.Next($i)
                $j = $password[$m]
                $password[$m] = $password[$n]
                $password[$n] = $j
            }
            [String]::new($password)
        }
        catch {
            Write-Error -ErrorRecord $_
        }
    }
}

function Import-ADUsers {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('CSV')]
        #just for safety let's force IO.Fileinfo type even though we will verify that later
        [System.IO.FileInfo]$CSVPath,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Domainname
    )
    
    $ErrorActionPreference = "Stop"
    if (!(Get-Module -Name ActiveDirectory -ListAvailable)) {
        Throw "Powershell module ActiveDirectory is not available. Please install it first"
    }
    Import-module ActiveDirectory
    #check if file specified even exist
    $TestPath = Test-Path $CSVPath
    if (!($testPath)) {
        Throw "Specified Path $csvpath does not exist"
    }
    #Get list of available domain suffixes
    Write-Verbose -Message "Getting List of available domain suffixes"
    $AvailableDomainsuffix = Get-adforest | select-object UPNSuffixes -ExpandProperty UPNSuffixes
    #check if domain suffix is available
    $checkdomain = $AvailableDomainsuffix.contains($Domainname)
    #since it will be impossible to create any users we treat that as a terminating error. We could also list all available domain suffixes but i think it's overkill :) 
    if (!($checkdomain)) {
        Throw "Specified domain suffix $domainname is not available."
    }

    
    
    #since it's in requirements we need to specify delimiter
    $CSVFile = Import-csv $CSVPath -Delimiter ";"
    $completed = @()
    $errors = @()
    foreach ($entry in $csvfile) {
        $samaccountname = $entry.accountname
        $email = $entry.email
        $Displayname = $entry.DisplayName
        $UPN = $samaccountname + "@" + $Domainname
        $password = New-password -Length 20

        Write-verbose -Message "Checking prerequisites"
        #verify if accountname isn't longer than 20 characters. Log and skip this iteration if there is an error 
        if ($samaccountname.length -gt 20) {
            $objecterr = New-Object -Type PSCustomObject -Property @{
                accountname = $samaccountname
                email       = $email
                reason      = "Too long Accountname"
            }
            Write-verbose -Message "Too long accountname"
            $errors += $objecterr
            continue
        }
        #verify if it's a proper e-mail - @ . after and at least 2,3 characters. Log and skip this iteration if there is an error
        if (!($email -match "[a-z0-9]+@[a-z]+\.[a-z]{2,3}")) {
            $objecterr = New-Object -Type PSCustomObject -Property @{
                accountname = $samaccountname
                email       = $email
                reason      = "Email doesn't look correct"
            }
            write-verbose -Message "email doesn't look correct"
            $errors += $objecterr
            continue
        }

        if (Get-ADUser -Filter { SamAccountName -eq $samaccountname }) {
            $objecterr = New-Object -Type PSCustomObject -Property @{
                accountname = $samaccountname
                email       = $email
                reason      = "This accountname already exists in AD"
            }
            write-verbose -Message "this accountname already exist in ad"
            $errors += $objecterr
            continue
        }
        Write-verbose -Message "prerequisites met"
        try {
            Write-verbose -Message "Creating account"
            #New-ADUser -SamAccountName $samaccountname -EmailAddress $email -UserPrincipalName $UPN -DisplayName $displayname -AccountPassword $password -ChangePasswordAtLogon 1 -ErrorAction stop | Enable-ADAccount
            $objectcompleted = New-Object -Type PSCustomObject -Property @{
                accountname = $samaccountname
                email       = $email
                password    = $password
            }
            $completed += $objectcompleted
            Write-verbose -Message "$samaccountname created, moving into the next one"
        }
        #can't think of any other exceptions that i can catch here specifically. Most common ones are duplicate users (handled earlier), password complexity (don't think that's possible with 20 characters) and error in domain suffix (also handled earlier)
        catch {            
            $objecterr = New-Object -Type PSCustomObject -Property @{
                accountname = $samaccountname
                email       = $email
                reason      = "Unrecognizable error"
            }
            $errors += $objecterr
            Write-Warning -Message "Due to unrecognizable error account $samaccountname has not been created"
        }

    }
    If (!(test-path -path C:\temp)) {
        $null = New-item -ItemType Directory -path C:\temp
    }
    $completed | Export-csv  -path C:\temp\importadusers_result.csv
    $errors | Export-csv  -path C:\temp\importadusers_errors.csv
}
