# this functin gets the key choice from the user.
function AesKeySize {
	Write-Host " (1) AES-128 "
	Write-Host " (2) AES-192 "
	Write-Host " (3) AES-256"
	
	do {
		$keychoice = Read-Host " Choose 1,2 or 3 "
		# switch is a short version of if-else statements
		$keysize = switch ($keychoice) { 
		# "choice" == { keysize }
			"1" { 16 }
			"2" { 24 }
			"3" { 32 }
			default { $null }
		}
		if ($null -eq $keysize) {
			Write-Host " Invalid. Choose 1,2, or 3"
		}
		#will keep running while there is an invalid choice
	} while ($null -eq $keysize)
		
		return $keysize
}
#this function gets the password/key from user
function Get-Key {
	#only accepts one parameter (keysize)
	param([int]$keysize)
	
	Write-Host " (1) Your own password "
	Write-Host " (2) Have the computer make one "
	
	do {
		$passchoice = Read-Host " Enter Choice "
		switch ($passchoice) {
			"1" { $answer = $true }
			"2" { $answer = $true }
			default {
				Write-Host " Invalid. Choose 1 or 2 "
				$answer = $false
			}
		} 
	} while (-not $answer)
	if ($passchoice -eq "1") {
		$pass = Read-Host " Enter Password:" -AsSecureString
		#converts to secure string into plain text then to a pointer
		$p = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pass))
		$salt = New-Object byte[] 16 # creates a 16 byte array and puts the salt in there
		[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($salt)
		# creates the key using the the pass, salt and 100,000 iterations and sha256
		$deriv = New-Object Security.Cryptography.Rfc2898DeriveBytes(
				$p, $salt, 100000,
				[Security.Cryptography.HashAlgorithmName]::SHA256)
		
		$keyBytes = $deriv.GetBytes($keysize)
		$deriv.Dispose()
		
		return @{ KeyBytes = $keyBytes; Salt = $salt; KeyMode = 1 }
	} else {
		$emptySalt = New-Object byte[] 16
    Write-Host " (1) Generate a key"
    Write-Host " (2) Enter your own hex key"
    do {
        $keychoice = Read-Host " Enter Choice"
    } while ($keychoice -notin @("1","2"))

    if ($keychoice -eq "1") {
        $keyBytes = New-Object byte[] $keysize
        [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($keyBytes)
        $hexkey = [BitConverter]::ToString($keyBytes) -replace "-",""
        Write-Host " Key: $hexkey"
        Read-Host " Press Enter when done "
    } else {
        $expectedhex = $keysize * 2
        do {
            $hexinput = (Read-Host " Enter $($keysize*8)-bit key in hex ($expectedhex hex chars)").Trim()
            $hexinput = $hexinput -replace "\s",""
            if ($hexinput.Length -ne $expectedhex -or $hexinput -notmatch '^[0-9A-Fa-f]+$') {
                Write-Host " Not a valid hex key."
                $hexinput = $null
            }
        } while ($hexinput -eq $null)
        $keyBytes = [byte[]]@(
            for ($i=0; $i -lt $hexinput.Length; $i += 2) {
                [Convert]::ToByte($hexinput.Substring($i, 2), 16)
            }
        )
    }
    return @{ KeyBytes = $keyBytes; Salt = $emptySalt; KeyMode = 0 }
	}
}	
#this function gets the decryption key
function Get-DecryptKey {
	# declares three parameters
	param([int]$keysize, [int]$answer, [byte[]]$Salt)
	
	if ($answer -eq 1) {
		#password key
		$passwordkey = Read-Host " Enter the password" -AsSecureString
		# converts from secure string to plaintext
		$depass = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($passwordkey))
		# re-derives the same key using the password and salt
		$deriv = New-Object Security.Cryptography.Rfc2898DeriveBytes($depass, $Salt, 100000,
		[Security.Cryptography.HashAlgorithmName]::SHA256)
		$keyBytes = $deriv.GetBytes($keysize)
		$deriv.Dispose()
		return $keyBytes
	} else {
		$expectedhex = $keysize * 2
		do {
			# asking for hex key
			$keyinput = (Read-Host " Enter $($KeySize*8) the key in hex ($length hex char)").Trim()
			$keyinput = $keyinput -replace "\s" , ""
			
		# [0-9A-Fa-f] is a character class which only allows characters 0-9, A-F and a-f
		# this if statement checks if the string has any of these characters from start to finish of the string
			if ($keyinput.Length -ne $expectedhex -or $keyinput -notmatch '^[0-9A-Fa-f]+$') {
				Write-Host " Not a hex value." 
				$keyinput = $null
			}
		} while ($keyinput -eq $null)
		# converts the hex into raw bytes
		# converts every pair of characters from base-16 to a byte
		return [byte[]]@(
			for ($i=0; $i -lt $keyinput.Length; $i += 2) {
			[Convert]::ToByte($keyinput.Substring($i, 2), 16)
			}	
		)
	}
}

# encryption and decryption functions below 

function encrypt-File {
	# four parameters declared
	param(
		[string]$filePath,
		[byte[]]$KeyBytes,
		[byte[]]$Salt,
		[int]$KeyMode
		)
	# checks if the path points to a file
	if (-not (Test-Path $filePath -PathType Leaf)) {
		Write-Host "Not a file."
		return
	}
	
	$outpath = $filePath + ".aesenc"
	# creates an AES object
	$aes = [Security.Cryptography.Aes]::Create()
	$aes.keySize = $KeyBytes.Length * 8
	$aes.Key = $keyBytes
	$aes.Mode = [Security.Cryptography.CipherMode]::CBC
	$aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
	$aes.GenerateIV()
	$iv = $aes.IV
	
	
	try {
		#reads the the file as a byte array
		$plainbytes = [IO.File]::ReadAllBytes($filePath)
		# the encryptor encrypts all bytes in one operation
		$encryptor = $aes.CreateEncryptor()
		$cipherbytes = $encryptor.TransformFinalBlock($plainbytes, 0, $plainbytes.Length)
		$encryptor.Dispose()
		
		$file = [IO.File]::OpenWrite($outpath)
		
		try {
			$file.Write([byte[]]@(0x41,0x45,0x53,0x43), 0, 4)
			$file.WriteByte([byte]$keyBytes.Length)
			$file.WriteByte([byte]$KeyMode)
			$file.Write($iv, 0, 16)
			$file.Write($Salt, 0, 16)
			$file.Write($cipherbytes, 0, $cipherbytes.Length)
			
		} finally{
			$file.Close()
		}
		
		Write-Host " File has been encrypted"
	} catch {
		#prints error if anything goes wrong
		Write-Host " Error: $Path : $_"
		if (Test-Path $outpath) { Remove-Item $outpath -Force }
	} finally {
		$aes.Dispose()
	}
}
# I got this far then realized you have a macbook 
# decrypt the file

function decrypt-File {
	param([string]$Path)
	# checks if the file exists/if it is a file
	if (-not (Test-Path $Path -PathType Leaf)) {
		Write-Host " Not a file: $Path"
	return
	}
	# checks if the file is encrypted
	if (-not $Path.EndsWith(".aesenc")) {
		Write-Host " Not an encrypted file "
	return 
	}
	$rawbytes = [IO.File]::ReadAllBytes($Path)
	
	if ($rawbytes.Length -lt 38 -or
	$rawbytes[0] -ne 0x41 -or $rawbytes[1] -ne 0x45 -or
	$rawbytes[2] -ne 0x53 -or $rawbytes[3] -ne 0x43) {
	Write-Host " Not a valid encrypted file."
	return
	}

	
	$keysize = [int]$rawbytes[4]
	$keyMode = [int]$rawbytes[5]
	$iv = $rawbytes[6..21]
	$salt = $rawbytes[22..37]
	$cipher = $rawbytes[38..($rawbytes.Length-1)]
	# calls get-KeyBytesForDecryption to get the key
	$keybytes = Get-DecryptKey -KeySize $keysize -answer $keyMode -Salt $salt
	$outpath = ($Path -replace "\.aesenc$","") + ".decrypted"
	# check if the path already exists and if they want to overwrie it
	if (Test-Path $outpath) {
		$overwrite = Read-Host " '$outpath' exists already. Would you like to Overwrite? (Y/N)"
		if ($overwrite -ne "Y") {
			Write-Host " $Path skipped"
		return
		}
	}
	
	$aes = [Security.Cryptography.Aes]::Create()
	$aes.KeySize = $keysize * 8
	$aes.Key = $keyBytes
	$aes.IV = $iv
	$aes.Mode = [Security.Cryptography.CipherMode]::CBC
	$aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
	
	try {
		#decrypts the ciphertext
		$decryptor =$aes.CreateDecryptor()
		$plainbytes = $decryptor.TransformFinalBlock($cipher,0,$cipher.Length)
		$decryptor.Dispose()
		# writes it to the output file
		[IO.File]::WriteAllBytes($outpath, $plainbytes)
		Write-Host " Decrypted: $outpath"
	} catch {
		Write-Host " Decryption Failed."
		
		if (Test-Path $outpath) { Remove-Item $outpath -Force}
	} finally {
		$aes.Dispose()
	}
}

# Get the file choice from user
function get-Files {
	param([string]$Operation)
	
	Write-Host " What do you want to $Operation?"
	Write-Host " (1) Single File"
	Write-Host " (2) Multiple Files"
	Write-Host " (3) Single Folder"
	Write-Host " (4) Multiple Folders"
	
	do {
		$choice = Read-Host " Enter choice"
	} while ($choice -notin @("1","2","3","4"))
	# creates an empty list to hold file paths
	$files = [System.Collections.Generic.List[string]]::new()
	$ext = if ($Operation -eq "decrypt") {"*.aesenc"} else {"*"}
	
	switch ($choice) {
		"1" {
			while ($true) {
			$p = (Read-Host " File path").Trim()
			if (Test-Path $p -PathType Leaf) { 
				$files.Add((Resolve-Path $p).Path)
            break
        }
        Write-Host " File not found: $p. Try again."
		}
	}
		"2" {
			Write-Host " Enter file paths one per line. Press Enter on a blank line to be done"
			while ($true) {
				$p = (Read-Host " File").Trim()
				if ($p -eq "") { break}
				if (Test-Path $p -PathType Leaf) { $files.Add((Resolve-Path $p).Path) }
				else { Write-Host " Not found: $p" }
			}
		}
		"3" {
			$d = (Read-Host "Folder").Trim()
			if (Test-Path $d -PathType Container) {
				Get-ChildItem -LiteralPath $d -Filter $ext -File |
				ForEach-Object {$files.Add($_.FullName) }
			} else { 
				Write-Host " Folder not found: $d "
			}
		}
		"4" {
			Write-Host " Enter folder paths one per line. Press Enter on a blank line to be done."
			while ($true) {
				$d = (Read-Host " Folder").Trim()
				if ($d -eq "") {
				break }
				if (Test-Path $d -PathType Container) {
					Get-ChildItem -LiteralPath $d -Filter $ext -File | ForEach-Object { $files.Add($_.FullName) }
				} else {
				Write-Host "Folder not found: $d" }
			}
		}
	}
	return $Files
}

#main loop

while ($true) {
	Write-Host " (1) Encrypt"
	Write-Host " (2) Decrypt"
	Write-Host " (3) Quit"
	
	$action = (Read-Host " Choice").Trim()
	
	switch ($action) {
		"1" {
			$keySize = AesKeySize
			$result   = Get-Key -keysize $keysize
			$keyBytes = [byte[]]$result.KeyBytes
			$salt     = [byte[]]$result.Salt
			$keyMode  = [int]$result.KeyMode
			if ($null -eq $keyBytes) {
				Write-Host " Keyp setup failed"
			break}
			$targetfiles = get-Files -Operation "encrypt"
			
			if ($targetfiles.Count -eq 0) {
				Write-Host "No Files selected"
			break}
			$targetfiles = $targetfiles | Where-Object { -not $_.EndsWith(".aesenc") }
			Write-Host " Encrypting $($targetfiles.Count)..."
			foreach ($f in $targetfiles) {
				Encrypt-File -filePath $f -KeyBytes $keyBytes -Salt $salt -KeyMode $keyMode
			}
			Write-Host " Done."

		}
		"2" {
			$targetFiles = get-Files -Operation "decrypt"
			
			if ($targetFiles.Count -eq 0) {
				Write-Host " No encrypted files selected."
				break
			}
			Write-Host "Decrypting $($targetFiles.Count)...."
			foreach ($f in $targetFiles) {
				decrypt-File -Path $f
			}
			Write-Host "It is done."
		}
		
		"3" {
			Write-Host " Ending session.."
			break
		}
		default {
			Write-Host " Invalid Choice."
		}
	}
	if ($action -eq "3") {
	break}
	Write-Host ""
}

#this code is the worst to type out
#my wrists hurt
		
		