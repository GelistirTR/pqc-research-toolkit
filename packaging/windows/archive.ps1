param(
    [Parameter(Mandatory=$true)][ValidateSet('Create','Extract')][string]$Mode,
    [Parameter(Mandatory=$true)][string]$Source,
    [Parameter(Mandatory=$true)][string]$Destination
)
$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath $Destination) { throw 'Archive destination must not already exist.' }
if ($Mode -eq 'Create') {
    Compress-Archive -LiteralPath $Source -DestinationPath $Destination -CompressionLevel Optimal
} else {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $destinationRoot = [System.IO.Path]::GetFullPath($Destination).TrimEnd('\') + '\'
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $archive = [System.IO.Compression.ZipFile]::OpenRead($Source)
    try {
        if ($archive.Entries.Count -gt 256) { throw 'Archive entry limit exceeded.' }
        [long]$totalBytes = 0
        $validated = @()
        foreach ($entry in $archive.Entries) {
            $name = $entry.FullName.Replace('\','/')
            if ($name.StartsWith('/') -or $name.Contains(':') -or $name.Contains([char]0)) { throw 'Unsafe archive path.' }
            foreach ($segment in $name.TrimEnd('/').Split('/')) {
                if ($segment -in @('', '.', '..') -or $segment.EndsWith('.') -or $segment.EndsWith(' ') -or
                    $segment -match '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)') { throw 'Unsafe archive segment.' }
            }
            if ((($entry.ExternalAttributes -shr 16) -band 61440) -eq 40960) { throw 'Archive links are not allowed.' }
            $target = [System.IO.Path]::GetFullPath((Join-Path $Destination $name.Replace('/','\')))
            if (-not $target.StartsWith($destinationRoot, [System.StringComparison]::OrdinalIgnoreCase) -or -not $seen.Add($target)) {
                throw 'Unsafe or duplicate archive target.'
            }
            $totalBytes += $entry.Length
            if ($entry.Length -gt 134217728 -or $totalBytes -gt 314572800) { throw 'Archive expansion limit exceeded.' }
            $validated += @{ entry = $entry; target = $target; directory = $name.EndsWith('/') }
        }
        [System.IO.Directory]::CreateDirectory($Destination) | Out-Null
        [long]$writtenTotal = 0
        $buffer = New-Object byte[] 65536
        foreach ($item in $validated) {
            if ($item.directory) { [System.IO.Directory]::CreateDirectory($item.target) | Out-Null; continue }
            [System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($item.target)) | Out-Null
            $inputStream = $item.entry.Open()
            $outputStream = $null
            try {
                $outputStream = [System.IO.File]::Open($item.target, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
                [long]$written = 0
                while (($count = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $written += $count; $writtenTotal += $count
                    if ($written -gt $item.entry.Length -or $writtenTotal -gt 314572800) { throw 'Actual expansion limit exceeded.' }
                    $outputStream.Write($buffer, 0, $count)
                }
                if ($written -ne $item.entry.Length) { throw 'Archive entry length mismatch.' }
            } finally {
                $inputStream.Dispose()
                if ($null -ne $outputStream) { $outputStream.Dispose() }
            }
        }
    } finally { $archive.Dispose() }
}
