param([Parameter(Mandatory=$true)][string]$Path)
$ErrorActionPreference = 'Stop'
$signature = Get-AuthenticodeSignature -LiteralPath $Path
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch '(?:^|, )O=OpenJS Foundation(?:,|$)') {
    throw 'Runtime must have a valid OpenJS Foundation Authenticode signature.'
}
[pscustomobject]@{ status = $signature.Status.ToString(); publisher = $signature.SignerCertificate.Subject } | ConvertTo-Json -Compress
