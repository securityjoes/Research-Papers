## New Attack Vector In The Cloud: Attackers caught exploiting Object Storage Services
Read full report in the following [link](https://www.securityjoes.com/post/new-attack-vector-in-the-cloud-attackers-caught-exploiting-object-storage-services).

### Related Files

|Filename   |Size   |SHA256   |
|---|---|---|
|adduser.bat   |349 bytes   |1EF7419804E401FBB3860862C2B2FBC1EC3C4650FE24FB44F787F81ACF6AD65B   |
|aduser.bat    |793 bytes   |2D77062FB28BB7A299DCB8FA4ED62503D19EA6B8BD14E4F7EC78C54B9D08F052 |
|h   |4.91 KB   |B14A23D0D77A45F4DF4889B0C2D239FB118F9D16F944571A8B4D08603D16FB41   |
|s   |4.93 KB   |9698D561DE233038CF922B0DE4A0BBB8E5723C800B4BC04C7AC82D92CB715DFD   |
|minio   |93.4 MB   |42AAACF6871108A45E1AE8EDE15BC7CDCB9CF9EDE067059524BA8D3B8928E91C   |
|networks.py    |2.02 KB   |FC7909C24B2BB7F42648C605DEACB3AE4F9574B95A562DD165E5E9ACA2CC7D74   |
|networks_linux   |8.4 MB   |0E084EB83954A090D83730B157F20549CF90B9D0206F5FD0BBCFF009788EEAFD   |
|pinger.py    |13.1 KB   |EADDE565B44E35608447B056761BA172B608B796418AB1244607DC17D21F05E3   |
|scan.py    |14.1 KB   |D56C63CC53ED72A879F224AB85019DB5FC2C30E8F193C1147975D46E3F5D913A   |
|scan_linux   |​9.57 MB   |9E1A2A068AF2524D2ABC48C1EDF46DE8CFA3329D3688164DB5969BC1914377FC   |
|shell.php   |​39 bytes   |D4CF68E351992FC32021C75820F7D2A858796DD9DC245B7FBBF2CEF8656081B2   |
|winhttpjs.bat   |20.1 KB   |6B46CF38C45AD81DFCBBD77A1B196C5DEA147088F6DAB1B1920A508D61BB03ED   |
|node.bat   |1.07 KB   |FFFA85E27836FD556A06660AC0AD76A35EF02687652A81194821C538E847D58F   |

### Network Infrastructure
|Item| VT Report|
|---|---|
|5.183.95.88|https://www.virustotal.com/gui/ip-address/5.183.95.88/relations|
|api.timeinfo.org|https://www.virustotal.com/gui/domain/api.timeinfo.org|

### Yara Rule
```
rule Lin_Go_Evil_Minio {
	meta:
		author = "Felipe Duarte, Security Joes"
		description = "Detects EvilMinIO Backdoor"
sha256_reference = "42AAACF6871108A45E1AE8EDE15BC7CDCB9CF9EDE067059524BA8D3B8928E91C"
	strings:
		$str1 = { 4? c7 44 ?? ?? 09 00 00 00 4? 8d 15 ?? ?? ?? ?? 4? 89 54 ?? ?? 4? c7 44 ?? ?? 02 00 00 00 44 0f 11 7c ?? ?? 44 0f 11 7c ?? ?? 4? 8b 54 ?? ?? 4? 8b 44 ?? ?? 4? 89 54 ?? ?? 4? 89 44 ?? ?? 4? 89 44 ?? ?? 4? 89 5c ?? ?? 4? 8b 44 ?? ?? 4? 8b 5c ?? ?? 4? 8d 4c ?? ?? b? 02 00 00 00 4? 89 fe e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 66 90 4? 85 ff 74 ?? }
		$str2 = "github.com/minio/minio/cmd/x.go"

	condition:
		all of them
}
```
