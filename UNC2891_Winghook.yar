rule UNC2891_Winghook
{
	meta:
		description = "Detects UNC2891 Winghook Keylogger"
		author = "Frank Boldewin (@r3c0nst)"
		date = "2022-30-03"		
		hash1 = "d071ee723982cf53e4bce89f3de5a8ef1853457b21bffdae387c4c2bd160a38e"

	strings:
		$code1 = {01 F9 81 E1 FF 00 00 00 41 89 CA [15] 44 01 CF 81 E7 FF 00 00 00} // crypt log file data
		$code2 = {83 E2 0F 0F B6 14 1? 32 14 01 88 14 0? 48 83 ?? ?? 48 83 ?? ?? 75} // decrypt path+logfile name
		$str1 = "fgets" ascii // hook function name
		$str2 = "read" ascii // hook function name

	condition:
		uint32 (0) ==  0x464c457f and filesize < 100KB and 1 of ($code*) and all of ($str*)
}
