rule UNC2891_Slapstick
{
	meta:
		description = "Detects UNC2891 Slapstick pam backdoor"
		author = "Frank Boldewin (@r3c0nst)"
		date = "2022-30-03"		
		hash1 = "9d0165e0484c31bd4ea467650b2ae2f359f67ae1016af49326bb374cead5f789"
		
	strings:
		$code1 = {F6 50 04 48 FF C0 48 39 D0 75 F5} // string decrypter
		$code2 = {88 01 48 FF C1 8A 11 89 C8 29 F8 84 D2 0F 85} // log buf crypter
		$str1 = "/proc/self/exe" fullword ascii
		$str2 = "%-23s %-23s %-23s %-23s %-23s %s" fullword ascii
		$str3 = "pam_sm_authenticate" ascii
		$str4 = "ACCESS GRANTED & WELCOME" xor // pam prompt message

	condition:
		uint32 (0) ==  0x464c457f and filesize < 100KB and (all of ($code*) or all of ($str*))
}
