rule UNC2891_Caketap
{
	meta:
		description = "Detects UNC2891 Rootkit Caketap"
		author = "Frank Boldewin (@r3c0nst)"
		date = "2022-30-03"		

	strings:
		$str1  = ".caahGss187" ascii fullword // SyS_mkdir hook cmd ident
		$str2 = "ipstat" ascii // rootkit lkm name
		$code1 = {41 80 7E 06 4B 75 ?? 41 80 7E 07 57 75 ?? 41 0F B6 46 2B} // HSM cmd KW check
		$code2 = {41 C6 46 01 3D 41 C6 46 08 32} // mode_flag switch

	condition:
        uint32 (0) ==  0x464c457f and (all of ($code*) or (all of ($str*) and #str2 == 2))
}
