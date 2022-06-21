import "pe"

rule ATM_CINEO4060_Blackbox {
    meta:
        description = "Detects Malware samples for Diebold Nixdorf CINEO 4060 ATMs used in blackboxing attacks across Europe since May 2021"
        author = "Frank Boldewin (@r3c0nst)"
        date = "2021-05-25"
	references = "https://twitter.com/r3c0nst/status/1539036442516660224"

    strings:
        $MyAgent1 = "javaagentsdemo/ClassListingTransformer.class" ascii fullword
        $MyAgent2 = "javaagentsdemo/MyUtils.class" ascii fullword
	$MyAgent3 = "javaagentsdemo/SimplestAgent.class" ascii fullword
	$Hook = "### [HookAPI]: Switching context!" fullword ascii
	$Delphi = "Borland\\Delphi\\RTL" fullword ascii

	$WMIHOOK1 = "TPM_SK.DLL" fullword ascii
	$WMIHOOK2 = "GetPCData" fullword ascii
	$WMIHOOK3 = {60 9C A3 E4 2B 41 00 E8 ?? ?? ?? ?? 9D 61 B8 02 00 00 00 C3} //Hook function
	$TRICK1 = "USERAUTH.DLL"  fullword ascii
	$TRICK2 = "GetAllSticksByID"  fullword ascii
	$TRICK3 = {6A 06 8B 45 FC 8B 00 B1 4F BA 1C 00 00 00}  //Hook function

    condition:
        (uint16(0) == 0x4b50 and filesize < 50KB and all of ($MyAgent*)) or
	(uint16(0) == 0x5A4D and (pe.characteristics & pe.DLL) and $Hook and $Delphi and all of ($WMIHOOK*) or all of ($TRICK*))
}
