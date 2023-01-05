rule UNC2891_Steelcorgi
{
	meta:
		description = "Detects UNC2891 Steelcorgi packed ELF binaries"
		author = "Frank Boldewin (@r3c0nst)"
		date = "2022-30-03"
		hash1 = "0760cd30d18517e87bf9fd8555513423db1cd80730b47f57167219ddbf91f170"
		hash2 = "3560ed07aac67f73ef910d0b928db3c0bb5f106b5daee054666638b6575a89c5"
		hash3 = "5b4bb50055b31dbd897172583c7046dd27cd03e1e3d84f7a23837e8df7943547"
		
	strings:
		$pattern1 = {70 61 64 00 6C 63 6B 00} // padlck
		$pattern2 = {FF 72 FF 6F FF 63 FF 2F FF 73 FF 65 FF 6C FF 66 FF 2F FF 65 FF 78 FF 65} // proc_self_exe
		
	condition:
		uint32(0) == 0x464c457f and all of them
}
