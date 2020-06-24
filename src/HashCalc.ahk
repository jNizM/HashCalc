; GLOBAL SETTINGS ===============================================================================================================

#NoEnv
#SingleInstance Force
#Persistent

SetBatchLines -1

global app := { name: "HashCalc", version: "0.9.2", release: "2020-05-07", author: "jNizM", licence: "MIT" }


; GUI ===========================================================================================================================

Gui, +hWndhGuiMain
Gui, Margin, 10, 10
Gui, Font, s9, Segoe UI

Gui, Add, Tab3, vGuiTab, % "Text|File|PBKDF2"


Gui, Tab, 1
Gui, Font, s9 c000000 norm, Segoe UI
Gui, Add, Edit,     xs+10 y+15 w585 r5 gSTRING_CALCULATE vHASH_STRING
Gui, Add, Text,     xs+10 y+7  w80 h23 0x200, % "HMAC"
Gui, Add, Edit,     x+5   yp   w500 gSTRING_CALCULATE vHASH_HMAC
Gui, Add, Text,     xs+10 y+10 w585 h1 0x5
Gui, Add, Text,     xs+10 y+10 w80 h23 0x200, % "MD2"
Gui, Add, Edit,     x+5   yp   w500 0x800 vHASH_STRING_MD2
Gui, Add, Text,     xs+10 y+7  w80 h23 0x200, % "MD4"
Gui, Add, Edit,     x+5   yp   w500 0x800 vHASH_STRING_MD4
Gui, Add, Text,     xs+10 y+7  w80 h23 0x200, % "MD5"
Gui, Add, Edit,     x+5   yp   w500 0x800 vHASH_STRING_MD5
Gui, Add, Text,     xs+10 y+7  w80 h23 0x200, % "SHA-1"
Gui, Add, Edit,     x+5   yp   w500 0x800 vHASH_STRING_SHA1
Gui, Add, Text,     xs+10 y+7  w80 h23 0x200, % "SHA-256"
Gui, Add, Edit,     x+5   yp   w500 0x800 vHASH_STRING_SHA256
Gui, Add, Text,     xs+10 y+7  w80 h23 0x200, % "SHA-384"
Gui, Add, Edit,     x+5   yp   w500 0x800 vHASH_STRING_SHA384
Gui, Add, Text,     xs+10 y+7  w80 h23 0x200, % "SHA-512"
Gui, Add, Edit,     x+5   yp   w500 0x800 vHASH_STRING_SHA512
Gui, Add, Text,     xs+10 y+10 w585 h1 0x5
Gui, Add, Text,     xs+10 y+10 w80 h23 0x200, % "Verify"
Gui, Add, Edit,     x+5   yp   w440 gSTRING_VERIFY vSTRING_VERIFY
Gui, Add, Edit,     x+5   yp   w55 vSTRING_IS_VERIFY 0x800


Gui, Tab, 2
Gui, Font, s9 c000000 norm, Segoe UI
Gui, Add, Edit,     xs+10 y+15 w500 vHASH_FILE
Gui, Add, Button,   x+6 yp-1 h25 w80 gFILE_GET, % "Browse"
Gui, Font, s9 c696969, Segoe UI
Gui, Add, Text,     xs+10 y+6  w500 h23 vHASH_FILE_SIZE 0x200, % "File Size:"
Gui, Add, Button,   x+6 yp-1 h25 w80 gFILE_CALCULATE, % "Calculate"
Gui, Font, s9 c000000, Segoe UI
Gui, Add, Text,     xs+10 y+9 w585 h1 0x5
Gui, Add, CheckBox, xs+10 y+10 w80 h23 vHASH_FILE_IS_MD2, % "MD2"
Gui, Add, Edit,     x+5   yp   w500 0x800 vHASH_FILE_MD2
Gui, Add, CheckBox, xs+10 y+7  w80 h23 vHASH_FILE_IS_MD4, % "MD4"
Gui, Add, Edit,     x+5   yp   w500 0x800 vHASH_FILE_MD4
Gui, Add, CheckBox, xs+10 y+7  w80 h23 vHASH_FILE_IS_MD5 Checked, % "MD5"
Gui, Add, Edit,     x+5   yp   w500 0x800 vHASH_FILE_MD5
Gui, Add, CheckBox, xs+10 y+7  w80 h23 vHASH_FILE_IS_SHA1 Checked, % "SHA-1"
Gui, Add, Edit,     x+5   yp   w500 0x800 vHASH_FILE_SHA1
Gui, Add, CheckBox, xs+10 y+7  w80 h23 vHASH_FILE_IS_SHA256 Checked, % "SHA-256"
Gui, Add, Edit,     x+5   yp   w500 0x800 vHASH_FILE_SHA256
Gui, Add, CheckBox, xs+10 y+7  w80 h23 vHASH_FILE_IS_SHA384, % "SHA-384"
Gui, Add, Edit,     x+5   yp   w500 0x800 vHASH_FILE_SHA384
Gui, Add, CheckBox, xs+10 y+7  w80 h23 vHASH_FILE_IS_SHA512, % "SHA-512"
Gui, Add, Edit,     x+5   yp   w500 0x800 vHASH_FILE_SHA512
Gui, Add, Text,     xs+10 y+10 w585 h1 0x5
Gui, Add, Text,     xs+10 y+10 w80 h23 0x200, % "Verify"
Gui, Add, Edit,     x+5   yp   w440 gFILE_VERIFY vFILE_VERIFY
Gui, Add, Edit,     x+5   yp   w55 vFILE_IS_VERIFY 0x800
Gui, Font, s8 c696969, Segoe UI
Gui, Add, Text,     xs+10 y+45 w585 0x200 vHASH_FILE_INFO


Gui, Tab, 3
Gui, Font, s9 c000000 norm, Segoe UI
Gui, Add, Text,     xs+10 y+15 w80 h23 0x200, % "Password"
Gui, Add, Edit,     x+5   yp   w500 gPBKDF2_CALCULATE vPBKDF2_PASSWORD
Gui, Add, Text,     xs+10 y+7 w80 h23 0x200, % "Salt"
Gui, Add, Edit,     x+5   yp   w500 gPBKDF2_CALCULATE vPBKDF2_SALT
Gui, Add, Text,     xs+10 y+7 w80 h23 0x200, % "Iterations"
Gui, Add, Edit,     x+5   yp   w500 gPBKDF2_CALCULATE vPBKDF2_ITERATIONS, % 4096
Gui, Add, Text,     xs+10 y+7 w80 h23 0x200, % "KeyBitLength"
Gui, Add, Edit,     x+5   yp   w500 gPBKDF2_CALCULATE vPBKDF2_KEYBITLENGTH, % 256
Gui, Add, Text,     xs+10 y+7 w80 h23 0x200, % "Algorithm"
Gui, Add, DropDownList, x+5 yp w500 gPBKDF2_CALCULATE vPBKDF2_ALGORITHM, % "MD2|MD4|MD5|SHA1|SHA256||SHA384|SHA512"
Gui, Add, Text,     xs+10 y+10 w585 h1 0x5
Gui, Add, Text,     xs+10 y+10 w80 h23 0x200, % "PBKDF2"
Gui, Add, Edit,     x+5   yp   w500 r7 0x800 vPBKDF2
Gui, Add, Text,     xs+10 y+10 w585 h1 0x5
Gui, Add, Text,     xs+10 y+10 w80 h23 0x200, % "Verify"
Gui, Add, Edit,     x+5   yp   w440 gPBKDF2_VERIFY vPBKDF2_VERIFY
Gui, Add, Edit,     x+5   yp   w55 vPBKDF2_IS_VERIFY 0x800
Gui, Font, s8 c696969, Segoe UI
Gui, Add, Text,     xs+10 y+45 w585 0x200 vPBKDF2_INFO


Gui, Show, AutoSize, % app.name
return


; WINDOW EVENTS =================================================================================================================

GuiClose:
	ExitApp
return

GuiDropFiles:
	GuiControl, Choose, GuiTab, 2
	loop, parse, A_GuiEvent, `n
	{
		if (A_Index > 1) {
			GuiControl,, HASH_FILE_INFO, % " * The drag-and-drop operation allows only one File at time."
			break
		}
		if (InStr(FileExist(A_LoopField), "D")) {
			GuiControl,, HASH_FILE_INFO, % " * The drag-and-drop operation allows only Files."
			break
		} else {
			GuiControl,, HASH_FILE, % A_GuiEvent
			FileGetSize, FILE_SIZE, % A_GuiEvent
			GuiControl,, HASH_FILE_SIZE, % "File Size: " StrFormatByteSizeEx(FILE_SIZE, 0x1)
			GuiControl,, HASH_FILE_INFO, % ""
		}
	}
return


STRING_CALCULATE:
	GuiControlGet, GET_STRING,, HASH_STRING
	GuiControlGet, GET_STRING_HMAC,, HASH_HMAC
	GuiControl,, HASH_STRING_MD2,    % (GET_STRING_HMAC) ? bcrypt.hmac(GET_STRING, GET_STRING_HMAC, "MD2")    : bcrypt.hash(GET_STRING, "MD2")
	GuiControl,, HASH_STRING_MD4,    % (GET_STRING_HMAC) ? bcrypt.hmac(GET_STRING, GET_STRING_HMAC, "MD4")    : bcrypt.hash(GET_STRING, "MD4")
	GuiControl,, HASH_STRING_MD5,    % (GET_STRING_HMAC) ? bcrypt.hmac(GET_STRING, GET_STRING_HMAC, "MD5")    : bcrypt.hash(GET_STRING, "MD5")
	GuiControl,, HASH_STRING_SHA1,   % (GET_STRING_HMAC) ? bcrypt.hmac(GET_STRING, GET_STRING_HMAC, "SHA1")   : bcrypt.hash(GET_STRING, "SHA1")
	GuiControl,, HASH_STRING_SHA256, % (GET_STRING_HMAC) ? bcrypt.hmac(GET_STRING, GET_STRING_HMAC, "SHA256") : bcrypt.hash(GET_STRING, "SHA256")
	GuiControl,, HASH_STRING_SHA384, % (GET_STRING_HMAC) ? bcrypt.hmac(GET_STRING, GET_STRING_HMAC, "SHA384") : bcrypt.hash(GET_STRING, "SHA384")
	GuiControl,, HASH_STRING_SHA512, % (GET_STRING_HMAC) ? bcrypt.hmac(GET_STRING, GET_STRING_HMAC, "SHA512") : bcrypt.hash(GET_STRING, "SHA512")
	gosub STRING_VERIFY
return

STRING_VERIFY:
	Gui, Submit, NoHide
	STRING_RESULT := (STRING_VERIFY = "") ? ""
				: (STRING_VERIFY = HASH_STRING_MD2)    ? "MD2"
				: (STRING_VERIFY = HASH_STRING_MD4)    ? "MD4"
				: (STRING_VERIFY = HASH_STRING_MD5)    ? "MD5"
				: (STRING_VERIFY = HASH_STRING_SHA1)   ? "SHA1"
				: (STRING_VERIFY = HASH_STRING_SHA256) ? "SHA256"
				: (STRING_VERIFY = HASH_STRING_SHA384) ? "SHA384"
				: (STRING_VERIFY = HASH_STRING_SHA512) ? "SHA512"
				: "FALSE"
	GuiControl, % (InStr(STRING_RESULT, "FALSE") ? "+c800000" : "+c008000"), STRING_IS_VERIFY
	GuiControl,, STRING_IS_VERIFY, % STRING_RESULT
return


FILE_GET:
	GET_FILE := ""
	FileSelectFile, GET_FILE, 3,, % "Open"
	if !(ErrorLevel) {
		GuiControl,, HASH_FILE, % GET_FILE
		FileGetSize, FILE_SIZE, % GET_FILE
		GuiControl,, HASH_FILE_SIZE, % "File Size: " StrFormatByteSizeEx(FILE_SIZE, 0x1)
	}
return

FILE_CALCULATE:
	GuiControlGet, GET_FILE,,  HASH_FILE
	GuiControlGet, IS_MD2,,    HASH_FILE_IS_MD2
	GuiControlGet, IS_MD4,,    HASH_FILE_IS_MD4
	GuiControlGet, IS_MD5,,    HASH_FILE_IS_MD5
	GuiControlGet, IS_SHA1,,   HASH_FILE_IS_SHA1
	GuiControlGet, IS_SHA256,, HASH_FILE_IS_SHA256
	GuiControlGet, IS_SHA384,, HASH_FILE_IS_SHA384
	GuiControlGet, IS_SHA512,, HASH_FILE_IS_SHA512
	if (IS_MD2)
		GuiControl,, HASH_FILE_MD2, % bcrypt.file(GET_FILE, "MD2")
	if (IS_MD4)
		GuiControl,, HASH_FILE_MD4, % bcrypt.file(GET_FILE, "MD4")
	if (IS_MD5)
		GuiControl,, HASH_FILE_MD5, % bcrypt.file(GET_FILE, "MD5")
	if (IS_SHA1)
		GuiControl,, HASH_FILE_SHA1, % bcrypt.file(GET_FILE, "SHA1")
	if (IS_SHA256)
		GuiControl,, HASH_FILE_SHA256, % bcrypt.file(GET_FILE, "SHA256")
	if (IS_SHA384)
		GuiControl,, HASH_FILE_SHA384, % bcrypt.file(GET_FILE, "SHA384")
	if (IS_SHA512)
		GuiControl,, HASH_FILE_SHA512, % bcrypt.file(GET_FILE, "SHA512")
	gosub FILE_VERIFY
return

FILE_VERIFY:
	Gui, Submit, NoHide
	FILE_RESULT := (FILE_VERIFY = "") ? ""
				: (FILE_VERIFY = HASH_FILE_MD2)    ? "MD2"
				: (FILE_VERIFY = HASH_FILE_MD4)    ? "MD4"
				: (FILE_VERIFY = HASH_FILE_MD5)    ? "MD5"
				: (FILE_VERIFY = HASH_FILE_SHA1)   ? "SHA1"
				: (FILE_VERIFY = HASH_FILE_SHA256) ? "SHA256"
				: (FILE_VERIFY = HASH_FILE_SHA384) ? "SHA384"
				: (FILE_VERIFY = HASH_FILE_SHA512) ? "SHA512"
				: "FALSE"
	GuiControl, % (InStr(FILE_RESULT, "FALSE") ? "+c800000" : "+c008000"), FILE_IS_VERIFY
	GuiControl,, FILE_IS_VERIFY, % FILE_RESULT
return


PBKDF2_CALCULATE:
	GuiControlGet, GET_PASSWORD,,     PBKDF2_PASSWORD
	GuiControlGet, GET_SALT,,         PBKDF2_SALT
	GuiControlGet, GET_ITERATIONS,,   PBKDF2_ITERATIONS
	GuiControlGet, GET_KEYBITLENGTH,, PBKDF2_KEYBITLENGTH
	GuiControlGet, GET_ALGORITHM,,    PBKDF2_ALGORITHM

	if (Mod(GET_KEYBITLENGTH, 8) != 0) {
		GuiControl,, PBKDF2, % ""
		GuiControl,, PBKDF2_INFO, % " * The desired key bit length must be a multiple of 8!"
		return
	}
	else if ((StrLen(GET_SALT) * 2) < 128)
		GuiControl,, PBKDF2_INFO, % " * The US National Institute of Standards and Technology recommends a salt length of 128 bits."
	else if (GET_ITERATIONS < 4096)
		GuiControl,, PBKDF2_INFO, % " * A Kerberos standard in 2005 recommended a minimum of 4096 iterations."
	else
		GuiControl,, PBKDF2_INFO, % ""

	if (GET_PASSWORD) && (GET_ITERATIONS) && (GET_KEYBITLENGTH) && (GET_ALGORITHM)
		GuiControl,, PBKDF2, % GET_PBKDF2 := bcrypt.pbkdf2(GET_PASSWORD, GET_SALT, GET_ALGORITHM, GET_ITERATIONS, GET_KEYBITLENGTH)
	else
		GuiControl,, PBKDF2, % ""
return

PBKDF2_VERIFY:
	GuiControlGet, GET_PBKDF2,, PBKDF2
	GuiControlGet, GET_VERIFY,, PBKDF2_VERIFY
	PBKDF2_RESULT := (GET_VERIFY = "") ? "" : (GET_VERIFY = GET_PBKDF2) ? "OK" : "FALSE"
	GuiControl, % (InStr(PBKDF2_RESULT, "OK") ? "+c008000" : "+c800000"), PBKDF2_IS_VERIFY
	GuiControl,, PBKDF2_IS_VERIFY, % PBKDF2_RESULT
return


; FUNCTIONS =====================================================================================================================

; ===============================================================================================================================
; Function .................:  StrFormatByteSizeEx
; Minimum supported client .:  Windows Vista SP1
; Minimum supported server .:  Windows Server 2008
; Links ....................:  https://docs.microsoft.com/en-us/windows/win32/api/shlwapi/nf-shlwapi-strformatbytesizeex
; Description ..............:  Converts a numeric value into a string that represents the number in bytes, kilobytes, megabytes,
;                              or gigabytes, depending on the size.
; ===============================================================================================================================
StrFormatByteSizeEx(int, flags := 0x2)
{
	size := VarSetCapacity(buf, 0x0104, 0)
	if (DllCall("shlwapi.dll\StrFormatByteSizeEx", "int64", int, "int", flags, "str", buf, "uint", size) != 0)
		throw Exception("StrFormatByteSizeEx failed", -1)
	return buf
}


; CLASSES =======================================================================================================================

; AHK implementation for CNG (https://github.com/jNizM/AHK_CNG)
class bcrypt
{
	static BCRYPT_OBJECT_LENGTH        := "ObjectLength"
	static BCRYPT_HASH_LENGTH          := "HashDigestLength"
	static BCRYPT_ALG_HANDLE_HMAC_FLAG := 0x00000008
	static hBCRYPT := DllCall("LoadLibrary", "str", "bcrypt.dll", "ptr")

	hash(String, AlgID, encoding := "utf-8")
	{
		AlgID         := this.CheckAlgorithm(AlgID)
		ALG_HANDLE    := this.BCryptOpenAlgorithmProvider(AlgID)
		OBJECT_LENGTH := this.BCryptGetProperty(ALG_HANDLE, this.BCRYPT_OBJECT_LENGTH, 4)
		HASH_LENGTH   := this.BCryptGetProperty(ALG_HANDLE, this.BCRYPT_HASH_LENGTH, 4)
		HASH_HANDLE   := this.BCryptCreateHash(ALG_HANDLE, HASH_OBJECT, OBJECT_LENGTH)
		this.BCryptHashData(HASH_HANDLE, STRING, encoding)
		HASH_LENGTH   := this.BCryptFinishHash(HASH_HANDLE, HASH_LENGTH, HASH_DATA)
		hash          := this.CalcHash(HASH_DATA, HASH_LENGTH)
		this.BCryptDestroyHash(HASH_HANDLE)
		this.BCryptCloseAlgorithmProvider(ALG_HANDLE)
		return hash
	}

	hmac(String, Hmac, AlgID, encoding := "utf-8")
	{
		AlgID         := this.CheckAlgorithm(AlgID)
		ALG_HANDLE    := this.BCryptOpenAlgorithmProvider(AlgID, this.BCRYPT_ALG_HANDLE_HMAC_FLAG)
		OBJECT_LENGTH := this.BCryptGetProperty(ALG_HANDLE, this.BCRYPT_OBJECT_LENGTH, 4)
		HASH_LENGTH   := this.BCryptGetProperty(ALG_HANDLE, this.BCRYPT_HASH_LENGTH, 4)
		HASH_HANDLE   := this.BCryptCreateHmac(ALG_HANDLE, HMAC, HASH_OBJECT, OBJECT_LENGTH, encoding)
		this.BCryptHashData(HASH_HANDLE, STRING, encoding)
		HASH_LENGTH   := this.BCryptFinishHash(HASH_HANDLE, HASH_LENGTH, HASH_DATA)
		hash          := this.CalcHash(HASH_DATA, HASH_LENGTH)
		this.BCryptDestroyHash(HASH_HANDLE)
		this.BCryptCloseAlgorithmProvider(ALG_HANDLE)
		return hash
	}

	file(FileName, AlgID, bytes := 1048576, offset := 0, length := -1, encoding := "utf-8")
	{
		AlgID         := this.CheckAlgorithm(AlgID)
		ALG_HANDLE    := this.BCryptOpenAlgorithmProvider(AlgID)
		OBJECT_LENGTH := this.BCryptGetProperty(ALG_HANDLE, this.BCRYPT_OBJECT_LENGTH, 4)
		HASH_LENGTH   := this.BCryptGetProperty(ALG_HANDLE, this.BCRYPT_HASH_LENGTH, 4)
		HASH_HANDLE   := this.BCryptCreateHash(ALG_HANDLE, HASH_OBJECT, OBJECT_LENGTH)
		if !(IsObject(f := FileOpen(filename, "r", encoding)))
			throw Exception("Failed to open file: " filename, -1)
		length := length < 0 ? f.length - offset : length
		if ((offset + length) > f.length)
			throw Exception("Invalid parameters offset / length!", -1)
		f.Pos(offset)
		while (length > bytes) && (dataread := f.RawRead(data, bytes)) {
			this.BCryptHashFile(HASH_HANDLE, DATA, DATAREAD)
			length -= dataread
		}
		if (length > 0) {
			if (dataread := f.RawRead(data, length))
				this.BCryptHashFile(HASH_HANDLE, DATA, DATAREAD)
		}
		f.Close()
		HASH_LENGTH   := this.BCryptFinishHash(HASH_HANDLE, HASH_LENGTH, HASH_DATA)
		hash          := this.CalcHash(HASH_DATA, HASH_LENGTH)
		this.BCryptDestroyHash(HASH_HANDLE)
		this.BCryptCloseAlgorithmProvider(ALG_HANDLE)
		return hash
	}

	pbkdf2(Password, Salt, AlgID, Iterations := 1024, KeySize := 128, encoding := "utf-8")
	{
		AlgID       := this.CheckAlgorithm(AlgID)
		ALG_HANDLE  := this.BCryptOpenAlgorithmProvider(AlgID, this.BCRYPT_ALG_HANDLE_HMAC_FLAG)
		this.BCryptDeriveKeyPBKDF2(ALG_HANDLE, Password, Salt, Iterations, KeySize / 8, PBKDF2_DATA, encoding)
		pbkdf2 := this.CalcHash(PBKDF2_DATA, KeySize / 8)
		this.BCryptCloseAlgorithmProvider(ALG_HANDLE)
		return pbkdf2
	}


	; ===========================================================================================================================
	; Function ...: BCryptOpenAlgorithmProvider
	; Links ......: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptopenalgorithmprovider
	; ===========================================================================================================================
	BCryptOpenAlgorithmProvider(ALGORITHM, FLAGS := 0)
	{
		if (NT_STATUS := DllCall("bcrypt\BCryptOpenAlgorithmProvider", "ptr*", BCRYPT_ALG_HANDLE
                                                                     , "ptr",  &ALGORITHM
                                                                     , "ptr",  0
                                                                     , "uint", FLAGS) != 0)
			throw Exception("BCryptOpenAlgorithmProvider: " NT_STATUS, -1)
		return BCRYPT_ALG_HANDLE
	}

	; ===========================================================================================================================
	; Function ...: BCryptGetProperty
	; Links ......: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgetproperty
	; ===========================================================================================================================
	BCryptGetProperty(BCRYPT_HANDLE, PROPERTY, cbOutput)
	{
		if (NT_STATUS := DllCall("bcrypt\BCryptGetProperty", "ptr",   BCRYPT_HANDLE
                                                           , "ptr",   &PROPERTY
                                                           , "uint*", pbOutput
                                                           , "uint",  cbOutput
                                                           , "uint*", cbResult
                                                           , "uint",  0) != 0)
			throw Exception("BCryptGetProperty: " NT_STATUS, -1)
		return pbOutput
	}

	; ===========================================================================================================================
	; Function ...: BCryptCreateHash
	; Links ......: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptcreatehash
	; ===========================================================================================================================
	BCryptCreateHash(BCRYPT_ALG_HANDLE, ByRef pbHashObject, cbHashObject)
	{
		VarSetCapacity(pbHashObject, cbHashObject, 0)
		if (NT_STATUS := DllCall("bcrypt\BCryptCreateHash", "ptr",  BCRYPT_ALG_HANDLE
                                                          , "ptr*", BCRYPT_HASH_HANDLE
                                                          , "ptr",  &pbHashObject
                                                          , "uint", cbHashObject
                                                          , "ptr",  0
                                                          , "uint", 0
                                                          , "uint", 0) != 0)
			throw Exception("BCryptCreateHash: " NT_STATUS, -1)
		return BCRYPT_HASH_HANDLE
	}

	BCryptCreateHmac(BCRYPT_ALG_HANDLE, HMAC, ByRef pbHashObject, cbHashObject, encoding := "utf-8")
	{
		VarSetCapacity(pbHashObject, cbHashObject, 0)
		VarSetCapacity(pbSecret, (StrPut(HMAC, encoding) - 1) * ((encoding = "utf-16" || encoding = "cp1200") ? 2 : 1), 0)
		cbSecret := StrPut(HMAC, &pbSecret, encoding) - 1
		if (NT_STATUS := DllCall("bcrypt\BCryptCreateHash", "ptr",  BCRYPT_ALG_HANDLE
                                                          , "ptr*", BCRYPT_HASH_HANDLE
                                                          , "ptr",  &pbHashObject
                                                          , "uint", cbHashObject
                                                          , "ptr",  &pbSecret
                                                          , "uint", cbSecret
                                                          , "uint", 0) != 0)
			throw Exception("BCryptCreateHash: " NT_STATUS, -1)
		return BCRYPT_HASH_HANDLE
	}

	; ===========================================================================================================================
	; Function ...: BCryptHashData
	; Links ......: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcrypthashdata
	; ===========================================================================================================================
	BCryptHashData(BCRYPT_HASH_HANDLE, STRING, encoding := "utf-8")
	{
		VarSetCapacity(pbInput, (StrPut(STRING, encoding) - 1) * ((encoding = "utf-16" || encoding = "cp1200") ? 2 : 1), 0)
		cbInput := StrPut(STRING, &pbInput, encoding) - 1
		if (NT_STATUS := DllCall("bcrypt\BCryptHashData", "ptr",  BCRYPT_HASH_HANDLE
                                                        , "ptr",  &pbInput
                                                        , "uint", cbInput
                                                        , "uint", 0) != 0)
			throw Exception("BCryptHashData: " NT_STATUS, -1)
		return true
	}

	BCryptHashFile(BCRYPT_HASH_HANDLE, pbInput, cbInput)
	{
		if (NT_STATUS := DllCall("bcrypt\BCryptHashData", "ptr",  BCRYPT_HASH_HANDLE
                                                        , "ptr",  &pbInput
                                                        , "uint", cbInput
                                                        , "uint", 0) != 0)
			throw Exception("BCryptHashData: " NT_STATUS, -1)
		return true
	}

	; ===========================================================================================================================
	; Function ...: BCryptFinishHash
	; Links ......: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptfinishhash
	; ===========================================================================================================================
	BCryptFinishHash(BCRYPT_HASH_HANDLE, cbOutput, ByRef pbOutput)
	{
		VarSetCapacity(pbOutput, cbOutput, 0)
		if (NT_STATUS := DllCall("bcrypt\BCryptFinishHash", "ptr",  BCRYPT_HASH_HANDLE
                                                          , "ptr",  &pbOutput
                                                          , "uint", cbOutput
                                                          , "uint", 0) != 0)
			throw Exception("BCryptFinishHash: " NT_STATUS, -1)
		return cbOutput
	}

	; ===========================================================================================================================
	; Function ...: BCryptDeriveKeyPBKDF2
	; Links ......: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptderivekeypbkdf2
	; ===========================================================================================================================
	BCryptDeriveKeyPBKDF2(BCRYPT_ALG_HANDLE, PASS, SALT, cIterations, cbDerivedKey, ByRef pbDerivedKey, encoding := "utf-8")
	{
		VarSetCapacity(pbDerivedKey, cbDerivedKey, 0)
		VarSetCapacity(pbPass, (StrPut(PASS, encoding) - 1) * ((encoding = "utf-16" || encoding = "cp1200") ? 2 : 1), 0)
		cbPass := StrPut(PASS, &pbPass, encoding) - 1
		VarSetCapacity(pbSalt, (StrPut(SALT, encoding) - 1) * ((encoding = "utf-16" || encoding = "cp1200") ? 2 : 1), 0)
		cbSalt := StrPut(SALT, &pbSalt, encoding) - 1
		if (NT_STATUS := DllCall("bcrypt\BCryptDeriveKeyPBKDF2", "ptr",   BCRYPT_ALG_HANDLE
                                                               , "ptr",   &pbPass
                                                               , "uint",  cbPass
                                                               , "ptr",   &pbSalt
                                                               , "uint",  cbSalt
                                                               , "int64", cIterations
                                                               , "ptr",   &pbDerivedKey
                                                               , "uint",  cbDerivedKey
                                                               , "uint",  0) != 0)
			throw Exception("BCryptDeriveKeyPBKDF2: " NT_STATUS, -1)
		return true
	}

	; ===========================================================================================================================
	; Function ...: BCryptDestroyHash
	; Links ......: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptdestroyhash
	; ===========================================================================================================================
	BCryptDestroyHash(BCRYPT_HASH_HANDLE)
	{
		if (NT_STATUS := DllCall("bcrypt\BCryptDestroyHash", "ptr", BCRYPT_HASH_HANDLE) != 0)
			throw Exception("BCryptDestroyHash: " NT_STATUS, -1)
		return true
	}

	; ===========================================================================================================================
	; Function ...: BCryptCloseAlgorithmProvider
	; Links ......: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptclosealgorithmprovider
	; ===========================================================================================================================
	BCryptCloseAlgorithmProvider(BCRYPT_ALG_HANDLE)
	{
		if (NT_STATUS := DllCall("bcrypt\BCryptCloseAlgorithmProvider", "ptr",  BCRYPT_ALG_HANDLE
                                                                      , "uint", 0) != 0)
			throw Exception("BCryptCloseAlgorithmProvider: " NT_STATUS, -1)
		return true
	}


	; ===========================================================================================================================
	; For Internal Use Only
	; ===========================================================================================================================
	CheckAlgorithm(ALGORITHM)
	{
		static HASH_ALGORITHM := ["MD2", "MD4", "MD5", "SHA1", "SHA256", "SHA384", "SHA512"]
		for index, value in HASH_ALGORITHM
			if (value = ALGORITHM)
				return Format("{:U}", ALGORITHM)
		throw Exception("Invalid hash algorithm", -1, ALGORITHM)
	}

	CalcHash(Byref HASH_DATA, HASH_LENGTH)
	{
		loop % HASH_LENGTH
			HASH .= Format("{:02x}", NumGet(HASH_DATA, A_Index - 1, "uchar"))
		return HASH
	}
}

; ===============================================================================================================================