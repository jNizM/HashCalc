; ===========================================================================================================================================================================

/*
	HashCalc (written in AutoHotkey)

	Author ....: jNizM
	Released ..: 2014-03-11
	Modified ..: 2021-11-04
	License ...: MIT
	GitHub ....: https://github.com/jNizM/HashCalc
	Forum .....: https://www.autohotkey.com/boards/viewtopic.php?t=96316
*/


; SCRIPT DIRECTIVES =========================================================================================================================================================

#Requires AutoHotkey v2.0-


; GLOBALS ===================================================================================================================================================================

app := Map("name", "HashCalc", "version", "1.0", "release", "2021-11-04", "author", "jNizM", "licence", "MIT")

hHLINE := DllCall("gdi32\CreateBitmap", "int", 1, "int", 2, "uint", 0x1, "uint", 32, "int64*", 0x7fa5a5a57f5a5a5a, "ptr")


; GUI =======================================================================================================================================================================

Main := Gui(, app["name"])
Main.MarginX := 10
Main.MarginY := 10
Main.SetFont("s10", "Segoe UI")

MainTab := Main.AddTab3("xm ym", ["Text", "File", "PBKDF2"])

; =================================================================================================

MainTab.UseTab("Text")

TB01ED01 := Main.AddEdit("xs+15 y+15 w585 r5")
TB01ED01.OnEvent("Change", HashText)

Main.AddText("xs+15 y+7 w80 h25 0x200", "HMAC")
TB01ED02 := Main.AddEdit("x+5 yp w500")
TB01ED02.OnEvent("Change", HashText)

Main.AddPicture("xs+15 y+10 w584 h1 BackgroundTrans", "HBITMAP:*" hHLINE)

Main.AddText("xs+15 y+10 w80 h25 0x200", "MD2")
TB01ED03 := Main.AddEdit("x+5 yp w500 0x800")
Main.AddText("xs+15 y+7 w80 h25 0x200", "MD4")
TB01ED04 := Main.AddEdit("x+5 yp w500 0x800")
Main.AddText("xs+15 y+7 w80 h25 0x200", "MD5")
TB01ED05 := Main.AddEdit("x+5 yp w500 0x800")
Main.AddText("xs+15 y+7 w80 h25 0x200", "SHA-1")
TB01ED06 := Main.AddEdit("x+5 yp w500 0x800")
Main.AddText("xs+15 y+7 w80 h25 0x200", "SHA-256")
TB01ED07 := Main.AddEdit("x+5 yp w500 0x800")
Main.AddText("xs+15 y+7 w80 h25 0x200", "SHA-384")
TB01ED08 := Main.AddEdit("x+5 yp w500 0x800")
Main.AddText("xs+15 y+7 w80 h25 0x200", "SHA-512")
TB01ED09 := Main.AddEdit("x+5 yp w500 0x800")

Main.AddPicture("xs+15 y+10 w584 h1 BackgroundTrans", "HBITMAP:*" hHLINE)

Main.AddText("xs+15 y+10 w80 h25 0x200", "Verify")
TB01ED10 := Main.AddEdit("x+5 yp w435")
TB01ED10.OnEvent("Change", VerifyText)
TB01ED11 := Main.AddEdit("x+5 yp w60 0x800")

; =================================================================================================

MainTab.UseTab("File")

TB02ED01 := Main.AddEdit("xs+15 y+15 w500")
Main.AddButton("x+6 yp-1 w80", "Browse").OnEvent("Click", GetFile)

Main.SetFont("s10 c696969", "Segoe UI")
TB02TX01 := Main.AddText("xs+15 y+6 w500 h25 0x200", "File Size:")
Main.SetFont("s10 cDefault", "Segoe UI")

Main.AddButton("x+6 yp-1 w80", "Calculate").OnEvent("Click", HashFile)

Main.AddPicture("xs+15 y+10 w584 h1 BackgroundTrans", "HBITMAP:*" hHLINE)

TB02CB01 := Main.AddCheckBox("xs+15 y+10 w80 h25", "MD2")
TB02ED02 := Main.AddEdit("x+5 yp w500 0x800")

TB02CB02 := Main.AddCheckBox("xs+15 y+7 w80 h25", "MD4")
TB02ED03 := Main.AddEdit("x+5 yp w500 0x800")

TB02CB03 := Main.AddCheckBox("xs+15 y+7 w80 h25 Checked", "MD5")
TB02ED04 := Main.AddEdit("x+5 yp w500 0x800")

TB02CB04 := Main.AddCheckBox("xs+15 y+7 w80 h25 Checked", "SHA-1")
TB02ED05 := Main.AddEdit("x+5 yp w500 0x800")

TB02CB05 := Main.AddCheckBox("xs+15 y+7 w80 h25 Checked", "SHA-256")
TB02ED06 := Main.AddEdit("x+5 yp w500 0x800")

TB02CB06 := Main.AddCheckBox("xs+15 y+7 w80 h25", "SHA-384")
TB02ED07 := Main.AddEdit("x+5 yp w500 0x800")

TB02CB07 := Main.AddCheckBox("xs+15 y+7 w80 h25", "SHA-512")
TB02ED08 := Main.AddEdit("x+5 yp w500 0x800")

Main.AddPicture("xs+15 y+10 w584 h1 BackgroundTrans", "HBITMAP:*" hHLINE)

Main.AddText("xs+15 y+10 w80 h25 0x200", "Verify")
TB02ED09 := Main.AddEdit("x+5 yp w435")
TB02ED09.OnEvent("Change", VerifyText)
TB02ED10 := Main.AddEdit("x+5 yp w60 0x800")

Main.SetFont("s10 c696969", "Segoe UI")
TB02TX02 := Main.AddText("xs+15 y+50 w585 h25 0x200")
Main.SetFont("s10 cDefault", "Segoe UI")

; =================================================================================================

MainTab.UseTab("PBKDF2")

Main.AddText("xs+15 y+15 w80 h25 0x200", "Password")
TB03ED01 := Main.AddEdit("x+5 yp w500")
TB03ED01.OnEvent("Change", PBKDF2)

Main.AddText("xs+15 y+7 w80 h25 0x200", "Salt")
TB03ED02 := Main.AddEdit("x+5 yp w500")
TB03ED02.OnEvent("Change", PBKDF2)

Main.AddText("xs+15 y+7 w80 h25 0x200", "Iterations")
TB03ED03 := Main.AddEdit("x+5 yp w500 0x2000")
Main.AddUpDown("Range1-2147483647", 4096)
TB03ED03.OnEvent("Change", PBKDF2)

Main.AddText("xs+15 y+7 w80 h25 0x200", "KeyBitLength")
TB03ED04 := Main.AddEdit("x+5 yp w500 0x2000")
Main.AddUpDown("Range8-2147483640", 256)
TB03ED04.OnEvent("Change", PBKDF2)

Main.AddText("xs+15 y+7 w80 h25 0x200", "Algorithm")
TB03DD01 := Main.AddDropDownList("x+5 yp w500 Choose5", ["MD2", "MD4", "MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512"])
TB03DD01.OnEvent("Change", PBKDF2)

Main.AddPicture("xs+15 y+10 w584 h1 BackgroundTrans", "HBITMAP:*" hHLINE)

Main.AddText("xs+15 y+10 w80 h25 0x200", "PBKDF2")
TB03ED05 := Main.AddEdit("x+5 yp w500 r7")

Main.AddPicture("xs+15 y+10 w584 h1 BackgroundTrans", "HBITMAP:*" hHLINE)

Main.AddText("xs+15 y+10 w80 h25 0x200", "Verify")
Main.AddEdit("x+5 yp w435")
TB03ED06 := Main.AddEdit("x+5 yp w60 0x800")

Main.SetFont("s10 c696969", "Segoe UI")
TB03TX01 := Main.AddText("xs+15 y+49 w585 h25 0x200")
Main.SetFont("s10 cDefault", "Segoe UI")

; =================================================================================================

Main.OnEvent("DropFiles", Main_DropFiles)
Main.Show()


; WINDOW EVENTS =============================================================================================================================================================


Main_DropFiles(GuiObj, GuiCtrlObj, FileArray, *)
{
	MainTab.Choose(2)
	TB02TX02.Text := ""

	for i, v in FileArray
	{
		if (i > 1)
		{
			TB02TX02.Text := " * The drag-and-drop operation allows only one File at time."
			break
		}

		if (InStr(FileExist(v), "D"))
		{
			TB02TX02.Text := " * The drag-and-drop operation allows only Files."
			break
		}
		else
		{
			TB02ED01.Text := v
			TB02TX01.Text := "File Size: " StrFormatByteSizeEx(FileGetSize(v), 0x1)
		}
	}
}


HashText(*)
{
	if (TB01ED02.Text)
	{
		TB01ED03.Text := Hash.HMAC("MD2",     TB01ED01.Text, TB01ED02.Text)
		TB01ED04.Text := Hash.HMAC("MD4",     TB01ED01.Text, TB01ED02.Text)
		TB01ED05.Text := Hash.HMAC("MD5",     TB01ED01.Text, TB01ED02.Text)
		TB01ED06.Text := Hash.HMAC("SHA-1",   TB01ED01.Text, TB01ED02.Text)
		TB01ED07.Text := Hash.HMAC("SHA-256", TB01ED01.Text, TB01ED02.Text)
		TB01ED08.Text := Hash.HMAC("SHA-384", TB01ED01.Text, TB01ED02.Text)
		TB01ED09.Text := Hash.HMAC("SHA-512", TB01ED01.Text, TB01ED02.Text)
	}
	else
	{
		TB01ED03.Text := Hash.String("MD2",     TB01ED01.Text)
		TB01ED04.Text := Hash.String("MD4",     TB01ED01.Text)
		TB01ED05.Text := Hash.String("MD5",     TB01ED01.Text)
		TB01ED06.Text := Hash.String("SHA-1",   TB01ED01.Text)
		TB01ED07.Text := Hash.String("SHA-256", TB01ED01.Text)
		TB01ED08.Text := Hash.String("SHA-384", TB01ED01.Text)
		TB01ED09.Text := Hash.String("SHA-512", TB01ED01.Text)
	}
	VerifyText()
}


VerifyText(*)
{
	switch TB01ED10.Text
	{
		case TB01ED03.Text: TB01ED11.Text := "MD2",    TB01ED11.SetFont("c008000")
		case TB01ED04.Text: TB01ED11.Text := "MD4",    TB01ED11.SetFont("c008000")
		case TB01ED05.Text: TB01ED11.Text := "MD4",    TB01ED11.SetFont("c008000")
		case TB01ED06.Text: TB01ED11.Text := "SHA1",   TB01ED11.SetFont("c008000")
		case TB01ED07.Text: TB01ED11.Text := "SHA256", TB01ED11.SetFont("c008000")
		case TB01ED08.Text: TB01ED11.Text := "SHA384", TB01ED11.SetFont("c008000")
		case TB01ED09.Text: TB01ED11.Text := "SHA512", TB01ED11.SetFont("c008000")
		default:            TB01ED11.Text := "FALSE",  TB01ED11.SetFont("c800000")
	}
}


GetFile(*)
{
	SelectedFile := FileSelect(3,, "Open")
	if (SelectedFile)
	{
		TB02ED01.Text := SelectedFile
		TB02TX01.Text := "File Size: " StrFormatByteSizeEx(FileGetSize(SelectedFile), 0x1)
	}
}


HashFile(*)
{
	if (TB02ED01.Text)
	{
		if (TB02CB01.Value)
			TB02ED02.Text := Hash.File("MD2",     TB02ED01.Text)
		if (TB02CB02.Value)
			TB02ED03.Text := Hash.File("MD4",     TB02ED01.Text)
		if (TB02CB03.Value)
			TB02ED04.Text := Hash.File("MD5",     TB02ED01.Text)
		if (TB02CB04.Value)
			TB02ED05.Text := Hash.File("SHA-1",   TB02ED01.Text)
		if (TB02CB05.Value)
			TB02ED06.Text := Hash.File("SHA-256", TB02ED01.Text)
		if (TB02CB06.Value)
			TB02ED07.Text := Hash.File("SHA-384", TB02ED01.Text)
		if (TB02CB06.Value)
			TB02ED04.Text := Hash.File("SHA-512", TB02ED01.Text)
		VerifyFile()
	}
}


VerifyFile(*)
{
	switch TB02ED09.Text
	{
		case TB02ED02.Text: TB02ED10.Text := "MD2",    TB02ED10.SetFont("c008000")
		case TB02ED03.Text: TB02ED10.Text := "MD4",    TB02ED10.SetFont("c008000")
		case TB02ED04.Text: TB02ED10.Text := "MD4",    TB02ED10.SetFont("c008000")
		case TB02ED05.Text: TB02ED10.Text := "SHA1",   TB02ED10.SetFont("c008000")
		case TB02ED06.Text: TB02ED10.Text := "SHA256", TB02ED10.SetFont("c008000")
		case TB02ED07.Text: TB02ED10.Text := "SHA384", TB02ED10.SetFont("c008000")
		case TB02ED08.Text: TB02ED10.Text := "SHA512", TB02ED10.SetFont("c008000")
		default:            TB02ED10.Text := "FALSE",  TB02ED10.SetFont("c800000")
	}
}


PBKDF2(*)
{
	TB03TX01.Text := ""

	if ((StrLen(TB03ED02.Text) * 2) < 128)
	{
		TB03TX01.Text := " * The US National Institute of Standards and Technology recommends a salt length of 128 bits."
	}

	if (TB03ED03.Text) && (TB03ED03.Text < 4096)
	{
		TB03TX01.Text := " * A Kerberos standard in 2005 recommended a minimum of 4096 iterations."
	}

	if (TB03ED04.Text) && (Mod(TB03ED04.Text, 8) != 0)
	{
		TB03ED05.Text := ""
		TB03TX01.Text := " * The desired key bit length must be a multiple of 8!"
		return
	}

	if (TB03ED01.Text) && (TB03ED02.Text) && (TB03ED03.Text) && (TB03ED04.Text)
		TB03ED05.Text := Hash.PBKDF2(TB03DD01.Text, TB03ED01.Text, TB03ED02.Text, TB03ED03.Text, TB03ED04.Text)
	VerifyPBKDF2()
}


VerifyPBKDF2(*)
{
	if (TB03ED05.Text)
		TB01ED11.Text := "OK",    TB01ED11.SetFont("c008000")
	else
		TB01ED11.Text := "FALSE", TB01ED11.SetFont("c008000")
}


; FUNCTIONS =================================================================================================================================================================

StrFormatByteSizeEx(Value, Flags := 0x2)
{
	Size := VarSetStrCapacity(&NumberStr, 1024)
	if !(DllCall("shlwapi\StrFormatByteSizeEx", "Int64", Value, "Int", Flags, "Str", NumberStr, "Int", Size))
		return NumberStr
	return ""
}


; INCLUDES ==================================================================================================================================================================


class Hash extends CNG
{

	static String(AlgId, String, Encoding := "UTF-8", Output := "HEXRAW")
	{
		static hAlgorithm := 0, hHash := 0

		try
		{
			; verify the hash algorithm identifier
			if !(ALGORITHM := this.BCrypt.HashAlgorithm(AlgId))
				throw Error("Unrecognized hash algorithm identifier: " AlgId, -1)

			; open an algorithm handle
			hAlgorithm := this.BCrypt.OpenAlgorithmProvider(ALGORITHM)

			; create a hash
			hHash := this.BCrypt.CreateHash(hAlgorithm)

			; hash some data
			Data := this.StrBuf(String, Encoding)
			this.BCrypt.HashData(hHash, Data, Data.Size - 1)

			; calculate the length of the hash
			HASH_LENGTH := this.BCrypt.GetProperty(hAlgorithm, this.BCrypt.Constants.BCRYPT_HASH_LENGTH, 4)

			; close the hash
			HASH_DATA := Buffer(HASH_LENGTH, 0)
			FINISH_HASH := this.BCrypt.FinishHash(hHash, &HASH_DATA, HASH_LENGTH)

			; convert bin to string (base64 / hex)
			HASH := this.Crypt.BinaryToString(HASH_DATA, HASH_LENGTH, Output)
		}
		catch as Exception
		{
			; represents errors that occur during application execution
			throw Exception
		}
		finally
		{
			; cleaning up resources
			if (hHash)
				this.BCrypt.DestroyHash(hHash)

			if (hAlgorithm)
				this.BCrypt.CloseAlgorithmProvider(hAlgorithm)
		}

		return HASH
	}


	static File(AlgId, FileName, Bytes := 10485760, Offset := 0, Length := -1, Encoding := "UTF-8", Output := "HEXRAW")
	{
		static hAlgorithm := 0, hHash := 0, File := 0

		try
		{
			; verify the hash algorithm identifier
			if !(ALGORITHM := this.BCrypt.HashAlgorithm(AlgId))
				throw Error("Unrecognized hash algorithm identifier: " AlgId, -1)

			; open an algorithm handle
			hAlgorithm := this.BCrypt.OpenAlgorithmProvider(ALGORITHM)

			; create a hash
			hHash := this.BCrypt.CreateHash(hAlgorithm)

			; hash some data
			if !(File := FileOpen(FileName, "r", Encoding))
				throw Error("Failed to open file: " FileName, -1)
			Length := Length < 0 ? File.Length - Offset : Length
			Data := Buffer(Bytes)
			if ((Offset + Length) > File.Length)
				throw Error("Invalid parameters offset / length!", -1)
			while (Length > Bytes) && (Dataread := File.RawRead(Data, Bytes)) {
				this.BCrypt.HashData(hHash, Data, Dataread)
				Length -= Dataread
			}
			if (Length > 0) {
				if (Dataread := File.RawRead(Data, Length))
					this.BCrypt.HashData(hHash, Data, Dataread)
			}

			; calculate the length of the hash
			HASH_LENGTH := this.BCrypt.GetProperty(hAlgorithm, this.BCrypt.Constants.BCRYPT_HASH_LENGTH, 4)

			; close the hash
			HASH_DATA := Buffer(HASH_LENGTH, 0)
			FINISH_HASH := this.BCrypt.FinishHash(hHash, &HASH_DATA, HASH_LENGTH)

			; convert bin to string (base64 / hex)
			HASH := this.Crypt.BinaryToString(HASH_DATA, HASH_LENGTH, Output)
		}
		catch as Exception
		{
			; represents errors that occur during application execution
			throw Exception
		}
		finally
		{
			; cleaning up resources
			if (File)
				File.Close()

			if (hHash)
				this.BCrypt.DestroyHash(hHash)

			if (hAlgorithm)
				this.BCrypt.CloseAlgorithmProvider(hAlgorithm)
		}

		return HASH
	}



	static HMAC(AlgId, String, Hmac, Encoding := "UTF-8", Output := "HEXRAW")
	{
		static hAlgorithm := 0, hHash := 0

		try
		{
			; verify the hash algorithm identifier
			if !(ALGORITHM := this.BCrypt.HashAlgorithm(AlgId))
				throw Error("Unrecognized hash algorithm identifier: " AlgId, -1)

			; open an algorithm handle
			hAlgorithm := this.BCrypt.OpenAlgorithmProvider(ALGORITHM, this.BCrypt.Constants.BCRYPT_ALG_HANDLE_HMAC_FLAG)

			; create a hash
			Mac := this.StrBuf(Hmac, Encoding)
			hHash := this.BCrypt.CreateHash(hAlgorithm, Mac, Mac.Size - 1)

			; hash some data
			Data := this.StrBuf(String, Encoding)
			this.BCrypt.HashData(hHash, Data, Data.Size - 1)

			; calculate the length of the hash
			HASH_LENGTH := this.BCrypt.GetProperty(hAlgorithm, this.BCrypt.Constants.BCRYPT_HASH_LENGTH, 4)

			; close the hash
			HASH_DATA := Buffer(HASH_LENGTH, 0)
			FINISH_HASH := this.BCrypt.FinishHash(hHash, &HASH_DATA, HASH_LENGTH)

			; convert bin to string (base64 / hex)
			HASH := this.Crypt.BinaryToString(HASH_DATA, HASH_LENGTH, Output)
		}
		catch as Exception
		{
			; represents errors that occur during application execution
			throw Exception
		}
		finally
		{
			; cleaning up resources
			if (hHash)
				this.BCrypt.DestroyHash(hHash)

			if (hAlgorithm)
				this.BCrypt.CloseAlgorithmProvider(hAlgorithm)
		}

		return HASH
	}



	static PBKDF2(AlgId, Password, Salt, Iterations := 4096, KeySize := 256, Encoding := "UTF-8", Output := "HEXRAW")
	{
		static hAlgorithm := 0, hHash := 0

		try
		{
			; verify the hash algorithm identifier
			if !(ALGORITHM := this.BCrypt.HashAlgorithm(AlgId))
				throw Error("Unrecognized hash algorithm identifier: " AlgId, -1)

			; check key bit length
			if (Mod(KeySize, 8) != 0)
				throw Error("The desired key bit length must be a multiple of 8!", -1)

			; open an algorithm handle
			hAlgorithm := this.BCrypt.OpenAlgorithmProvider(ALGORITHM, this.BCrypt.Constants.BCRYPT_ALG_HANDLE_HMAC_FLAG)

			; derives a key from a hash value
			PBKDF2_DATA := this.BCrypt.DeriveKeyPBKDF2(hAlgorithm, Password, Salt, Iterations, KeySize / 8, Encoding)

			; convert bin to string (base64 / hex)
			PBKDF2 := this.Crypt.BinaryToString(PBKDF2_DATA, PBKDF2_DATA.size, Output)
		}
		catch as Exception
		{
			; represents errors that occur during application execution
			throw Exception
		}
		finally
		{
			; cleaning up resources
			if (hAlgorithm)
				this.BCrypt.CloseAlgorithmProvider(hAlgorithm)
		}

		return PBKDF2
	}
}


; ===========================================================================================================================================================================


class CNG
{

	class BCrypt
	{

		#DllLoad "*i bcrypt.dll"


		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		; //
		; // FUNCTION NAME: BCrypt.CloseAlgorithmProvider
		; //
		; // This function closes an algorithm provider.
		; //
		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		static CloseAlgorithmProvider(hAlgorithm)
		{
			NT_STATUS := DllCall("bcrypt\BCryptCloseAlgorithmProvider", "Ptr",  hAlgorithm
			                                                          , "UInt", Flags := 0
			                                                          , "UInt")

			if (NT_STATUS = this.NT.SUCCESS)
				return true
			throw Error(this.GetErrorMessage(NT_STATUS), -1)
		}


		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		; //
		; // FUNCTION NAME: BCrypt.CreateHash
		; //
		; // This function is called to create a hash or Message Authentication Code (MAC) object.
		; //
		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		static CreateHash(hAlgorithm, Buf := 0, Size := 0)
		{
			NT_STATUS := DllCall("bcrypt\BCryptCreateHash", "Ptr",  hAlgorithm
			                                              , "Ptr*", &hHash := 0
			                                              , "Ptr",  0
			                                              , "UInt", 0
			                                              , "Ptr",  Buf
			                                              , "UInt", Size
			                                              , "UInt", Flags := 0
			                                              , "UInt")

			if (NT_STATUS = this.NT.SUCCESS)
				return hHash
			throw Error(this.GetErrorMessage(NT_STATUS), -1)
		}


		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		; //
		; // FUNCTION NAME: BCrypt.Decrypt
		; //
		; // This function decrypts a block of data.
		; //
		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		static Decrypt(hKey, InputBuf, InputSize, IVBuf := 0, IVSize := 0, &OutputBuf := 0, Flags := 0)
		{
			NT_STATUS := DllCall("bcrypt\BCryptDecrypt", "Ptr",   hKey
			                                           , "Ptr",   InputBuf
			                                           , "UInt",  InputSize
			                                           , "Ptr",   0
			                                           , "Ptr",   IVBuf
			                                           , "UInt",  IVSize
			                                           , "Ptr",   0
			                                           , "UInt",  0
			                                           , "UInt*", &Result := 0
			                                           , "UInt",  Flags
			                                           , "UInt")

			if (NT_STATUS != this.NT.SUCCESS)
				throw Error(this.GetErrorMessage(NT_STATUS), -1)

			OutputBuf := Buffer(Result, 0)
			NT_STATUS := DllCall("bcrypt\BCryptDecrypt", "Ptr",   hKey
			                                           , "Ptr",   InputBuf
			                                           , "UInt",  InputSize
			                                           , "Ptr",   0
			                                           , "Ptr",   IVBuf
			                                           , "UInt",  IVSize
			                                           , "Ptr",   OutputBuf
			                                           , "UInt",  OutputBuf.Size
			                                           , "UInt*", &Result := 0
			                                           , "UInt",  Flags
			                                           , "UInt")

			if (NT_STATUS = this.NT.SUCCESS)
				return OutputBuf.Size
			throw Error(this.GetErrorMessage(NT_STATUS), -1)
		}


		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		; //
		; // FUNCTION NAME: BCrypt.DeriveKeyPBKDF2
		; //
		; // This function derives a key from a hash value by using the PBKDF2 key derivation algorithm as defined by RFC 2898.
		; //
		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		static DeriveKeyPBKDF2(hAlgorithm, Pass, Salt, Iterations, DerivedKey, Encoding := "UTF-8")
		{
			Passwd := CNG.StrBuf(Pass, Encoding)
			Salt   := CNG.StrBuf(Salt, Encoding)
			DKey   := Buffer(DerivedKey, 0)

			NT_STATUS := DllCall("bcrypt\BCryptDeriveKeyPBKDF2", "Ptr",   hAlgorithm
			                                                   , "Ptr",   Passwd
			                                                   , "UInt",  Passwd.Size - 1
			                                                   , "Ptr",   Salt
			                                                   , "UInt",  Salt.Size - 1
			                                                   , "Int64", Iterations
			                                                   , "Ptr",   DKey
			                                                   , "UInt",  DerivedKey
			                                                   , "UInt",  Flags := 0
			                                                   , "UInt")

			if (NT_STATUS = this.NT.SUCCESS)
				return DKey
			throw Error(this.GetErrorMessage(NT_STATUS), -1)
		}


		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		; //
		; // FUNCTION NAME: BCrypt.DestroyHash
		; //
		; // This function destroys a hash or Message Authentication Code (MAC) object.
		; //
		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		static DestroyHash(hHash)
		{
			NT_STATUS := DllCall("bcrypt\BCryptDestroyHash", "Ptr", hHash, "UInt")

			if (NT_STATUS = this.NT.SUCCESS)
				return true
			throw Error(this.GetErrorMessage(NT_STATUS), -1)
		}


		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		; //
		; // FUNCTION NAME: BCrypt.DestroyKey
		; //
		; // This function destroys a key.
		; //
		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		static DestroyKey(hKey)
		{
			NT_STATUS := DllCall("bcrypt\BCryptDestroyKey", "Ptr", hKey, "UInt")

			if (NT_STATUS = this.NT.SUCCESS)
				return true
			throw Error(this.GetErrorMessage(NT_STATUS), -1)
		}


		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		; //
		; // FUNCTION NAME: BCrypt.Encrypt
		; //
		; // This function encrypts a block of data.
		; //
		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		static Encrypt(hKey, InputBuf, InputSize, IVBuf := 0, IVSize := 0, &OutputBuf := 0, Flags := 0)
		{
			NT_STATUS := DllCall("bcrypt\BCryptEncrypt", "Ptr",   hKey
			                                           , "Ptr",   InputBuf
			                                           , "UInt",  InputSize
			                                           , "Ptr",   0
			                                           , "Ptr",   IVBuf
			                                           , "UInt",  IVSize
			                                           , "Ptr",   0
			                                           , "UInt",  0
			                                           , "UInt*", &Result := 0
			                                           , "UInt",  Flags
			                                           , "UInt")

			if (NT_STATUS != this.NT.SUCCESS)
				throw Error(this.GetErrorMessage(NT_STATUS), -1)

			OutputBuf := Buffer(Result, 0)
			NT_STATUS := DllCall("bcrypt\BCryptEncrypt", "Ptr",   hKey
			                                           , "Ptr",   InputBuf
			                                           , "UInt",  InputSize
			                                           , "Ptr",   0
			                                           , "Ptr",   IVBuf
			                                           , "UInt",  IVSize
			                                           , "Ptr",   OutputBuf
			                                           , "UInt",  OutputBuf.Size
			                                           , "UInt*", &Result := 0
			                                           , "UInt",  Flags
			                                           , "UInt")

			if (NT_STATUS = this.NT.SUCCESS)
				return OutputBuf.Size
			throw Error(this.GetErrorMessage(NT_STATUS), -1)
		}


		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		; //
		; // FUNCTION NAME: BCrypt.FinishHash
		; //
		; // This function retrieves the hash or Message Authentication Code (MAC) value for the data accumulated from prior calls to BCrypt.HashData.
		; //
		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		static FinishHash(hHash, &Buf, Size)
		{
			Buf := Buffer(Size, 0)
			NT_STATUS := DllCall("bcrypt\BCryptFinishHash", "Ptr",  hHash
			                                              , "Ptr",  Buf
			                                              , "UInt", Size
			                                              , "UInt", Flags := 0
			                                              , "UInt")

			if (NT_STATUS = this.NT.SUCCESS)
				return Size
			throw Error(this.GetErrorMessage(NT_STATUS), -1)
		}


		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		; //
		; // FUNCTION NAME: BCrypt.GenerateSymmetricKey
		; //
		; // This function creates a key object for use with a symmetrical key encryption algorithm from a supplied key.
		; //
		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		static GenerateSymmetricKey(hAlgorithm, Buf := 0, Size := 0)
		{
			NT_STATUS := DllCall("bcrypt\BCryptGenerateSymmetricKey", "Ptr",  hAlgorithm
			                                                        , "Ptr*", &hKey := 0
			                                                        , "Ptr",  0
			                                                        , "UInt", 0
			                                                        , "Ptr",  Buf
			                                                        , "UInt", Size
			                                                        , "UInt", Flags := 0
			                                                        , "UInt")

			if (NT_STATUS = this.NT.SUCCESS)
				return hKey
			throw Error(this.GetErrorMessage(NT_STATUS), -1)
		}


		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		; //
		; // FUNCTION NAME: BCrypt.GetProperty
		; //
		; // This function retrieves the value of a named property for a CNG object.
		; //
		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		static GetProperty(hObject, Property, Size)
		{
			NT_STATUS := DllCall("bcrypt\BCryptGetProperty", "Ptr",   hObject
			                                               , "Ptr",   StrPtr(Property)
			                                               , "Ptr*",  &Buf := 0
			                                               , "UInt",  Size
			                                               , "UInt*", &Result := 0
			                                               , "UInt",  Flags := 0
			                                               , "UInt")

			if (NT_STATUS = this.NT.SUCCESS)
				return Buf
			throw Error(this.GetErrorMessage(NT_STATUS), -1)
		}


		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		; //
		; // FUNCTION NAME: BCrypt.HashData
		; //
		; // This function performs a one way hash or Message Authentication Code (MAC) on a data buffer.
		; //
		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		static HashData(hHash, Buf, Size)
		{
			NT_STATUS := DllCall("bcrypt\BCryptHashData", "Ptr",  hHash
			                                            , "Ptr",  Buf
			                                            , "UInt", Size
			                                            , "UInt", Flags := 0
			                                            , "UInt")

			if (NT_STATUS = this.NT.SUCCESS)
				return true
			throw Error(this.GetErrorMessage(NT_STATUS), -1)
		}


		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		; //
		; // FUNCTION NAME: BCrypt.OpenAlgorithmProvider
		; //
		; // This function loads and initializes a CNG provider.
		; //
		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		static OpenAlgorithmProvider(AlgId, Flags := 0)
		{
			NT_STATUS := DllCall("bcrypt\BCryptOpenAlgorithmProvider", "Ptr*", &hAlgorithm := 0
			                                                         , "Str",  AlgId
			                                                         , "Ptr",  Implementation := 0
			                                                         , "UInt", Flags
			                                                         , "UInt")

			if (NT_STATUS = this.NT.SUCCESS)
				return hAlgorithm
			throw Error(this.GetErrorMessage(NT_STATUS), -1)
		}


		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		; //
		; // FUNCTION NAME: BCrypt.SetProperty
		; //
		; // This function sets the value of a named property for a CNG object.
		; //
		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		static SetProperty(hObject, Property, Input)
		{
			NT_STATUS := DllCall("bcrypt\BCryptSetProperty", "Ptr",  hObject
			                                               , "Ptr",  StrPtr(Property)
			                                               , "Ptr",  StrPtr(Input)
			                                               , "UInt", StrLen(Input)
			                                               , "UInt", Flags := 0
			                                               , "UInt")

			if (NT_STATUS = this.NT.SUCCESS)
				return true
			throw Error(this.GetErrorMessage(NT_STATUS), -1)
		}


		static GetErrorMessage(STATUS_CODE)
		{
			switch STATUS_CODE
			{
				case this.NT.AUTH_TAG_MISMATCH:
					return "The computed authentication tag did not match the input authentication tag."
				case this.NT.BUFFER_TOO_SMALL:
					return "The buffer is too small to contain the entry. No information has been written to the buffer."
				case this.NT.INVALID_BUFFER_SIZE:
					return "The size of the buffer is invalid for the specified operation."
				case this.NT.INVALID_HANDLE:
					return "An invalid HANDLE was specified."
				case this.NT.INVALID_PARAMETER:
					return "An invalid parameter was passed to a service or function."
				case this.NT.NOT_FOUND:
					return "The object was not found."
				case this.NT.NOT_SUPPORTED:
					return "The request is not supported."
				case this.NT.NO_MEMORY:
					return "Not enough virtual memory or paging file quota is available to complete the specified operation."
				default:
					return "BCrypt failed " STATUS_CODE
			}
		}


		class Constants
		{
			static BCRYPT_ALG_HANDLE_HMAC_FLAG            := 0x00000008
			static BCRYPT_HASH_REUSABLE_FLAG              := 0x00000020
			static BCRYPT_BLOCK_PADDING                   := 0x00000001


			; AlgOperations flags for use with BCryptEnumAlgorithms()
			static BCRYPT_CIPHER_OPERATION                := 0x00000001
			static BCRYPT_HASH_OPERATION                  := 0x00000002
			static BCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION := 0x00000004
			static BCRYPT_SECRET_AGREEMENT_OPERATION      := 0x00000008
			static BCRYPT_SIGNATURE_OPERATION             := 0x00000010
			static BCRYPT_RNG_OPERATION                   := 0x00000020
			static BCRYPT_KEY_DERIVATION_OPERATION        := 0x00000040


			; https://docs.microsoft.com/en-us/windows/win32/seccng/cng-algorithm-identifiers
			static BCRYPT_3DES_ALGORITHM                  := "3DES"
			static BCRYPT_3DES_112_ALGORITHM              := "3DES_112"
			static BCRYPT_AES_ALGORITHM                   := "AES"
			static BCRYPT_AES_CMAC_ALGORITHM              := "AES-CMAC"
			static BCRYPT_AES_GMAC_ALGORITHM              := "AES-GMAC"
			static BCRYPT_DES_ALGORITHM                   := "DES"
			static BCRYPT_DESX_ALGORITHM                  := "DESX"
			static BCRYPT_MD2_ALGORITHM                   := "MD2"
			static BCRYPT_MD4_ALGORITHM                   := "MD4"
			static BCRYPT_MD5_ALGORITHM                   := "MD5"
			static BCRYPT_RC2_ALGORITHM                   := "RC2"
			static BCRYPT_RC4_ALGORITHM                   := "RC4"
			static BCRYPT_RNG_ALGORITHM                   := "RNG"
			static BCRYPT_SHA1_ALGORITHM                  := "SHA1"
			static BCRYPT_SHA256_ALGORITHM                := "SHA256"
			static BCRYPT_SHA384_ALGORITHM                := "SHA384"
			static BCRYPT_SHA512_ALGORITHM                := "SHA512"
			static BCRYPT_PBKDF2_ALGORITHM                := "PBKDF2"
			static BCRYPT_XTS_AES_ALGORITHM               := "XTS-AES"


			; https://docs.microsoft.com/en-us/windows/win32/seccng/cng-property-identifiers
			static BCRYPT_BLOCK_LENGTH                    := "BlockLength"
			static BCRYPT_CHAINING_MODE                   := "ChainingMode"
			static BCRYPT_CHAIN_MODE_CBC                  := "ChainingModeCBC"
			static BCRYPT_CHAIN_MODE_CCM                  := "ChainingModeCCM"
			static BCRYPT_CHAIN_MODE_CFB                  := "ChainingModeCFB"
			static BCRYPT_CHAIN_MODE_ECB                  := "ChainingModeECB"
			static BCRYPT_CHAIN_MODE_GCM                  := "ChainingModeGCM"
			static BCRYPT_HASH_LENGTH                     := "HashDigestLength"
			static BCRYPT_OBJECT_LENGTH                   := "ObjectLength"
		}


		class NT
		{
			static SUCCESS             := 0x00000000
			static AUTH_TAG_MISMATCH   := 0xC000A002
			static BUFFER_TOO_SMALL    := 0xC0000023
			static INVALID_BUFFER_SIZE := 0xC0000206
			static INVALID_HANDLE      := 0xC0000008
			static INVALID_PARAMETER   := 0xC000000D
			static NO_MEMORY           := 0xC0000017
			static NOT_FOUND           := 0xC0000225
			static NOT_SUPPORTED       := 0xC00000BB
		}


		static EncryptionAlgorithm(Algorithm)
		{
			switch Algorithm
			{
				case "AES": return this.Constants.BCRYPT_AES_ALGORITHM
				case "DES": return this.Constants.BCRYPT_DES_ALGORITHM
				case "RC2": return this.Constants.BCRYPT_RC2_ALGORITHM
				case "RC4": return this.Constants.BCRYPT_RC4_ALGORITHM
				default: return ""
			}
		}


		static ChainingMode(ChainMode)
		{
			switch ChainMode
			{
				case "CBC", "ChainingModeCBC": return this.Constants.BCRYPT_CHAIN_MODE_CBC
				case "ECB", "ChainingModeECB": return this.Constants.BCRYPT_CHAIN_MODE_ECB
				default: return ""
			}
		}


		static HashAlgorithm(Algorithm)
		{
			switch Algorithm
			{
				case "MD2":               return this.Constants.BCRYPT_MD2_ALGORITHM
				case "MD4":               return this.Constants.BCRYPT_MD4_ALGORITHM
				case "MD5":               return this.Constants.BCRYPT_MD5_ALGORITHM
				case "SHA1", "SHA-1":     return this.Constants.BCRYPT_SHA1_ALGORITHM
				case "SHA256", "SHA-256": return this.Constants.BCRYPT_SHA256_ALGORITHM
				case "SHA384", "SHA-384": return this.Constants.BCRYPT_SHA384_ALGORITHM
				case "SHA512", "SHA-512": return this.Constants.BCRYPT_SHA512_ALGORITHM
				default: return ""
			}
		}
	}


	; =======================================================================================================================================================================


	class Crypt
	{

		#DllLoad "*i crypt32.dll"


		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		; //
		; // FUNCTION NAME: Crypt.BinaryToString
		; //
		; // This function converts an array of bytes into a formatted string.
		; //
		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		static BinaryToString(BufIn, SizeIn, Flags := "BASE64")
		{
			static CRYPT_STRING :=  { BASE64: 0x1, BINARY: 0x2, HEX: 0x4, HEXRAW: 0xc }
			static CRYPT_STRING_NOCRLF := 0x40000000

			if !(DllCall("crypt32\CryptBinaryToStringW", "Ptr",   BufIn
			                                           , "UInt",  SizeIn
			                                           , "UInt",  (CRYPT_STRING.%Flags% | CRYPT_STRING_NOCRLF)
			                                           , "Ptr",   0
			                                           , "UInt*", &Size := 0))
				throw Error("Can't compute the destination buffer size, error: " A_LastError, -1)

			BufOut := Buffer(Size << 1, 0)
			if !(DllCall("crypt32\CryptBinaryToStringW", "Ptr",   BufIn
			                                           , "UInt",  SizeIn
			                                           , "UInt",  (CRYPT_STRING.%Flags% | CRYPT_STRING_NOCRLF)
			                                           , "Ptr",   BufOut
			                                           , "UInt*", Size))
				throw Error("Can't convert source buffer to " Flags ", error: " A_LastError, -1)

			return StrGet(BufOut)
		}


		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		; //
		; // FUNCTION NAME: Crypt.StringToBinary
		; //
		; // This function converts a formatted string into an array of bytes.
		; //
		; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		static StringToBinary(String, &Binary, Flags := "BASE64")
		{
			static CRYPT_STRING := { BASE64: 0x1, BINARY: 0x2, HEX: 0x4, HEXRAW: 0xc }

			if !(DllCall("crypt32\CryptStringToBinaryW", "Ptr",   StrPtr(String)
			                                           , "UInt",  0
			                                           , "UInt",  CRYPT_STRING.%Flags%
			                                           , "Ptr",   0
			                                           , "UInt*", &Size := 0
			                                           , "Ptr",   0
			                                           , "Ptr",   0))
				throw Error("Can't compute the destination buffer size, error: " A_LastError, -1)

			Binary := Buffer(Size, 0)
			if !(DllCall("crypt32\CryptStringToBinaryW", "Ptr",   StrPtr(String)
			                                           , "UInt",  0
			                                           , "UInt",  CRYPT_STRING.%Flags%
			                                           , "Ptr",   Binary
			                                           , "UInt*", Binary.Size
			                                           , "Ptr",   0
			                                           , "Ptr",   0))
				throw Error("Can't convert source buffer to " Flags ", error: " A_LastError, -1)

			return Binary.Size
		}
	}


	; =======================================================================================================================================================================


	static StrBuf(Str, Encoding := "UTF-8")
	{
		Buf := Buffer(StrPut(Str, Encoding))
		StrPut(Str, Buf, Encoding)
		return Buf
	}

}

; ===========================================================================================================================================================================
