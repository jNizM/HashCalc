; ===================================================================================
; AHK Version ...: AHK_L 1.1.13.01 x64 Unicode
; Win Version ...: Windows 7 Professional x64 SP1
; Description ...: Calculate hash from string to
;                  MD2, MD4, MD5, SHA1, SHA-256, SHA-384, SHA-512
; Version .......: 2013.12.17-1337
; Author ........: jNizM
; License .......: WTFPL
; License URL ...: http://www.wtfpl.net/txt/copying/
; ===================================================================================
;@Ahk2Exe-SetName HashCalc v0.1
;@Ahk2Exe-SetDescription HashCalc
;@Ahk2Exe-SetVersion 2013.12.17-1337
;@Ahk2Exe-SetCopyright Copyright (c) 2013`, jNizM
;@Ahk2Exe-SetOrigFilename HashCalc.ahk
; ===================================================================================

; GLOBAL SETTINGS ===================================================================

#Warn
#NoEnv
#SingleInstance Force

; SCRIPT ============================================================================
love := chr(9829)

Gui, Margin, 10, 10
Gui, Font, s9, Courier New
Gui, Add, Text,   xm   ym     w100, Data Format:
Gui, Add, Text,   x+10 ym     w390, Data:
Gui, Add, DropDownList, xm ym+20  w100 AltSubmit vDDL, Text String||
Gui, Add, Edit,   x+10 ym+20  w390 vStr, AutoHotkey
Gui, Add, Checkbox, xm ym+50  w100 h23 vCheck, Salt Hash
Gui, Add, Edit,   x+10 ym+50  w390 vSalt, Salt
Gui, Add, Text,   xm   ym+85  w586 0x10

Gui, Add, Text,   xm   ym+100 w100 h23 0x200, MD2
Gui, Add, Edit,   x+10 ym+100 w390 ReadOnly vMD2,
Gui, Add, Button, x+3  ym+100 w80  h23 -Theme 0x8000 gCopyMD2 vCopyMD2, Copy
Gui, Add, Text,   xm   ym+130 w100 h23 0x200, MD4
Gui, Add, Edit,   x+10 ym+130 w390 ReadOnly vMD4,
Gui, Add, Button, x+3  ym+130 w80  h23 -Theme 0x8000 gCopyMD4 vCopyMD4, Copy
Gui, Add, Text,   xm   ym+160 w100 h23 0x200, MD5
Gui, Add, Edit,   x+10 ym+160 w390 ReadOnly vMD5,
Gui, Add, Button, x+3  ym+160 w80  h23 -Theme 0x8000 gCopyMD5 vCopyMD5, Copy
Gui, Add, Text,   xm   ym+190 w100 h23 0x200, SHA-1
Gui, Add, Edit,   x+10 ym+190 w390 ReadOnly vSHA,
Gui, Add, Button, x+3  ym+190 w80  h23 -Theme 0x8000 gCopySHA vCopySHA, Copy
Gui, Add, Text,   xm   ym+220 w100 h23 0x200, SHA256
Gui, Add, Edit,   x+10 ym+220 w390 ReadOnly vSHA2,
Gui, Add, Button, x+3  ym+220 w80  h23 -Theme 0x8000 gCopySHA2 vCopySHA2, Copy
Gui, Add, Text,   xm   ym+250 w100 h23 0x200, SHA384
Gui, Add, Edit,   x+10 ym+250 w390 ReadOnly vSHA3,
Gui, Add, Button, x+3  ym+250 w80  h23 -Theme 0x8000 gCopySHA3 vCopySHA3, Copy
Gui, Add, Text,   xm   ym+280 w100 h23 0x200, SHA512
Gui, Add, Edit,   x+10 ym+280 w390 ReadOnly vSHA5,
Gui, Add, Button, x+3  ym+280 w80  h23 -Theme 0x8000 gCopySHA5 vCopySHA5, Copy
Gui, Add, Text,   xm   ym+315 w586 0x10

Gui, Add, Text,   xm   ym+330 w100 h23 0x200, Verify
Gui, Add, Edit,   x+10 ym+330 w390 vVerify,
Gui, Add, Edit,   x+3  ym+330 w80 0x201 ReadOnly vHashOK,
Gui, Add, Text,   xm   ym+365 w586 0x10

Gui, Font, cSilver,
Gui, Add, Text,   xm   ym+380 w250 h21 0x200, made with %love% and AHK 2013, jNizM
Gui, Font,,
Gui, Add, Button, xm+337 ym+379 w80 -Theme 0x8000 gCalculate, Calculate
Gui, Add, Button, x+3    ym+379 w80 -Theme 0x8000 gClear, Clear
Gui, Add, Button, x+3    ym+379 w80 -Theme 0x8000 gClose, Close

Gui, Show, AutoSize, HashCalc v0.1
SetTimer, CheckEdit, 100
return

CheckEdit:
    Gui, Submit, NoHide
    GuiControl, % Check = "0" ? "Disable" : "Enable", Salt
    GuiControl, % DDL   = "2" ? "Disable" : "Enable", Check
    GuiControl, % MD2   = ""  ? "Disable" : "Enable", CopyMD2
    GuiControl, % MD4   = ""  ? "Disable" : "Enable", CopyMD4
    GuiControl, % MD5   = ""  ? "Disable" : "Enable", CopyMD5
    GuiControl, % SHA   = ""  ? "Disable" : "Enable", CopySHA
    GuiControl, % SHA2  = ""  ? "Disable" : "Enable", CopySHA2
    GuiControl, % SHA3  = ""  ? "Disable" : "Enable", CopySHA3
    GuiControl, % SHA5  = ""  ? "Disable" : "Enable", CopySHA5
    Goto, VerifyHash
return

Calculate:
    GuiControlGet, DDL
    GuiControlGet, Str
    GuiControlGet, Check
    GuiControlGet, Salt
    GuiControl,, MD2,  % Check = "0" ? MD2(Str)    : SecureSalted("MD2", Str, Salt)
    GuiControl,, MD4,  % Check = "0" ? MD4(Str)    : SecureSalted("MD4", Str, Salt)
    GuiControl,, MD5,  % Check = "0" ? MD5(Str)    : SecureSalted("MD5", Str, Salt)
    GuiControl,, SHA,  % Check = "0" ? SHA(Str)    : SecureSalted("SHA", Str, Salt)
    GuiControl,, SHA2, % Check = "0" ? SHA256(Str) : SecureSalted("SHA256", Str, Salt)
    GuiControl,, SHA3, % Check = "0" ? SHA384(Str) : SecureSalted("SHA384", Str, Salt)
    GuiControl,, SHA5, % Check = "0" ? SHA512(Str) : SecureSalted("SHA512", Str, Salt)
return

Clear:
    GuiControl,, MD2,
    GuiControl,, MD4,
    GuiControl,, MD5,
    GuiControl,, SHA,
    GuiControl,, SHA2,
    GuiControl,, SHA3,
    GuiControl,, SHA5,
return

VerifyHash:
    Gui, Submit, NoHide
    Result := Hashify(Verify, MD2, MD4, MD5, SHA, SHA2, SHA3, SHA5)
    GuiControl, % (InStr(Result,"OK")) ? "+c008000" : "+c800000", HashOK
    GuiControl,, HashOk, %Result%
return

CopyMD2:
    Clipboard := MD2
return
CopyMD4:
    Clipboard := MD4
return
CopyMD5:
    Clipboard := MD5
return
CopySHA:
    Clipboard := SHA
return
CopySHA2:
    Clipboard := SHA2
return
CopySHA3:
    Clipboard := SHA3
return
CopySHA5:
    Clipboard := SHA5
return


Close:
    ExitApp
return


; FUNCTIONS =========================================================================

; Verify ============================================================================
Hashify(Hash, MD2, MD4, MD5, SHA, SHA2, SHA3, SHA5)
{
    return, % (Hash = "") ? "" : (Hash = MD2) ? ("MD2 OK") : (Hash = MD4) ? ("MD4 OK") : (Hash = MD5) ? ("MD5 OK") : (Hash = SHA) ? ("SHA1 OK")
            : (Hash = SHA2) ? ("SHA256 OK") : (Hash = SHA3) ? ("SHA384 OK") : (Hash = SHA5) ? ("SHA512 OK") : "FALSE"
}

; SecureSalted ======================================================================
SecureSalted(algo, data, salt)
{
    hash := ""
    saltedHash := %algo%(data . salt) 
    saltedHashR := %algo%(salt . data)
    len := StrLen(saltedHash)
    loop, % len / 2
    {
        byte1 := "0x" . SubStr(saltedHash, 2 * A_index - 1, 2)
        byte2 := "0x" . SubStr(saltedHashR, 2 * A_index - 1, 2)
        SetFormat, integer, hex
        hash .= StrLen(ns := SubStr(byte1 ^ byte2, 3)) < 2 ? "0" ns : ns
    }
    SetFormat, integer, dez
    return hash
}

; MD2 ===============================================================================
MD2(string)
{
    return HashFromString(string, 0x8001)
}
; MD4 ===============================================================================
MD4(string)
{
    return HashFromString(string, 0x8002)
}
; MD5 ===============================================================================
MD5(string)
{
    return HashFromString(string, 0x8003)
}
; SHA ===============================================================================
SHA(string)
{
    return HashFromString(string, 0x8004)
}
; SHA256 ============================================================================
SHA256(string)
{
    return HashFromString(string, 0x800c)
}
; SHA384 ============================================================================
SHA384(string)
{
    return HashFromString(string, 0x800d)
}
; SHA512 ============================================================================
SHA512(string)
{
    return HashFromString(string, 0x800e)
}

; HashFromAddr ======================================================================
HashFromAddr(pData, len, algid, key = 0)
{
    hProv := size := hHash := hash := ""
    ptr := (A_PtrSize) ? "Ptr" : "UInt"
    aw := (A_IsUnicode) ? "W" : "A"
    if (DllCall("advapi32\CryptAcquireContext", "Ptr*", hProv, "Ptr", 0, "Ptr", 0, "Uint", 24, "UInt", 0xF0000000))
    {
        if (DllCall("advapi32\CryptCreateHash", "Ptr", hProv, "Uint", algid, "Uint", 0, "Uint", 0, "Ptr*", hHash))
        {
            if (DllCall("advapi32\CryptHashData", "Ptr", hHash, "Ptr", pData, "Uint", len, "Uint", 0))
            {
                if (DllCall("advapi32\CryptGetHashParam", "Ptr", hHash, "Uint", 2, "Ptr", 0, "Uint*", size, "Uint", 0))
                {
                    VarSetCapacity(bhash, size, 0)
                    DllCall("advapi32\CryptGetHashParam", "Ptr", hHash, "Uint", 2, "Ptr", &bhash, "Uint*", size, "Uint", 0)
                }
            }
            DllCall("advapi32\CryptDestroyHash", "Ptr", hHash)
        }
        DllCall("advapi32\CryptReleaseContext", "Ptr", hProv, "Uint", 0)
    }
    int := A_FormatInteger
    SetFormat, Integer, h
    loop, % size
    {
        v := substr(NumGet(bhash, A_Index - 1, "UChar") "", 3)
        while (StrLen(v) < 2)
        {
            v := "0" v
        }
        hash .= v
    }
    SetFormat, Integer, % int
    return hash
}

; HashFromString ====================================================================
HashFromString(string, algid, key = 0)
{
    len := StrLen(string)
    if (A_IsUnicode)
    {
        VarSetCapacity(data, len)
        StrPut := "StrPut"
        %StrPut%(string, &data, len, "cp0")
        return HashFromAddr(&data, len, algid, key)
    }
    data := string
    return HashFromAddr(&data, len, algid, key)
}


; EXIT ==============================================================================

GuiClose:
    ExitApp