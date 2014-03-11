; ===================================================================================
; AHK Version ...: AHK_L 1.1.14.02 x64 Unicode
; Win Version ...: Windows 7 Professional x64 SP1
; Description ...: Calculate hash from string or file to
;                  MD2, MD4, MD5, SHA1, SHA-256, SHA-384, SHA-512
;                  HMAC
; Version .......: 2013.12.30-1545
; Author ........: jNizM
; ===================================================================================
;@Ahk2Exe-SetName HashCalc v0.6
;@Ahk2Exe-SetDescription HashCalc
;@Ahk2Exe-SetVersion 2013.12.30-1545
;@Ahk2Exe-SetCopyright Copyright (c) 2013`, jNizM
;@Ahk2Exe-SetOrigFilename HashCalc.ahk
; ===================================================================================

; GLOBAL SETTINGS ===================================================================

#Warn
#NoEnv
#SingleInstance Force
SetBatchLines, -1

; SCRIPT ============================================================================
love := chr(9829)

Gui, Margin, 10, 10
Gui, Font, s9, Courier New
Gui, Add, Text,   xm   ym     w100, Data Format:
Gui, Add, Text,   x+10 ym     w390, Data:
Gui, Add, DropDownList, xm ym+20  w100 AltSubmit vDDL, Text String||File
Gui, Add, Edit,   x+10 ym+20  w390 vStr, AutoHotkey
Gui, Add, Button, x+3  ym+20  w80 h23 -Theme 0x8000 gFile vFile, File
Gui, Add, Checkbox, xm ym+50  w100 h23 vCheck, HMAC
Gui, Add, Edit,   x+10 ym+50  w390 vHMAC, HMAC
Gui, Add, Text,   xm   ym+85  w586 0x10

Gui, Add, Checkbox,   xm   ym+100 w100 h23 vCheckMD2, MD2
Gui, Add, Edit,   x+10 ym+100 w390 0x800 vMD2,
Gui, Add, Button, x+3  ym+100 w80  h23 -Theme 0x8000 gCopyMD2 vCopyMD2, Copy
Gui, Add, Checkbox,   xm   ym+130 w100 h23 vCheckMD4, MD4
Gui, Add, Edit,   x+10 ym+130 w390 0x800 vMD4,
Gui, Add, Button, x+3  ym+130 w80  h23 -Theme 0x8000 gCopyMD4 vCopyMD4, Copy
Gui, Add, Checkbox,   xm   ym+160 w100 h23 Checked vCheckMD5, MD5
Gui, Add, Edit,   x+10 ym+160 w390 0x800 vMD5,
Gui, Add, Button, x+3  ym+160 w80  h23 -Theme 0x8000 gCopyMD5 vCopyMD5, Copy
Gui, Add, Checkbox,   xm   ym+190 w100 h23 Checked vCheckSHA, SHA-1
Gui, Add, Edit,   x+10 ym+190 w390 0x800 vSHA,
Gui, Add, Button, x+3  ym+190 w80  h23 -Theme 0x8000 gCopySHA vCopySHA, Copy
Gui, Add, Checkbox,   xm   ym+220 w100 h23 vCheckSHA2, SHA256
Gui, Add, Edit,   x+10 ym+220 w390 0x800 vSHA2,
Gui, Add, Button, x+3  ym+220 w80  h23 -Theme 0x8000 gCopySHA2 vCopySHA2, Copy
Gui, Add, Checkbox,   xm   ym+250 w100 h23 vCheckSHA3, SHA384
Gui, Add, Edit,   x+10 ym+250 w390 0x800 vSHA3,
Gui, Add, Button, x+3  ym+250 w80  h23 -Theme 0x8000 gCopySHA3 vCopySHA3, Copy
Gui, Add, Checkbox,   xm   ym+280 w100 h23 vCheckSHA5, SHA512
Gui, Add, Edit,   x+10 ym+280 w390 0x800 vSHA5,
Gui, Add, Button, x+3  ym+280 w80  h23 -Theme 0x8000 gCopySHA5 vCopySHA5, Copy
Gui, Add, Text,   xm   ym+315 w586 0x10

Gui, Add, Text,   xm   ym+330 w100 h23 0x200, Verify
Gui, Add, Edit,   x+10 ym+330 w390 vVerify,
Gui, Add, Edit,   x+3  ym+330 w80 0x201 0x800 vHashOK,
Gui, Add, Text,   xm   ym+365 w586 0x10

Gui, Font, cSilver,
Gui, Add, Text,   xm   ym+380 w275 h21 0x200, made with %love% and AHK 2013-%A_YYYY%, jNizM
Gui, Font,,
Gui, Add, Button, xm+337 ym+379 w80 -Theme 0x8000 gCalculate, Calculate
Gui, Add, Button, x+3    ym+379 w80 -Theme 0x8000 gClear, Clear
Gui, Add, Button, x+3    ym+379 w80 -Theme 0x8000 gClose, Close

Gui, Show, AutoSize, HashCalc v0.6
SetTimer, CheckEdit, 100
SetTimer, VerifyHash, 200
return

GuiDropFiles:
    FilePath := A_GuiEvent
    GuiControl,, Str, % FilePath
    GuiControl, Choose, DDL, 2
return

CheckEdit:
    Gui, Submit, NoHide
    GuiControl, % DDL   = "2" ? "Disable" : "Enable",  HMAC
    if !(DDL = 2)
        GuiControl, % Check = "0" ? "Disable" : "Enable",  HMAC
    GuiControl, % DDL   = "2" ? "Disable" : "Enable",  Check
    GuiControl, % DDL   = "2" ? "Enable"  : "Disable", File
    GuiControl, % MD2   = ""  ? "Disable" : "Enable",  CopyMD2
    GuiControl, % MD4   = ""  ? "Disable" : "Enable",  CopyMD4
    GuiControl, % MD5   = ""  ? "Disable" : "Enable",  CopyMD5
    GuiControl, % SHA   = ""  ? "Disable" : "Enable",  CopySHA
    GuiControl, % SHA2  = ""  ? "Disable" : "Enable",  CopySHA2
    GuiControl, % SHA3  = ""  ? "Disable" : "Enable",  CopySHA3
    GuiControl, % SHA5  = ""  ? "Disable" : "Enable",  CopySHA5
return

File:
    FileSelectFile, File
    GuiControl,, Str, %File%
return

Calculate:
    Gui, Submit, NoHide
    GuiControl,, MD2,  % CheckMD2  = "1" ? (DDL = "2" ? FileMD2(Str)    : (Check = "0" ? MD2(Str)    : HMAC(HMAC, Str, "MD2")))    : ""
    GuiControl,, MD4,  % CheckMD4  = "1" ? (DDL = "2" ? FileMD4(Str)    : (Check = "0" ? MD4(Str)    : HMAC(HMAC, Str, "MD4")))    : ""
    GuiControl,, MD5,  % CheckMD5  = "1" ? (DDL = "2" ? FileMD5(Str)    : (Check = "0" ? MD5(Str)    : HMAC(HMAC, Str, "MD5")))    : ""
    GuiControl,, SHA,  % CheckSHA  = "1" ? (DDL = "2" ? FileSHA(Str)    : (Check = "0" ? SHA(Str)    : HMAC(HMAC, Str, "SHA")))    : ""
    GuiControl,, SHA2, % CheckSHA2 = "1" ? (DDL = "2" ? FileSHA256(Str) : (Check = "0" ? SHA256(Str) : HMAC(HMAC, Str, "SHA256"))) : ""
    GuiControl,, SHA3, % CheckSHA3 = "1" ? (DDL = "2" ? FileSHA384(Str) : (Check = "0" ? SHA384(Str) : HMAC(HMAC, Str, "SHA384"))) : ""
    GuiControl,, SHA5, % CheckSHA5 = "1" ? (DDL = "2" ? FileSHA512(Str) : (Check = "0" ? SHA512(Str) : HMAC(HMAC, Str, "SHA512"))) : ""
return

Clear:
    GuiControl,, Str, AutoHotkey
    GuiControl,, HMAC, HMAC
    GuiControl,, MD2,
    GuiControl,, MD4,
    GuiControl,, MD5,
    GuiControl,, SHA,
    GuiControl,, SHA2,
    GuiControl,, SHA3,
    GuiControl,, SHA5,
    GuiControl,, Verify,
return

VerifyHash:
    Gui, Submit, NoHide
    Result := Hashify(Verify, MD2, MD4, MD5, SHA, SHA2, SHA3, SHA5)
    GuiControl, % (InStr(Result, "OK")) ? "+c008000" : "+c800000", HashOK
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

; HMAC ==============================================================================
HMAC(Key, Message, Algo := "MD5")
{
    static Algorithms := {MD2: {ID: 0x8001, Size: 64}
                        , MD4: {ID: 0x8002, Size: 64}
                        , MD5: {ID: 0x8003, Size: 64}
                        , SHA: {ID: 0x8004, Size: 64}
                        , SHA256: {ID: 0x800C, Size: 64}
                        , SHA384: {ID: 0x800D, Size: 128}
                        , SHA512: {ID: 0x800E, Size: 128}}
    static iconst := 0x36
    static oconst := 0x5C
    if !Algorithms.HasKey(Algo)
    {
        return ""
    }
    Hash := InnerHashLen := ""
    HashLen := 0
    AlgID := Algorithms[Algo].ID
    BlockSize := Algorithms[Algo].Size
    MsgLen := StrPut(Message, "UTF-8") - 1
    KeyLen := StrPut(Key, "UTF-8") - 1
    VarSetCapacity(K, KeyLen + 1, 0)
    StrPut(Key, &K, KeyLen, "UTF-8")
    if (KeyLen > BlockSize)
    {
        CalcAddrHash(&K, KeyLen, AlgID, KeyHash, KeyHashLen)
    }

    VarSetCapacity(ipad, BlockSize + MsgLen, iconst)
    Addr := KeyLen > BlockSize ? &KeyHash : &K
    Length := KeyLen > BlockSize ? KeyHashLen : KeyLen
    i := 0
    while (i < Length)
    {
        NumPut(NumGet(Addr + 0, i, "UChar") ^ iconst, ipad, i, "UChar")
        i++
    }
    if (MsgLen)
    {
        StrPut(Message, &ipad + BlockSize, MsgLen, "UTF-8")
    }
    CalcAddrHash(&ipad, BlockSize + MsgLen, AlgID, InnerHash, InnerHashLen)

    VarSetCapacity(opad, BlockSize + InnerHashLen, oconst)
    Addr := KeyLen > BlockSize ? &KeyHash : &K
    Length := KeyLen > BlockSize ? KeyHashLen : KeyLen
    i := 0
    while (i < Length)
    {
        NumPut(NumGet(Addr + 0, i, "UChar") ^ oconst, opad, i, "UChar")
        i++
    }
    Addr := &opad + BlockSize
    i := 0
    while (i < InnerHashLen)
    {
        NumPut(NumGet(InnerHash, i, "UChar"), Addr + i, 0, "UChar")
        i++
    }
    return CalcAddrHash(&opad, BlockSize + InnerHashLen, AlgID)
}

; MD2 ===============================================================================
MD2(string, encoding = "UTF-8")
{
    return CalcStringHash(string, 0x8001, encoding)
}
FileMD2(filename)
{
    return CalcFileHash(filename, 0x8001, 64 * 1024)
}
; MD4 ===============================================================================
MD4(string, encoding = "UTF-8")
{
    return CalcStringHash(string, 0x8002, encoding)
}
FileMD4(filename)
{
    return CalcFileHash(filename, 0x8002, 64 * 1024)
}
; MD5 ===============================================================================
MD5(string, encoding = "UTF-8")
{
    return CalcStringHash(string, 0x8003, encoding)
}
FileMD5(filename)
{
    return CalcFileHash(filename, 0x8003, 64 * 1024)
}
; SHA ===============================================================================
SHA(string, encoding = "UTF-8")
{
    return CalcStringHash(string, 0x8004, encoding)
}
FileSHA(filename)
{
    return CalcFileHash(filename, 0x8004, 64 * 1024)
}
; SHA256 ============================================================================
SHA256(string, encoding = "UTF-8")
{
    return CalcStringHash(string, 0x800c, encoding)
}
FileSHA256(filename)
{
    return CalcFileHash(filename, 0x800c, 64 * 1024)
}
; SHA384 ============================================================================
SHA384(string, encoding = "UTF-8")
{
    return CalcStringHash(string, 0x800d, encoding)
}
FileSHA384(filename)
{
    return CalcFileHash(filename, 0x800d, 64 * 1024)
}
; SHA512 ============================================================================
SHA512(string, encoding = "UTF-8")
{
    return CalcStringHash(string, 0x800e, encoding)
}
FileSHA512(filename)
{
    return CalcFileHash(filename, 0x800e, 64 * 1024)
}

; CalcAddrHash ======================================================================
CalcAddrHash(addr, length, algid, byref hash = 0, byref hashlength = 0)
{
    static h := [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, "a", "b", "c", "d", "e", "f"]
    static b := h.minIndex()
    hProv := hHash := o := ""
    if (DllCall("advapi32\CryptAcquireContext", "Ptr*", hProv, "Ptr", 0, "Ptr", 0, "UInt", 24, "UInt", 0xF0000000))
    {
        if (DllCall("advapi32\CryptCreateHash", "Ptr", hProv, "UInt", algid, "UInt", 0, "UInt", 0, "Ptr*", hHash))
        {
            if (DllCall("advapi32\CryptHashData", "Ptr", hHash, "Ptr", addr, "UInt", length, "UInt", 0))
            {
                if (DllCall("advapi32\CryptGetHashParam", "Ptr", hHash, "UInt", 2, "Ptr", 0, "UInt*", hashlength, "UInt", 0))
                {
                    VarSetCapacity(hash, hashlength, 0)
                    if (DllCall("advapi32\CryptGetHashParam", "Ptr", hHash, "UInt", 2, "Ptr", &hash, "UInt*", hashlength, "UInt", 0))
                    {
                        loop, % hashlength
                        {
                            v := NumGet(hash, A_Index - 1, "UChar")
                            o .= h[(v >> 4) + b] h[(v & 0xf) + b]
                        }
                    }
                }
            }
            DllCall("advapi32\CryptDestroyHash", "Ptr", hHash)
        }
        DllCall("advapi32\CryPtreleaseContext", "Ptr", hProv, "UInt", 0)
    }
    return o
}

; CalcStringHash ====================================================================
CalcStringHash(string, algid, encoding = "UTF-8", byref hash = 0, byref hashlength = 0)
{
    chrlength := (encoding = "CP1200" || encoding = "UTF-16") ? 2 : 1
    length := (StrPut(string, encoding) - 1) * chrlength
    VarSetCapacity(data, length, 0)
    StrPut(string, &data, floor(length / chrlength), encoding)
    return CalcAddrHash(&data, length, algid, hash, hashlength)
}

; CalcFileHash ======================================================================
CalcFileHash(filename, algid, continue = 0, byref hash = 0, byref hashlength = 0)
{
    fpos := ""
    if (!(f := FileOpen(filename, "r")))
    {
        return
    }
    f.pos := 0
    if (!continue && f.length > 0x7fffffff)
    {
        return
    }
    if (!continue)
    {
        VarSetCapacity(data, f.length, 0)
        f.rawRead(&data, f.length)
        f.pos := oldpos
        return CalcAddrHash(&data, f.length, algid, hash, hashlength)
    }
    hashlength := 0
    while (f.pos < f.length)
    {
        readlength := (f.length - fpos > continue) ? continue : f.length - f.pos
        VarSetCapacity(data, hashlength + readlength, 0)
        DllCall("RtlMoveMemory", "Ptr", &data, "Ptr", &hash, "Ptr", hashlength)
        f.rawRead(&data + hashlength, readlength)
        h := CalcAddrHash(&data, hashlength + readlength, algid, hash, hashlength)
    }
    return h
}


; EXIT ==============================================================================

GuiClose:
    ExitApp