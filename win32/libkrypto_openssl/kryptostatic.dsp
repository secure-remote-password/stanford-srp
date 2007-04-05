# Microsoft Developer Studio Project File - Name="kryptostatic" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=kryptostatic - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "kryptostatic.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "kryptostatic.mak" CFG="kryptostatic - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "kryptostatic - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "kryptostatic - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "kryptostatic - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "kryptostatic___Win32_Release"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /YX /FD /c
# ADD CPP /nologo /MT /W3 /GX /O2 /I "." /I "../include" /D "NDEBUG" /D "WIN32" /D "_MBCS" /D "_LIB" /D "HAVE_CONFIG_H" /YX /FD /c
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ELSEIF  "$(CFG)" == "kryptostatic - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "kryptostatic___Win32_Debug"
# PROP BASE Intermediate_Dir "kryptostatic___Win32_Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "kryptostatic___Win32_Debug"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /YX /FD /GZ  /c
# ADD CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /I "." /I "../include" /D "_DEBUG" /D "WIN32" /D "_MBCS" /D "_LIB" /D "HAVE_CONFIG_H" /YX /FD /GZ  /c
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ENDIF 

# Begin Target

# Name "kryptostatic - Win32 Release"
# Name "kryptostatic - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=..\..\libkrypto\cipher.c
# End Source File
# Begin Source File

SOURCE=..\..\libkrypto\cipher_crypt_cbc.c
# End Source File
# Begin Source File

SOURCE=..\..\libkrypto\cipher_crypt_cfb.c
# End Source File
# Begin Source File

SOURCE=..\..\libkrypto\cipher_crypt_ecb.c
# End Source File
# Begin Source File

SOURCE=..\..\libkrypto\cipher_crypt_ofb.c
# End Source File
# Begin Source File

SOURCE=..\..\libkrypto\cipher_imp_blowfish.c
# End Source File
# Begin Source File

SOURCE=..\..\libkrypto\cipher_imp_cast.c
# End Source File
# Begin Source File

SOURCE=..\..\libkrypto\cipher_imp_des.c
# End Source File
# Begin Source File

SOURCE=..\..\libkrypto\cipher_imp_none.c
# End Source File
# Begin Source File

SOURCE=..\..\libkrypto\hash.c
# End Source File
# Begin Source File

SOURCE=..\..\libkrypto\hash_imp_md5.c
# End Source File
# Begin Source File

SOURCE=..\..\libkrypto\hash_imp_sha.c
# End Source File
# Begin Source File

SOURCE=..\..\libkrypto\krypto.c
# End Source File
# Begin Source File

SOURCE=..\..\libkrypto\krypto_rand_conf.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=..\..\libkrypto\cipher_imp_blowfish.h
# End Source File
# Begin Source File

SOURCE=..\..\libkrypto\cipher_imp_cast.h
# End Source File
# Begin Source File

SOURCE=..\..\libkrypto\cipher_imp_des.h
# End Source File
# Begin Source File

SOURCE=.\config.h
# End Source File
# Begin Source File

SOURCE=..\..\libkrypto\hash_imp_md5.h
# End Source File
# Begin Source File

SOURCE=..\..\libkrypto\hash_imp_sha.h
# End Source File
# Begin Source File

SOURCE=..\..\libkrypto\krypto.h
# End Source File
# Begin Source File

SOURCE=..\..\libkrypto\krypto_locl.h
# End Source File
# End Group
# End Target
# End Project
