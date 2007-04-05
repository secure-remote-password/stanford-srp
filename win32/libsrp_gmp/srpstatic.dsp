# Microsoft Developer Studio Project File - Name="srpstatic" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=srpstatic - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "srpstatic.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "srpstatic.mak" CFG="srpstatic - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "srpstatic - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "srpstatic - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "srpstatic - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "srpstatic___Win32_Release"
# PROP BASE Intermediate_Dir "srpstatic___Win32_Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "srpstatic___Win32_Release"
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

!ELSEIF  "$(CFG)" == "srpstatic - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "srpstatic___Win32_Debug"
# PROP BASE Intermediate_Dir "srpstatic___Win32_Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "srpstatic___Win32_Debug"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /YX /FD /GZ /c
# ADD CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /I "." /I "../include" /D "_DEBUG" /D "WIN32" /D "_MBCS" /D "_LIB" /D "HAVE_CONFIG_H" /YX /FD /GZ /c
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

# Name "srpstatic - Win32 Release"
# Name "srpstatic - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=..\..\libsrp\cstr.c
# End Source File
# Begin Source File

SOURCE=..\..\libsrp\rfc2945_client.c
# End Source File
# Begin Source File

SOURCE=..\..\libsrp\rfc2945_server.c
# End Source File
# Begin Source File

SOURCE=..\..\libsrp\srp.c
# End Source File
# Begin Source File

SOURCE=..\..\libsrp\srp6_client.c
# End Source File
# Begin Source File

SOURCE=..\..\libsrp\srp6_server.c
# End Source File
# Begin Source File

SOURCE=..\..\libsrp\t_client.c
# End Source File
# Begin Source File

SOURCE=..\..\libsrp\t_conf.c
# End Source File
# Begin Source File

SOURCE=..\..\libsrp\t_conv.c
# End Source File
# Begin Source File

SOURCE=..\..\libsrp\t_getpass.c
# End Source File
# Begin Source File

SOURCE=..\..\libsrp\t_math.c
# End Source File
# Begin Source File

SOURCE=..\..\libsrp\t_misc.c
# End Source File
# Begin Source File

SOURCE=..\..\libsrp\t_pw.c
# End Source File
# Begin Source File

SOURCE=..\..\libsrp\t_read.c
# End Source File
# Begin Source File

SOURCE=..\..\libsrp\t_server.c
# End Source File
# Begin Source File

SOURCE=..\..\libsrp\t_sha.c
# End Source File
# Begin Source File

SOURCE=..\..\libsrp\t_truerand.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=.\config.h
# End Source File
# Begin Source File

SOURCE=..\..\libsrp\cstr.h
# End Source File
# Begin Source File

SOURCE=..\..\libsrp\srp.h
# End Source File
# Begin Source File

SOURCE=..\..\libsrp\t_client.h
# End Source File
# Begin Source File

SOURCE=..\..\libsrp\t_defines.h
# End Source File
# Begin Source File

SOURCE=..\..\libsrp\t_pwd.h
# End Source File
# Begin Source File

SOURCE=..\..\libsrp\t_read.h
# End Source File
# Begin Source File

SOURCE=..\..\libsrp\t_server.h
# End Source File
# Begin Source File

SOURCE=..\..\libsrp\t_sha.h
# End Source File
# End Group
# End Target
# End Project
