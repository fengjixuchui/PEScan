!IF "$(PLATFORM)"=="X64" || "$(PLATFORM)"=="x64"
ARCH=amd64
!ELSE
ARCH=x86
!ENDIF

OUTDIR=bin\$(ARCH)
OBJDIR=obj\$(ARCH)
DIASDK_DIR=C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\DIA SDK

CC=cl
RD=rd /s /q
RM=del /q
LINKER=link
TARGET=pescan.exe

OBJS=\
	$(OBJDIR)\main.obj\
	$(OBJDIR)\filemapping.obj\

LIBS=\
	diaguids.lib\

CFLAGS=\
	/nologo\
	/c\
	/DUNICODE\
	/O2\
	/W4\
	/Zi\
	/EHsc\
	/Fo"$(OBJDIR)\\"\
	/Fd"$(OBJDIR)\\"\
	/wd4100\
	/I"$(DIASDK_DIR)\include"\

LFLAGS=\
	/NOLOGO\
	/DEBUG\
	/SUBSYSTEM:CONSOLE\
!IF "$(PLATFORM)"=="X64" || "$(PLATFORM)"=="x64"
	/LIBPATH:"$(DIASDK_DIR)\lib\amd64"\
!ELSE
	/LIBPATH:"$(DIASDK_DIR)\lib"\
!ENDIF

all: $(OUTDIR)\$(TARGET)

$(OUTDIR)\$(TARGET): $(OBJS)
	@if not exist $(OUTDIR) mkdir $(OUTDIR)
	$(LINKER) $(LFLAGS) $(LIBS) /PDB:"$(@R).pdb" /OUT:$@ $**

.cpp{$(OBJDIR)}.obj:
	@if not exist $(OBJDIR) mkdir $(OBJDIR)
	$(CC) $(CFLAGS) $<

clean:
	@if exist $(OBJDIR) $(RD) $(OBJDIR)
	@if exist $(OUTDIR)\$(TARGET) $(RM) $(OUTDIR)\$(TARGET)
	@if exist $(OUTDIR)\$(TARGET:exe=ilk) $(RM) $(OUTDIR)\$(TARGET:exe=ilk)
	@if exist $(OUTDIR)\$(TARGET:exe=pdb) $(RM) $(OUTDIR)\$(TARGET:exe=pdb)
