/*++

 Visual Data Tracer v1.0 Alpha
 Copyright (C) 2008-2010  
	Rodrigo Rubira Branco (BSDaemon) <rodrigo@risesecurity.org>
	Julio Auto <julio@julioauto.com>

 This is the tracing module of Visual Data Tracer. It's a WinDbg extension
 that dumps the execution trace in a format that is suitable to be later
 consumed by the VDT GUI.

 Module Name:

    vdt-tracer.cpp

--*/

#include <ntverp.h>
#include <time.h>
#include <string.h>
#include <assert.h>
#include <memory>
#include <map>

using namespace std;

#include "vdt-tracer.h"

//
// globals
//
EXT_API_VERSION         ApiVersion = { (VER_PRODUCTVERSION_W >> 8), (VER_PRODUCTVERSION_W & 0xff), EXT_API_VERSION_NUMBER64, 0 };
WINDBG_EXTENSION_APIS   ExtensionApis;
ULONG SavedMajorVersion;
ULONG SavedMinorVersion;


HRESULT
CALLBACK
DebugExtensionInitialize(
	OUT PULONG  Version,
	OUT PULONG  Flags
	)
{
	IDebugClient *DebugClient;
    PDEBUG_CONTROL DebugControl;
    HRESULT Hr;

    *Version = DEBUG_EXTENSION_VERSION(1, 0);
    *Flags = 0;
    Hr = S_OK;

    if ((Hr = DebugCreate(__uuidof(IDebugClient),
                          (void **)&DebugClient)) != S_OK)
    {
        return Hr;
    }

    if ((Hr = DebugClient->QueryInterface(__uuidof(IDebugControl),
                                  (void **)&DebugControl)) == S_OK)
    {

        //
        // Get the windbg-style extension APIS
        //
        ExtensionApis.nSize = sizeof (ExtensionApis);
        Hr = DebugControl->GetWindbgExtensionApis64(&ExtensionApis);

        DebugControl->Release();

    }
    DebugClient->Release();

	vdt_initmap();

    return Hr;
}



/***********************************************************
 * !vdt_help
 *
 * Purpose: Display usage help
 *          
 *
 *  Parameters:
 *     N/A
 *
 *  Return Values:
 *     N/A
 *
 ***********************************************************/
HRESULT
CALLBACK
vdt_help(PDEBUG_CLIENT Client, PCSTR args)
{
    dprintf("Visual Data Tracer v1.0 Alpha - Copyright (C) 2008-2010\n" \
			"License: This software was created as companion to a Phrack Article.\n" \
			"Developed by Rodrigo Rubira Branco (BSDaemon) <rodrigo@risesecurity.org> and \nJulio Auto <julio@julioauto.com>\n\n");

	dprintf("!vdt_trace <filename>                                  - trace the program until a breakpoint or exception and save the trace\n" \
			"                                                       in a file to be later consumed by the Visual Data Tracer GUI.\n" \
			"!vdt_help											- this help screen											\n");

	return S_OK;
}

typedef union
{
	CHAR Str[256];
	struct
	{
		CHAR Mnem[8];
		CHAR Dst[16];
		CHAR Src[16];
		CHAR SrcDep1[4];
		CHAR SrcDep2[4];
		CHAR SrcDep3[4];
		CHAR Disas[204];
	} Members;

} VdtEntry;

enum VDT_OPERANDS
{
	VDT_SRC,
	VDT_DST
};

inline HRESULT VdtParseOperands(VdtEntry *Entry, CHAR *RawOps, PDEBUG_REGISTERS2 Registers2, VDT_OPERANDS Type)
{	
	size_t CharsCopied = 0;

	if (Type == VDT_SRC)
	{
		Entry->Members.SrcDep1[0] = '\0';
		Entry->Members.SrcDep2[0] = '\0';
		Entry->Members.SrcDep3[0] = '\0';

		// Offset (resolved constant)
		if (RawOps[0] == 'o')
		{
			CHAR *TempStr = strchr(RawOps, '(');
			assert(TempStr != 0);

			// We always have 8 digits here
			strncpy(Entry->Members.Src, TempStr+1, 8);
			CharsCopied = 8;
		}
		// Constant number
		else if (RawOps[0] >= 0x30 && RawOps[0] <= 0x39)
		{
			CharsCopied = strspn(RawOps, "1234567890ABCDEF");
			strncpy(Entry->Members.Src, RawOps, CharsCopied);
		}
		// Pointer
		else if (strstr(RawOps, "ptr"))
		{			
			// Get from context: $ea (and $ea2 for rightmost param, if applicable)
			ULONG RegIndex;
			DEBUG_VALUE RegValue;
			if (Registers2->GetPseudoIndexByName("$ea", &RegIndex) != S_OK)
			{
				dprintf("Error: Could not get $ea index\n");
				return S_FALSE;
			}
			if (Registers2->GetPseudoValues(DEBUG_REGSRC_DEBUGGEE, 1, NULL, RegIndex, &RegValue) != S_OK)
			{
				dprintf("Error: Could not get $ea value\n");
				return S_FALSE;
			}

			sprintf(Entry->Members.Src, "*%08x", RegValue.I32);
			CharsCopied = 9;

			// If it's not a symbol, parse for register dependence - only for SRC operands
			CHAR *PtrBegin = strchr(RawOps, '[') + 1;
			CHAR *PtrEnd = strchr(RawOps, ']');
			assert(PtrEnd != 0);
			size_t PtrLen = PtrEnd - PtrBegin;

			CHAR TempStr[256];
			memcpy(TempStr, PtrBegin, PtrLen);
			TempStr[PtrLen] = '\0';

			if (!strchr(TempStr, '('))
			{
				int i = 0;
				PCHAR YetAnotherTempPtr = strtok(TempStr, "+-*/");
				while (YetAnotherTempPtr)
				{
					// Constants are not dependences
					if (YetAnotherTempPtr[0] >= 0x30 && YetAnotherTempPtr[0] <= 0x39)
						break;

					if (!i)
						strcpy(Entry->Members.SrcDep1, YetAnotherTempPtr);
					else
					{
						strcpy(Entry->Members.SrcDep2, YetAnotherTempPtr);
						i++; break;
					}

					i++;
					YetAnotherTempPtr = strtok(NULL, "+-*/");
				}				
			}
			
		}
		// Register
		else
		{
			CharsCopied = strspn(RawOps, "abcdefghijklmnopqrstuvwxyz");
			strncpy(Entry->Members.Src, RawOps, CharsCopied);
		}

		Entry->Members.Src[CharsCopied] = '\0';
	}
	// Seriously: fix this! This duplication of code is ridiculous!
	// Type == VDT_DST
	else
	{
		// Offset (resolved constant)
		if (RawOps[0] == 'o')
		{
			CHAR *TempStr = strchr(RawOps, '(');
			assert(TempStr != 0);

			// We always have 8 digits here
			strncpy(Entry->Members.Dst, TempStr+1, 8);
			CharsCopied = 8;
		}
		// Constant number
		else if (RawOps[0] >= 0x30 && RawOps[0] <= 0x39)
		{
			CharsCopied = strspn(RawOps, "1234567890ABCDEF");
			strncpy(Entry->Members.Dst, RawOps, CharsCopied);
		}
		// Pointer
		else if (strstr(RawOps, "ptr"))
		{			
			// Get from context: $ea (and $ea2 for rightmost param, if applicable)
			ULONG RegIndex;
			DEBUG_VALUE RegValue;
			if (Registers2->GetPseudoIndexByName("$ea", &RegIndex) != S_OK)
			{
				dprintf("Error: Could not get $ea index\n");
				return S_FALSE;
			}
			if (Registers2->GetPseudoValues(DEBUG_REGSRC_DEBUGGEE, 1, NULL, RegIndex, &RegValue) != S_OK)
			{
				dprintf("Error: Could not get $ea value\n");
				return S_FALSE;
			}

			sprintf(Entry->Members.Dst, "*%08x", RegValue.I32);
			CharsCopied = 9;
			
		}
		// Register
		else
		{
			CharsCopied = strspn(RawOps, "abcdefghijklmnopqrstuvwxyz");
			strncpy(Entry->Members.Dst, RawOps, CharsCopied);
		}

		Entry->Members.Dst[CharsCopied] = '\0';
	}
	return S_OK;
}

/***********************************************************
 * !vdt_trace
 *
 * Purpose: Trace and dump to a file
 *          
 *
 *  Parameters:
 *    !vdt_trace <out-filename>
 *
 *  Return Values:
 *     N/A
 *
 ***********************************************************/
HRESULT
CALLBACK
vdt_trace(PDEBUG_CLIENT Client, PSTR args)
{
// Helping macro for this function only
// It crashes when I pass NULL in the 4th param?!?!? o.O
#define WriteEntryToFile(f,e) \
			if(FALSE == WriteFile(f, e, 256, (ULONG*) &Dummy, NULL)) \
			{ \
				dprintf("Could not write to file (error %d)\n", GetLastError()); \
				Instrs--; Success = FALSE; \
				break; \
			} \
			DumpedInstrs++;




	ULONG MaxDisassembleLength = 1000; // Should be enough

	HANDLE File = NULL;
	PSTR InFilename = NULL;
	PSTR Buffer, TmpToken, Opcodes;
	CHAR FullMnem[32];
	VdtEntry Entry;
	ULONG CurIndex = -1;
	BOOL Success = FALSE;

	CONTEXT Context;
	ULONG Pid, Tid, EventType, Instrs, DumpedInstrs;
	ULONG64 Dummy;

	PDEBUG_CONTROL Control;
	PDEBUG_ADVANCED Advanced;
	PDEBUG_REGISTERS Registers;
	PDEBUG_REGISTERS2 Registers2;
	PDEBUG_SYMBOLS Symbols;
	Client->QueryInterface(__uuidof(IDebugControl), (void **) &Control);
	Client->QueryInterface(__uuidof(IDebugAdvanced), (void **) &Advanced);
	Client->QueryInterface(__uuidof(IDebugRegisters), (void **) &Registers);
	Client->QueryInterface(__uuidof(IDebugRegisters2), (void **) &Registers2);
	Client->QueryInterface(__uuidof(IDebugSymbols), (void **) &Symbols);

	if (!Advanced || !Control) {
		dprintf("Error!\n");
		goto e_release;
	}

	size_t StrBoundary = strcspn(args, " \t\n\0");
	char BkupChar = args[StrBoundary];
	args[StrBoundary] = '\0';

	if ((File = CreateFile(args, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL))
		== INVALID_HANDLE_VALUE) {
		dprintf("Invalid parameter!\n Type !vdt-tracer.vdt_help for more information.\n");
		goto e_release;
	}

	args[StrBoundary] = BkupChar;

	/* The following is not yet implemented. It refers to accepting the input filename
	   as a parameter so we can automatically find the input memory range (where the file
	   is mapped in the address space)
	// If we have more than just the first argument (i.e. - we are passed the input filename)
	if (strlen(args) > StrBoundary)
	{
		StrBoundary += strspn(args+StrBoundary, " \t\n\0");
		InFilename = (PSTR) calloc(strlen(args+StrBoundary)+1, sizeof(CHAR));
		strcpy(InFilename, args+StrBoundary);

		IDebugBreakpoint *bptPtr = NULL;
		Control->AddBreakpoint(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID, &bptPtr);
		ULONG64 FncOffset;
		if (Symbols->GetOffsetByName("kernel32!MapViewOfFile", &FncOffset) != E_FAIL)
		{
			bptPtr->SetOffset(FncOffset);
			bptPtr->AddFlags(DEBUG_BREAKPOINT_ENABLED);
		}
		dprintf("%d\n",FncOffset);
	}
	*/

	if (!(Buffer = (PSTR) calloc(MaxDisassembleLength, sizeof(CHAR)))) {
		dprintf("Error while allocating memory\n");
		goto e_release;
	}

	// Write the magic of the file header
	if(FALSE == WriteFile(File, VDT_FILE_MAGIC, sizeof(VDT_FILE_MAGIC), (ULONG*) &Dummy, NULL)) \
	{
		dprintf("Could not write to file (error %d)\n", GetLastError());
		goto e_release;
	}

	Success = TRUE;

	Instrs = DumpedInstrs = 0;
	time_t then = time(NULL);

	do {
		Instrs++;
		
		if (Advanced->GetThreadContext(&Context, sizeof(Context)) != S_OK) {
			Instrs--; Success = FALSE;
			dprintf("Error while getting the current thread context\n");
			break;
		}

		if (Control->Disassemble(Context.Eip, DEBUG_DISASM_EFFECTIVE_ADDRESS, Buffer, 
									MaxDisassembleLength, NULL, &Dummy) != S_OK) {
			Instrs--; Success = FALSE;
			dprintf("Error while disassembling\n");
			break;
		};


		memcpy(Entry.Members.Disas, Buffer, sizeof(Entry.Members.Disas)-1);

		// Skip the first part (instruction address)
		strtok(Buffer, " \t\n");

		// Instruction bytes
		Opcodes = strtok(NULL, " \t\n");

		// Instruction mnemonic
		TmpToken = strtok(NULL, " \t\n");

		// Discard prefixes
		while (Opcodes[0])
		{
			// Prefixes not shown in the disassembly (operand size, address size, segment override, etc)
			if (*((USHORT*)Opcodes) == 0x3632 || *((USHORT*)Opcodes) == 0x6532 || *((USHORT*)Opcodes) == 0x3633
					|| *((USHORT*)Opcodes) == 0x6533 || *((USHORT*)Opcodes) == 0x3436 || *((USHORT*)Opcodes) == 0x3536
					|| *((USHORT*)Opcodes) == 0x3636 || *((USHORT*)Opcodes) == 0x3736 
					/* || *((USHORT*)Opcodes) == 0x6239 --> Not treating 'WAIT' as prefix right now */)
				Opcodes += 2;
		
			// 'rep' prefix
			else if (*((USHORT*)TmpToken) == 0x6572 && TmpToken[2] == 'p')
			{
				TmpToken = strtok(NULL, " \t\n");
				Opcodes += 2;
			}
			// 'lock' prefix
			else if (*((ULONG*)TmpToken) == 0x6b636f6c)
			{
				TmpToken = strtok(NULL, " \t\n");
				Opcodes += 2;
			}
			else
				break;
		}
					

		memcpy(Entry.Members.Mnem, TmpToken, sizeof(Entry.Members.Mnem));
		Entry.Members.Mnem[sizeof(Entry.Members.Mnem)-1] = '\0';


		// If it's a push (no pusha or pushf), write it in the file
		if (*((ULONG*)TmpToken) == 0x68737570 && !TmpToken[4])
		{
			// Manually restoring a tokenized string - bad idea
			TmpToken += strspn(TmpToken+strlen(TmpToken)+1, " \t\n") + strlen(TmpToken) + 1;

			sprintf(Entry.Members.Dst, "*%08x", Context.Esp - 4);
			if (VdtParseOperands(&Entry, TmpToken, Registers2, VDT_SRC) != S_OK)
				break;
			WriteEntryToFile(File, Entry.Str);
		}
		// Or if it's a pop
		else if (*((USHORT*)TmpToken) == 0x6F70 && TmpToken[2] == 'p')
		{
			// No popa, popf, etc
			if (!TmpToken[3])
			{
				// Manually restoring a tokenized string - bad idea
				TmpToken += strspn(TmpToken+strlen(TmpToken)+1, " \t\n") + strlen(TmpToken) + 1;

				sprintf(Entry.Members.Src, "*%08x", Context.Esp);
				Entry.Members.SrcDep1[0] = '\0';
				Entry.Members.SrcDep2[0] = '\0';
				if (VdtParseOperands(&Entry, TmpToken, Registers2, VDT_DST) != S_OK)
					break;
				WriteEntryToFile(File, Entry.Str);
			}
		}
		// IN and INS (can be used as stop conditions)
		else if (*((USHORT*)TmpToken) == 0x6E69 && 
				((TmpToken[2] != 't') && (TmpToken[2] != 'v') && (TmpToken[2] != 'c')))
		{
			Entry.Members.Src[0] = '\0';
			Entry.Members.SrcDep1[0] = '\0';
			Entry.Members.SrcDep2[0] = '\0';
			Entry.Members.SrcDep3[0] = '\0';

			// Manually restoring a tokenized string - bad idea
			TmpToken += strspn(TmpToken+strlen(TmpToken)+1, " \t\n") + strlen(TmpToken) + 1;

			if (Entry.Members.Mnem[2] == 's')
				sprintf(Entry.Members.Dst, "*%08x", Context.Edi);
			else
			{
				TmpToken = strtok(TmpToken, ",");
				if (VdtParseOperands(&Entry, TmpToken, Registers2, VDT_DST) != S_OK)
					break;
			}

			WriteEntryToFile(File, Entry.Str);
		}
		// SETcc (has to be logged with incomplete info)
		else if (*((USHORT*)TmpToken) == 0x6573)
		{
			Entry.Members.Src[0] = '\0';
			Entry.Members.SrcDep1[0] = '\0';
			Entry.Members.SrcDep2[0] = '\0';
			Entry.Members.SrcDep3[0] = '\0';

			// Manually restoring a tokenized string - bad idea
			TmpToken += strspn(TmpToken+strlen(TmpToken)+1, " \t\n") + strlen(TmpToken) + 1;

			TmpToken = strtok(TmpToken, ",");
			if (VdtParseOperands(&Entry, TmpToken, Registers2, VDT_DST) != S_OK)
				break;

			WriteEntryToFile(File, Entry.Str);
		}
		// RDTSC and RDPMC (stop condition for EDX and EAX)
		else if (*((USHORT*)TmpToken) == 0x6472)
		{
			Entry.Members.Src[0] = '\0';
			Entry.Members.SrcDep1[0] = '\0';
			Entry.Members.SrcDep2[0] = '\0';
			Entry.Members.SrcDep3[0] = '\0';

			Entry.Members.Dst[0] = 'e'; Entry.Members.Dst[1] = 'a'; Entry.Members.Dst[2] = 'x'; Entry.Members.Dst[3] = '\0'; 
			WriteEntryToFile(File, Entry.Str);

			Entry.Members.Dst[0] = 'e'; Entry.Members.Dst[1] = 'd'; Entry.Members.Dst[2] = 'x'; Entry.Members.Dst[3] = '\0'; 
			WriteEntryToFile(File, Entry.Str);
		}
		// CPUID (stop condition for EAX, EBX, ECX, and EDX)
		else if (*((USHORT*)TmpToken) == 0x7063)
		{
			Entry.Members.Src[0] = '\0';
			Entry.Members.SrcDep1[0] = '\0';
			Entry.Members.SrcDep2[0] = '\0';
			Entry.Members.SrcDep3[0] = '\0';

			Entry.Members.Dst[0] = 'e'; Entry.Members.Dst[1] = 'a'; Entry.Members.Dst[2] = 'x'; Entry.Members.Dst[3] = '\0'; 
			WriteEntryToFile(File, Entry.Str);

			Entry.Members.Dst[0] = 'e'; Entry.Members.Dst[1] = 'b'; Entry.Members.Dst[2] = 'x'; Entry.Members.Dst[3] = '\0'; 
			WriteEntryToFile(File, Entry.Str);

			Entry.Members.Dst[0] = 'e'; Entry.Members.Dst[1] = 'c'; Entry.Members.Dst[2] = 'x'; Entry.Members.Dst[3] = '\0'; 
			WriteEntryToFile(File, Entry.Str);

			Entry.Members.Dst[0] = 'e'; Entry.Members.Dst[1] = 'd'; Entry.Members.Dst[2] = 'x'; Entry.Members.Dst[3] = '\0'; 
			WriteEntryToFile(File, Entry.Str);
		}
		// CALL, RET, SYSCALL, SYSENTER, etc... (we log it just so that the output trace doesn't look so weird)
		else if ((*((USHORT*)TmpToken) == 0x7973) || // SY*
					(*((USHORT*)TmpToken) == 0x6163) || // CA*
					(*((USHORT*)TmpToken) == 0x6E69 && TmpToken[2] == 't') || // INT*
					(*((USHORT*)TmpToken) == 0x6572)) // RE*
		{
			Entry.Members.Dst[0] = '\0';
			Entry.Members.Src[0] = '\0';
			Entry.Members.SrcDep1[0] = '\0';
			Entry.Members.SrcDep2[0] = '\0';
			Entry.Members.SrcDep3[0] = '\0';

			WriteEntryToFile(File, Entry.Str);
		}
		else
		{
			// We need some info from the opcodes to get the right reference entry
			if (*((USHORT*)Opcodes) == 0x6630)
				sprintf(FullMnem, "%c%c%c%c-%s", Opcodes[0], Opcodes[1], Opcodes[2], Opcodes[3], TmpToken);
			else
				sprintf(FullMnem, "%c%c-%s", Opcodes[0], Opcodes[1], TmpToken);

			// Manually restoring a tokenized string - bad idea
			TmpToken += strspn(TmpToken+strlen(TmpToken)+1, " \t\n") + strlen(TmpToken) + 1;
			
			VdtInstr Instr = InstructionDefs[FullMnem];

			//dprintf("%s %p %p\n", FullMnem, Instr.Dst, Instr.Src);
		
			// We are mostly interested in instructions that have a source and a destination operand
			if (Instr.Dst && Instr.Src)
			{
				// String instructions
				if (strlen(Entry.Members.Mnem) == 4 && Entry.Members.Mnem[3] == 's')
				{
					// Trouble coming ahead - if the isntruction is rep'ed, we have no effective address 
					// information available in the disassembly text outpput.
					// We need to parse differently, with the help of the x86ref and the context
					// Use the context to get register (and, therefore, EA) info

					if (IsCharAlphaA(Instr.Dst[0]))
					{							
						strcpy(Entry.Members.Dst, Instr.Dst);
					}
					else
					{
						sprintf(Entry.Members.Dst, "*%08x", Context.Edi);
					}

					if (Instr.Src[0] == '-')
					{
						sprintf(Entry.Members.Src, "*%08x", Context.Esi);
						Entry.Members.SrcDep1[0] = 'e'; Entry.Members.SrcDep1[1] = 's'; Entry.Members.SrcDep1[2] = 'i'; Entry.Members.SrcDep1[3] = '\0';
					}
					else
					{
						strcpy(Entry.Members.Src, Instr.Src);
						Entry.Members.SrcDep1[0] = '\0';
					}
					
					Entry.Members.SrcDep2[0] = '\0';
					Entry.Members.SrcDep3[0] = '\0';
				}

				// Else if it's LEA
				else if (*((USHORT *)Entry.Members.Mnem) == 0x656c && Entry.Members.Mnem[2] == 'a')
				{
					// LEA requires a slightly special way of parsing
					// Its source operand looks like a 'ptr' operand but, in reality, it's not.
					// Nevertheless, we'll borrow some code from the 'ptr' operand parsing.

					TmpToken = strtok(TmpToken, ",");
					if (VdtParseOperands(&Entry, TmpToken, Registers2, VDT_DST) != S_OK)
						break;

					TmpToken = strtok(NULL, ",");
					TmpToken = strchr(TmpToken, '[') + 1;
					PCHAR PtrEnd = strchr(TmpToken, ']');
					assert(PtrEnd != 0);
					*PtrEnd = '\0';

					PCHAR AnotherTempPtr;
					PCHAR YetAnotherTempPtr;

					// If it's just a constant - why the hell don't they just a use a MOV, then?
					if ((AnotherTempPtr = strchr(TmpToken, '(')))
					{
						strncpy(Entry.Members.Src, AnotherTempPtr+1, 8);
						Entry.Members.Src[8] = '\0';
						Entry.Members.SrcDep1[0] = '\0';
					}
					else
					{
						int i = 0;
						YetAnotherTempPtr = strtok(TmpToken, "+-*/");
						while (YetAnotherTempPtr)
						{
							if (YetAnotherTempPtr[0] >= 0x30 && YetAnotherTempPtr[0] <= 0x39)
								break;
							if (!i)
								strcpy(Entry.Members.Src, YetAnotherTempPtr);
							else
							{
								strcpy(Entry.Members.SrcDep1, YetAnotherTempPtr);
								i++; break;
							}

							i++;
							YetAnotherTempPtr = strtok(NULL, "+-*/");
						}

						if (!i)
							Entry.Members.Src[0] = '\0';
						else if (i == 1)
							Entry.Members.SrcDep1[0] = '\0';
					}

					Entry.Members.SrcDep2[0] = '\0';
					Entry.Members.SrcDep3[0] = '\0';
				}

				// End of 'special cases' - parse as usual
				else
				{
					if (IsCharAlphaA(Instr.Dst[0]))
					{
						strcpy(Entry.Members.Dst, Instr.Dst);
					}
					else
					{
						TmpToken = strtok(TmpToken, ",");
						if (VdtParseOperands(&Entry, TmpToken, Registers2, VDT_DST) != S_OK)
							break;
					}

					if (Instr.Src[0] == '-')
					{
						TmpToken = strtok(NULL, ",");
						if (VdtParseOperands(&Entry, TmpToken, Registers2, VDT_SRC) != S_OK)
							break;
					}
					else if (Instr.Src[0] == 'x')
					{
						strcpy(Entry.Members.Src, Instr.Dst);
						
						Entry.Members.SrcDep1[0] = '\0';
						Entry.Members.SrcDep2[0] = '\0';
						Entry.Members.SrcDep3[0] = '\0';
					}
					else if (Instr.Src[0] == '*')
					{
						TmpToken = strtok(NULL, ",");
						if (VdtParseOperands(&Entry, TmpToken, Registers2, VDT_SRC) != S_OK)
							break;

						if (Entry.Members.SrcDep1[0] == '\0')
							strcpy(Entry.Members.SrcDep1, Instr.Dst);
						else if (Entry.Members.SrcDep2[0] == '\0')
							strcpy(Entry.Members.SrcDep2, Instr.Dst);
						else if (Entry.Members.SrcDep3[0] == '\0')
							strcpy(Entry.Members.SrcDep3, Instr.Dst);
					}
					else
					{
						strcpy(Entry.Members.Src, Instr.Src);

						Entry.Members.SrcDep1[0] = '\0';
						Entry.Members.SrcDep2[0] = '\0';
						Entry.Members.SrcDep3[0] = '\0';
					}
				}

				int DstLen = strlen(Entry.Members.Dst);
				if (DstLen >= 2 &&
					Entry.Members.Dst[DstLen-2] == 'd' &&
					Entry.Members.Dst[DstLen-1] == 'a')
				{
					Entry.Members.Dst[DstLen-1] = 'x';
					WriteEntryToFile(File, Entry.Str);

					Entry.Members.Dst[DstLen-2] = 'a';
				}

				//dprintf("Here!\n");
				WriteEntryToFile(File, Entry.Str);
			}
		}


		if (Control->SetExecutionStatus(DEBUG_STATUS_STEP_INTO) != S_OK) {
			Instrs--; Success = FALSE;
			dprintf("Error while setting the execution status to stepping mode\n");
			break;
		}

		if (Control->WaitForEvent(0, 1000) != S_OK) {
			Instrs--; Success = FALSE;
			dprintf("Error while waiting for event\n");
			break;
		}

		char extrainf[256];
		unsigned long extraused;
		if (Control->GetLastEventInformation(&EventType, &Pid, &Tid, extrainf, 256, &extraused, NULL, 0, NULL) != S_OK) {
			Instrs--; Success = FALSE;
			dprintf("Error while trying to get information on the last event\n");
			break;
		}

		if (EventType == DEBUG_EVENT_BREAKPOINT)
			vdt_help(NULL, NULL);

	} while (!EventType); // EventType == 0 for the tracing steps (undocumented)

	dprintf("\nA total of %u instructions were traced and %u were dumped to %s\n", 
			Instrs, DumpedInstrs, args);

	if (!EventType)
		dprintf("This command ended abruptly. The output file is not suited for analysis\n");

	time_t now = time(NULL);

	dprintf("Duration of this command in seconds: %f\n\n", difftime(now, then));

	free(Buffer);

	CloseHandle(File);

e_release:
	if (Advanced) Advanced->Release();
	if (Control) Control->Release();

	return (Success ? S_OK : E_FAIL);

#undef WriteEntryToFile
}

