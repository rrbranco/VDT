/* 
Visual Data Trace v1.0 Alpha

Copyright (C) 2008-2010  
	Rodrigo Rubira Branco (BSDaemon) <rodrigo@risesecurity.org>
	Julio Auto <julio@julioauto.com>
*/

#include "stdafx.h"
#include "MainWindow.h"
#include "VisualDataTracer.h"

using namespace VisualDataTracer;

[STAThreadAttribute]
int main(array<System::String ^> ^args)
{
	// Enabling Windows XP visual effects before any controls are created
	Application::EnableVisualStyles();
	Application::SetCompatibleTextRenderingDefault(false); 

	// Initialize global members
	VDTAnalyzer::InitRegMap();

	// Create the main window and run it
	Application::Run(gcnew MainWindow());
	return 0;
}

/*
 * Alright. This is the analyzer's code. So far, it's meant
 * to be somewhat simple, leaving most of the hard work to be
 * done by the tracer itself. This part of VDT is essentially
 * just a dataflow analyzer with a few specifities regarding
 * the target platform (x86) and the domain of the application.
 *
 * Something that is worth mentioning about this analyzer is
 * its characteristic of 'forking' searches. Consider the
 * following instruction:
 *
 *  mov eax, [ebx+ecx]
 *
 * If our search leads to that instruction (i.e. we were looking
 * for eax's definition), we would fork our search into _three_
 * different 'lines of search', for we now have three different
 * targets:
 *
 * 1) ebx
 * 2) ecx
 * 3) The memory location pointed by 'ebx+ecx'
 *
 * From our perspective, we are interested in all of these targets
 * because controlling any of them (that is, their values) would
 * put us in control of 'eax', even though controlling targets '1'
 * or '2' would require us to have a deep understanding of the
 * memory state in order to deterministically control 'eax', i.e.
 * assigning a specifically desired value to it.
 */

/*
 * The register name mapping.
 * Notice how, in some cases, we skip two entries so that
 * we won't have, say, 'ah == al'
 */
void VDTAnalyzer::InitRegMap()
{
	VDTAnalyzer::GlobalRegisterMap = gcnew Hashtable();

	VDTAnalyzer::GlobalRegisterMap["eax"] = (unsigned long) EAX; VDTAnalyzer::GlobalRegisterMap["al"] = (unsigned long) EAX+2; VDTAnalyzer::GlobalRegisterMap["ah"] = (unsigned long) EAX+2; VDTAnalyzer::GlobalRegisterMap["ax"] = (unsigned long) EAX; VDTAnalyzer::GlobalRegisterMap["rax"] = (unsigned long) EAX;
	VDTAnalyzer::GlobalRegisterMap["ebx"] = (unsigned long) EBX; VDTAnalyzer::GlobalRegisterMap["bl"] = (unsigned long) EBX+2; VDTAnalyzer::GlobalRegisterMap["bh"] = (unsigned long) EBX+2; VDTAnalyzer::GlobalRegisterMap["bx"] = (unsigned long) EBX; VDTAnalyzer::GlobalRegisterMap["rbx"] = (unsigned long) EBX;
	VDTAnalyzer::GlobalRegisterMap["ecx"] = (unsigned long) ECX; VDTAnalyzer::GlobalRegisterMap["cl"] = (unsigned long) ECX+2; VDTAnalyzer::GlobalRegisterMap["ch"] = (unsigned long) ECX+2; VDTAnalyzer::GlobalRegisterMap["cx"] = (unsigned long) ECX; VDTAnalyzer::GlobalRegisterMap["rcx"] = (unsigned long) ECX;
	VDTAnalyzer::GlobalRegisterMap["edx"] = (unsigned long) EDX; VDTAnalyzer::GlobalRegisterMap["dl"] = (unsigned long) EDX+2; VDTAnalyzer::GlobalRegisterMap["dh"] = (unsigned long) EDX+2; VDTAnalyzer::GlobalRegisterMap["dx"] = (unsigned long) EDX; VDTAnalyzer::GlobalRegisterMap["rdx"] = (unsigned long) EDX;
	VDTAnalyzer::GlobalRegisterMap["esi"] = (unsigned long) ESI; VDTAnalyzer::GlobalRegisterMap["si"] = (unsigned long) ESI; VDTAnalyzer::GlobalRegisterMap["rsi"] = (unsigned long) ESI;
	VDTAnalyzer::GlobalRegisterMap["edi"] = (unsigned long) EDI; VDTAnalyzer::GlobalRegisterMap["di"] = (unsigned long) EDI; VDTAnalyzer::GlobalRegisterMap["rdi"] = (unsigned long) EDI;
	VDTAnalyzer::GlobalRegisterMap["ebp"] = (unsigned long) EBP; VDTAnalyzer::GlobalRegisterMap["bp"] = (unsigned long) EBP; VDTAnalyzer::GlobalRegisterMap["rbp"] = (unsigned long) EBP;
	VDTAnalyzer::GlobalRegisterMap["esp"] = (unsigned long) ESP; VDTAnalyzer::GlobalRegisterMap["sp"] = (unsigned long) ESP; VDTAnalyzer::GlobalRegisterMap["rsp"] = (unsigned long) ESP;
}


/*
 * This function searches the register mapping to see if the
 * two parametrized names match/overlap. E.g. match_regs("al", "ax") = TRUE;
 */
bool VDTAnalyzer::MatchRegs(String ^reg1, String ^reg2)
{
	if ((VDTAnalyzer::GlobalRegisterMap[reg1] == nullptr) || (VDTAnalyzer::GlobalRegisterMap[reg2] == nullptr))
		return false;

	/* The obvious case */
	if (!String::Compare(reg1, reg2))
		return true;

	unsigned long arrayAddress = (unsigned long) VDTAnalyzer::GlobalRegisterMap[reg1];
	char **reg_list = (char **) arrayAddress;

	for (int i = 0; String::Compare(gcnew String(reg_list[i]), ""); i++)
		if (!String::Compare(gcnew String (reg_list[i]), reg2))
			return true;

	return false;
}

/*
 * This is the search for a definition. It goes like this:
 * 'Go backwards searching the trace starting at index 'startIndx' for a
 * instruction that defines 'target'. If you find it, return the index where
 * you found it (or ULLONG_MAX if you failed to find it).'
 */
unsigned long long VDTAnalyzer::SearchDef(unsigned long long startIndx, String ^target)
{
	while (startIndx != ULLONG_MAX)
	{
		VdtInstruction ^instr = (VdtInstruction ^) VDTAnalyzer::GlobalInstrMap[startIndx--];

		// Check if this instruction defines this target
		if ((!String::Compare(instr->Dst, target)) || (MatchRegs(target, instr->Dst)))
			return startIndx + 1;
	}
	return ULLONG_MAX;
}

/*
 * Little helping function to insert a register in the search/target queue.
 * This was moved here to clean up the code a bit by eliminating so many
 * repetitions.
 */
inline void VDTAnalyzer::PushReg(String ^reg, unsigned long long defPos, VdtTarget ^curTarget)
{
	// Checking for EDA or DA (EDX:EAX and DX:AX, respectively)
	if (!String::Compare(reg, "da"))
	{
		VDTAnalyzer::GlobalTargetQueue->Enqueue(gcnew VdtTarget("dx", defPos, gcnew Pair(curTarget->OutChain, defPos+1)));
		VDTAnalyzer::GlobalTargetQueue->Enqueue(gcnew VdtTarget("ax", defPos, gcnew Pair(curTarget->OutChain, defPos+1)));
	}
	else if (!String::Compare(reg, "eda"))
	{
		VDTAnalyzer::GlobalTargetQueue->Enqueue(gcnew VdtTarget("edx", defPos, gcnew Pair(curTarget->OutChain, defPos+1)));
		VDTAnalyzer::GlobalTargetQueue->Enqueue(gcnew VdtTarget("eax", defPos, gcnew Pair(curTarget->OutChain, defPos+1)));
	}
	else
		VDTAnalyzer::GlobalTargetQueue->Enqueue(gcnew VdtTarget(reg, defPos, gcnew Pair(curTarget->OutChain, defPos+1)));
}

/*
 * This is the search itself!
 *
 * We start with the user-specified target in the target queue, ready to
 * start looking from the bottom of our trace, i.e. the end of the trace file.
 * We go searching backwards BFS-like, forking and merging searches as explained,
 * until we eventually find some definition whose source is part of the user
 * input (as specified by the user with the 'taint ranges' parameters) or
 * exhaust our search.
 */
ArrayList ^VDTAnalyzer::SearchTaintOf(String ^target, unsigned long long startingIndx)
{
	VDTAnalyzer::GlobalTargetQueue = gcnew Queue();
	VDTAnalyzer::GlobalVisitedSet = gcnew ArrayList();

	ArrayList ^retVal = gcnew ArrayList();

	Pair ^startChain = gcnew Pair(nullptr, startingIndx-1);
	VDTAnalyzer::GlobalTargetQueue->Enqueue(gcnew VdtTarget(target, startingIndx-1, startChain));

	while (VDTAnalyzer::GlobalTargetQueue->Count != 0)
	{
		unsigned long long defPos;
		VdtTarget ^curTarget = (VdtTarget ^) VDTAnalyzer::GlobalTargetQueue->Dequeue();

		String ^visitedKey = String::Concat(String::Format("{0:X8}", curTarget->InstrIndx)->ToLower(), curTarget->TargetName);

		// If "node" not yet visited
		if (!VDTAnalyzer::GlobalVisitedSet->Contains(visitedKey))
		{
			VDTAnalyzer::GlobalVisitedSet->Add(visitedKey);

			defPos = SearchDef(curTarget->InstrIndx, curTarget->TargetName);

			VdtInstruction ^instr;
			if (defPos != ULLONG_MAX)
				instr = (VdtInstruction ^) VDTAnalyzer::GlobalInstrMap[defPos];

			//printf("Searching for %s from %08lx: %s %08x\n", curTarget.TargetName, (long) curTarget.InstrIndx, instr->fulldump, defPos);

			// First check if we have a tainting instruction
			if (instr != nullptr && instr->Src[0] == '*')
			{
				String ^addr = instr->Src->Substring(1);

				IEnumerator ^keyEnum = VDTAnalyzer::GlobalTaintRanges->Keys->GetEnumerator();

				while (keyEnum->MoveNext())
				{
					if ((addr->CompareTo((String ^)keyEnum->Current) >= 0) && 
						(addr->CompareTo((String ^)VDTAnalyzer::GlobalTaintRanges[keyEnum->Current]) <= 0))
					{
						retVal->Add("Possible source of taint found!");
						retVal->Add(String::Concat("Printing (possibly a part of) the tainting instruction: ", instr->FullDump));
						retVal->Add(String::Concat("Destination operand: ", instr->Dst));
						retVal->Add(String::Concat("Source operand: ", instr->Src));

						retVal->Add("\n");
						retVal->Add("Printing dataflow path:");
						retVal->Add(String::Concat(String::Concat(defPos, ".\t\t"), instr->FullDump));

						Pair ^tmpChain = curTarget->OutChain;

						while (tmpChain->First != nullptr)
						{
							VdtInstruction ^tmp = (VdtInstruction ^) VDTAnalyzer::GlobalInstrMap[(unsigned long long) tmpChain->Second-1];
							retVal->Add(String::Concat(String::Concat((unsigned long long) tmpChain->Second, ".\t\t"), tmp->FullDump));

							tmpChain = (Pair ^) tmpChain->First;
						}

						VdtInstruction ^tmp = (VdtInstruction ^) VDTAnalyzer::GlobalInstrMap[(unsigned long long) tmpChain->Second+1];
						retVal->Add(String::Concat(String::Concat((unsigned long long) tmpChain->Second+2, ".\t\t"), tmp->FullDump));

						/* TODO: Fix this?
						int user_choice = 0;
						while (user_choice != 'y' && user_choice != 'n')
						{
							printf("\nContinue searching for another match? [y/N]:");
							user_choice = getc(stdin);

							if (user_choice == '\n' || user_choice == 'N')
								user_choice = 'n';
							else if (user_choice == 'Y')
								user_choice = 'y';
							else
								// Discard the remaining characters
								fflush(stdin);
						}
						*/

						/*if (user_choice == 'y')
						{
							GlobalTargetQueue.pop();
							break;
						}
						else
						{
							return;
						}*/

						return retVal;
					}
				}

				// User requested to keep searching
				//if (it != input_ranges.end())
				//	continue;
			}

			// No match? Then keep looking! (If we still have anywhere to search)
			if (defPos != ULLONG_MAX)
			{
				// If it's a memory operand, start looking for its def
				if (instr->Src[0] == '*')
				{
					VDTAnalyzer::GlobalTargetQueue->Enqueue(gcnew VdtTarget(instr->Src, defPos, gcnew Pair(curTarget->OutChain, defPos+1)));

					// If the address is not 4-byte aligned we should try looking for it's aligned 'version' too
					// TODO: fix this!!!
					unsigned int targetAddr = (unsigned int) Int32::Parse(instr->Src->Substring(1), System::Globalization::NumberStyles::AllowHexSpecifier);
					if (targetAddr % 4)
					{
						VDTAnalyzer::GlobalTargetQueue->Enqueue(gcnew VdtTarget(String::Concat("*", String::Format("{0:X8}", targetAddr - (targetAddr%4))->ToLower()), defPos, gcnew Pair(curTarget->OutChain, defPos+1)));
					}
					// And same for 2-byte alignment
					if (targetAddr % 2)
					{
						VDTAnalyzer::GlobalTargetQueue->Enqueue(gcnew VdtTarget(String::Concat("*", String::Format("{0:X8}", targetAddr - (targetAddr%2))->ToLower()), defPos, gcnew Pair(curTarget->OutChain, defPos+1)));
					}
				}

				// Else if it's a register operand
				else if (VDTAnalyzer::GlobalRegisterMap[instr->Src] != nullptr)
				{
					// If it's not a 'xor eax, eax'...
					if ((String::Compare(instr->Mnem, "xor") || String::Compare(instr->Dst, instr->Src)))
						PushReg(instr->Src, defPos, curTarget);
				}

				// Else if it's a constant operand but the instruction is not an assignment,
				// treat it as 'transformation' (i.e. a taint could still lead to partial control)
				// Continue looking for a def of the same element
				else if ((String::Compare(instr->Mnem->Substring(0,3), "mov")) && (String::Compare(instr->Mnem, "lea")) && (String::Compare(instr->Mnem, "push")) && (String::Compare(instr->Mnem, "pop")))
				{
					curTarget->InstrIndx = defPos;
					curTarget->OutChain = gcnew Pair(curTarget->OutChain, defPos+1);
					VDTAnalyzer::GlobalTargetQueue->Enqueue(curTarget);
					continue;
				}

				// Add the dependences too!
				if (!String::IsNullOrEmpty(instr->SrcDep1))
				{
					PushReg(instr->SrcDep1, defPos, curTarget);

					if (!String::IsNullOrEmpty(instr->SrcDep2))
					{
						PushReg(instr->SrcDep2, defPos, curTarget);

						if (!String::IsNullOrEmpty(instr->SrcDep3))
							PushReg(instr->SrcDep3, defPos, curTarget);
					}
				}
			}
		}
	}
	
	return retVal;
}