#include <stdio.h>
#include <windows.h>
#include "ldisasm.cpp"

#define JMP_OPCODE 0xe9
#define JMP_RAX_OPCODE 0xff, 0xe0
#define JMP_RAX_LEN 2
#define MOV_RAX_OPCODE 0x48, 0xB8
#define MOV_RAX_LEN 10
#define JMP_INSTRUCTION_LEN 5

void hookme(int i) {
	printf("i=%d\n", i);
}

char* originalInstructions;

int getPatchSize(char* funcAddr) {
	int instructionLenCounter = 0;
	while (instructionLenCounter < 5) {
		instructionLenCounter += ldisasm(funcAddr + instructionLenCounter, true);
	}
	return instructionLenCounter;
}

void hookFunction(char* funcAddr, char* newFunction) {
	int originalLen = getPatchSize(funcAddr);

	int relativeOffset = newFunction - funcAddr - JMP_INSTRUCTION_LEN;
	char jmp_bytecode[] = { JMP_OPCODE,
		((char*)&relativeOffset)[0],
		((char*)&relativeOffset)[1],
		((char*)&relativeOffset)[2],
		((char*)&relativeOffset)[3]}; // nop

	int oldProtect;
	
	// save original instructions, and prepare jmp back
	char *addr = funcAddr + originalLen;
	char movOpcode[] = { MOV_RAX_OPCODE };
	char jmpOpcode[] = { JMP_RAX_OPCODE };
	originalInstructions = VirtualAlloc(NULL, originalLen + MOV_RAX_LEN + JMP_RAX_LEN, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	memcpy(originalInstructions, funcAddr, originalLen); // save original
	memcpy(originalInstructions + originalLen, movOpcode, sizeof(movOpcode)); // mov rax,
	memcpy(originalInstructions + originalLen + sizeof(movOpcode), &addr, MOV_RAX_LEN - sizeof(movOpcode)); // addr
	memcpy(originalInstructions + originalLen + MOV_RAX_LEN, jmpOpcode, JMP_RAX_LEN); // jmp rax
	VirtualProtect(originalInstructions, sizeof(originalInstructions), PAGE_EXECUTE, &oldProtect);

	// overwrite instructions with jmp
	VirtualProtect(funcAddr, sizeof(jmp_bytecode), PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy(funcAddr, jmp_bytecode, sizeof(jmp_bytecode)); 
	VirtualProtect(funcAddr, sizeof(jmp_bytecode), oldProtect, &oldProtect);
}

typedef void funcptr();

void hook(int i) {
	printf("get pwned\n");
	((funcptr*)originalInstructions)(i + 1);
	printf("get pwned 2\n");
}

int main()
{
	hookme(1);
	hookFunction(hookme, hook, &originalInstructions);
	hookme(1);
}
