#include <stdio.h>
#include <windows.h>

#define JMP_OPCODE 0xe9
#define JMP_RAX_OPCODE 0xff, 0xe0
#define JMP_RAX_LEN 2
#define MOV_RAX_OPCODE 0x48, 0xB8
#define MOV_RAX_LEN 10
#define JMP_INSTRUCTION_LEN 5
#define BYTECODE_LEN 8

void hookme(int i) {
	printf("i=%d\n", i);
}

char originalInstructions[BYTECODE_LEN + MOV_RAX_LEN + JMP_RAX_LEN];

void hookFunction(char* funcAddr, char* newFunction) {
	int relativeOffset = newFunction - funcAddr - JMP_INSTRUCTION_LEN;
	char jmp_bytecode[] = { JMP_OPCODE,
		((char*)&relativeOffset)[0],
		((char*)&relativeOffset)[1],
		((char*)&relativeOffset)[2],
		((char*)&relativeOffset)[3],
		0x90,
		0x90,
		0x90 }; // nop

	int oldProtect;
	VirtualProtect(funcAddr, sizeof(jmp_bytecode), PAGE_EXECUTE_READWRITE, &oldProtect);

	char *addr = funcAddr + BYTECODE_LEN;
	char movOpcode[] = { MOV_RAX_OPCODE };
	char jmpOpcode[] = { JMP_RAX_OPCODE };
	memcpy(originalInstructions, funcAddr, sizeof(jmp_bytecode)); // save original
	memcpy(originalInstructions + BYTECODE_LEN, movOpcode, sizeof(movOpcode)); // mov rax,
	memcpy(originalInstructions + BYTECODE_LEN + sizeof(movOpcode), &addr, MOV_RAX_LEN - sizeof(movOpcode)); // addr
	memcpy(originalInstructions + BYTECODE_LEN + MOV_RAX_LEN, jmpOpcode, JMP_RAX_LEN); // jmp rax

	memcpy(funcAddr, jmp_bytecode, sizeof(jmp_bytecode));  // overwrite instructions
	VirtualProtect(funcAddr, sizeof(jmp_bytecode), oldProtect, &oldProtect);

	VirtualProtect(originalInstructions, sizeof(originalInstructions), PAGE_EXECUTE, &oldProtect);
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
	hookFunction(hookme, hook);
	hookme(1);
}
