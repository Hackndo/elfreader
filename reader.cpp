#include <iostream>
#include <fstream>
#include <string>
#include <stdio.h>
#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include "elf.h"

using namespace std;

void read_elf_header(ifstream *file_handle, Elf32_Ehdr *elf_header)
{
	assert(elf_header != NULL);
	(*file_handle).seekg(0, ios::beg);
	(*file_handle).read((char *)elf_header, sizeof(Elf32_Ehdr));
}

bool is_ELF(Elf32_Ehdr eh)
{
	/* ELF magic bytes are 0x7f,'E','L','F'
	 * Using  octal escape sequence to represent 0x7f
	 */
	if(!strncmp((char*)eh.e_ident, "\177ELF", 4)) {
		/* IS a ELF file */
		return 1;
	} else {
		printf("ELF KO\n");
		/* Not ELF file */
		return 0;
	}
}

void display_elf_header(Elf32_Ehdr elf_header)
{
	printf("\n********************************************************************************\n");
	printf("*                                ELF HEADER                                    *\n");
	printf("********************************************************************************\n\n");

	/* Storage capacity class */
	printf("Storage class\t= ");
	switch(elf_header.e_ident[EI_CLASS])
	{
		case ELFCLASS32:
			printf("32-bit objects\n");
			break;

		case ELFCLASS64:
			printf("64-bit objects\n");
			break;

		default:
			printf("INVALID CLASS\n");
			break;
	}

	/* Data Format */
	printf("Data format\t= ");
	switch(elf_header.e_ident[EI_DATA])
	{
		case ELFDATA2LSB:
			printf("2's complement, little endian\n");
			break;

		case ELFDATA2MSB:
			printf("2's complement, big endian\n");
			break;

		default:
			printf("INVALID Format\n");
			break;
	}

	/* OS ABI */
	printf("OS ABI\t\t= ");
	switch(elf_header.e_ident[EI_OSABI])
	{
		case ELFOSABI_SYSV:
			printf("UNIX System V ABI\n");
			break;

		case ELFOSABI_HPUX:
			printf("HP-UX\n");
			break;

		case ELFOSABI_ARM:
			printf("ARM\n");
			break;

		case ELFOSABI_STANDALONE:
			printf("Standalone (embedded) app\n");
			break;

		default:
			printf("Unknown (0x%x)\n", elf_header.e_ident[EI_OSABI]);
			break;
	}

	/* ELF filetype */
	printf("Filetype \t= ");
	switch(elf_header.e_type)
	{
		case ET_NONE:
			printf("N/A (0x0)\n");
			break;

		case ET_REL:
			printf("Relocatable\n");
			break;

		case ET_EXEC:
			printf("Executable\n");
			break;

		case ET_DYN:
			printf("Shared Object\n");
			break;
		default:
			printf("Unknown (0x%x)\n", elf_header.e_type);
			break;
	}

	/* ELF Machine-id */
	printf("Machine\t\t= ");
	switch(elf_header.e_machine)
	{
		case EM_NONE:
			printf("None (0x0)\n");
			break;

		case EM_386:
			printf("INTEL x86 (0x%x)\n", EM_386);
			break;

		case EM_ARM:
			printf("ARM (0x%x)\n", EM_ARM);
			break;
		default:
			printf("Machine\t= 0x%x\n", elf_header.e_machine);
			break;
	}

	/* Entry point */
	printf("Entry point\t= 0x%08x\n", elf_header.e_entry);

	/* ELF header size in bytes */
	printf("ELF header size\t= 0x%08x\n", elf_header.e_ehsize);

	/* Program Header */
	printf("\nProgram Header\t= ");
	printf("0x%08x\n", elf_header.e_phoff);				/* start */
	printf("\t\t  %d entries\n", elf_header.e_phnum);	/* num entry */
	printf("\t\t  %d bytes\n", elf_header.e_phentsize);	/* size/entry */

	/* Section header starts at */
	printf("\nSection Header\t= ");
	printf("0x%08x\n", elf_header.e_shoff);				/* start */
	printf("\t\t  %d entries\n", elf_header.e_shnum);	/* num entry */
	printf("\t\t  %d bytes\n", elf_header.e_shentsize);	/* size/entry */
	printf("\t\t  0x%08x (string table offset)\n", elf_header.e_shstrndx);

	/* File flags (Machine specific)*/
	printf("\nFile flags \t= 0x%08x\n", elf_header.e_flags);

	/* ELF file flags are machine specific.
	 * INTEL implements NO flags.
	 * ARM implements a few.
	 * Add support below to parse ELF file flags on ARM
	 */
	int32_t ef = elf_header.e_flags;
	printf("\t\t  ");

	if(ef & EF_ARM_RELEXEC)
		printf(",RELEXEC ");

	if(ef & EF_ARM_HASENTRY)
		printf(",HASENTRY ");

	if(ef & EF_ARM_INTERWORK)
		printf(",INTERWORK ");

	if(ef & EF_ARM_APCS_26)
		printf(",APCS_26 ");

	if(ef & EF_ARM_APCS_FLOAT)
		printf(",APCS_FLOAT ");

	if(ef & EF_ARM_PIC)
		printf(",PIC ");

	printf("\n");	/* End of ELF header */
}

void read_program_headers(ifstream *file_handle, Elf32_Ehdr eh, Elf32_Phdr ph[]) {
	(*file_handle).seekg(eh.e_phoff, ios::beg);
	// En gros, ici, j'ai ph qui est un tableau de structure Elf32_Phdr. Je voudrais boucler
	// pour remplir chaque structure avec eh.e_phentsize bytes (taille d'une structure Elf32_Phdr)
	for (int i=0; i < eh.e_phnum; i++) {
		(*file_handle).read((char *)&ph[i], sizeof(Elf32_Phdr));
	}
}

void display_program_headers(Elf32_Phdr* ph_table, int size) {
	printf("\n********************************************************************************\n");
	printf("*                                 SEGMENTS                                     *\n");
	printf("********************************************************************************\n\n");

	printf("+---+----------+----------+----------+----------+----------+----+---------+\n");
	printf("|idx|offset    |vaddr     |paddr     |file size |mem size  |algn|name     |\n");
	printf("+---+----------+----------+----------+----------+----------+----+---------+\n");

	string p_types[] = {"PT_NULL", "PT_LOAD", "PT_DYNAMIC", "PT_INTERP", "PT_NOTE", "PT_SHLIB", "PT_PHDR", "PT_NUM"};
	string seg_name;
	for (int i=0; i < size; i++) {
		if (ph_table[i].p_type < sizeof(p_types)) {
			seg_name = p_types[ph_table[i].p_type];
		} else {
			seg_name = "UNKNOWN";
		}
		printf(" %03d ", i);
		printf("0x%08x ", ph_table[i].p_offset);
		printf("0x%08x ", ph_table[i].p_vaddr);
		printf("0x%08x ", ph_table[i].p_paddr);
		printf("0x%08x ", ph_table[i].p_filesz);
		printf("0x%08x ", ph_table[i].p_memsz);
		printf("%4d ", ph_table[i].p_align);
		printf("%s\t", seg_name.c_str());
		printf("\n");
		//printf("Offset\t= 0x%08x\n", ph[i].p_filesz);
	}
}

void read_section_headers(ifstream *file_handle, Elf32_Ehdr eh, Elf32_Shdr sh[]) {
	(*file_handle).seekg(eh.e_shoff, ios::beg);
	// En gros, ici, j'ai ph qui est un tableau de structure Elf32_Phdr. Je voudrais boucler
	// pour remplir chaque structure avec eh.e_phentsize bytes (taille d'une structure Elf32_Phdr)
	for (int i=0; i < eh.e_shnum; i++) {
		(*file_handle).read((char *)&sh[i], sizeof(Elf32_Shdr));
	}
}

char *read_section(ifstream *file_handle, Elf32_Ehdr eh, Elf32_Shdr sh) {
	char *buff = new char[sh.sh_size];
	(*file_handle).seekg(sh.sh_offset, ios::beg);
	(*file_handle).read(buff, sh.sh_size);
	return buff;
}

void display_section_headers(ifstream *file_handle, Elf32_Ehdr eh, Elf32_Shdr* sh_table) {
	Elf32_Shdr string_section = sh_table[eh.e_shstrndx];
	char *buff = read_section(file_handle, eh, string_section);

	printf("\n********************************************************************************\n");
	printf("*                                 SECTIONS                                     *\n");
	printf("********************************************************************************\n\n");
	printf("+---+----------+----------+----------+----+----------+----------+--------------+\n");
	printf("|idx|offset    |load-addr |size      |algn|flags     |type      |section       |\n");
	printf("+---+----------+----------+----------+----+----------+----------+--------------+\n");

	for (int i=0; i < eh.e_shnum; i++) {
		
		printf(" %03d ", i);
		printf("0x%08x ", sh_table[i].sh_offset);
		printf("0x%08x ", sh_table[i].sh_addr);
		printf("0x%08x ", sh_table[i].sh_size);
		printf("%4d ", sh_table[i].sh_addralign);
		printf("0x%08x ", sh_table[i].sh_flags);
		printf("0x%08x ", sh_table[i].sh_type);
		printf("%s\t", buff+sh_table[i].sh_name);
		printf("\n");
	}
}

void display_symbol_table(ifstream *file_handle, Elf32_Ehdr eh, Elf32_Shdr* sh_table, int symbol_table) {
	char *str_tbl;
	Elf32_Sym* sym_tbl;
	int i, symbol_count;

	sym_tbl = (Elf32_Sym*)read_section(file_handle, eh, sh_table[symbol_table]);

	/* Read linked string-table
	 * Section containing the string table having names of
	 * symbols of this section
	 */
	int str_tbl_ndx = sh_table[symbol_table].sh_link;
	str_tbl = read_section(file_handle, eh, sh_table[str_tbl_ndx]);

	symbol_count = (sh_table[symbol_table].sh_size/sizeof(Elf32_Sym));
	printf("%d symbols\n", symbol_count);
	printf("+---+----------+----+----+---------+\n");
	printf("|idx|value     |bind|type|name     |\n");
	printf("+---+----------+----+----+---------+\n");

	for(i=0; i< symbol_count; i++) {
		printf(" %03d ", i);
		printf("0x%08x ", sym_tbl[i].st_value);
		printf("0x%02x ", ELF32_ST_BIND(sym_tbl[i].st_info));
		printf("0x%02x ", ELF32_ST_TYPE(sym_tbl[i].st_info));
		printf("%s\n", (str_tbl + sym_tbl[i].st_name));
	}
	printf("\n");
}

void display_symbols(ifstream* file_handle, Elf32_Ehdr eh, Elf32_Shdr* sh_table) {

	printf("\n********************************************************************************\n");
	printf("*                                  SYMBOLS                                     *\n");
	printf("********************************************************************************\n\n");

	for (int i=0; i < eh.e_shnum; i++) {
		if ((sh_table[i].sh_type==SHT_SYMTAB) || (sh_table[i].sh_type==SHT_DYNSYM)) {
			printf("[Section %03d] ", i);
			display_symbol_table(file_handle, eh, sh_table, i);
		}
	}
}


void disassemble(ifstream* file_handle, Elf32_Ehdr eh, Elf32_Shdr* sh_table)
{
	int i;
	char* sh_str;   /* section-header string-table is also a section. */
	char* buf;      /* buffer to hold contents of the .text section */

	/* Read section-header string-table */
	sh_str = read_section(file_handle, eh, sh_table[eh.e_shstrndx]);

	for(i=0; i<eh.e_shnum; i++) {
		if(!strcmp(".text", (sh_str + sh_table[i].sh_name))) {
			printf("Found section\t\".text\"\n");
			printf("at offset\t0x%08x\n", sh_table[i].sh_offset);
			printf("of size\t\t0x%08x\n", sh_table[i].sh_size);
			break;
		}
	}

	(*file_handle).seekg(sh_table[i].sh_offset, ios::beg);
	buf = new char[sh_table[i].sh_size];
	(*file_handle).read(buf, sh_table[i].sh_size);
	/* Now buf contains the instructions (4bytes each) */
	for (int j = 0; j < sh_table[i].sh_size; j++) {
		cout << "db 0x" << hex << (int(buf[j]) & 0xff) << endl;
	}

}  

void display_help() {
	printf("Usage: readelf <options> elf_binary\n"
		"  Displays information about elf binary\n"
		"  Options are:\n"
		"\t-e\tDisplay ELF header\n"
		"\t-p\tDisplay Program header table\n"
		"\t-s\tDisplay Section header table\n"
		"\t-S\tDisplay Symbol table\n"
		"\t-D\tDecompile binary\n"
		"\t-h\tDisplay help\n"
		);
}

int main(int argc, char* argv[]) {
	if (argc < 2) {
		printf("Usage: %s [-hespSD] elf_binary\n" , argv[0]);
		return -1;
	}

	int opt;
    enum { ELF, SECTION, PROGRAM, SYMBOL, DISASSEMBLE, HELP, ALL } mode = ALL;

    while ((opt = getopt(argc, argv, "hespSD")) != -1) {
        switch (opt) {
        case 'h': mode = HELP; break;
        case 'e': mode = ELF; break;
        case 's': mode = SECTION; break;
        case 'p': mode = PROGRAM; break;
        case 'S': mode = SYMBOL; break;
        case 'D': mode = DISASSEMBLE; break;
        default:
            fprintf(stderr, "Usage: %s [-hespSD] binary\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if (mode == HELP) {
    	display_help();
    }

	Elf32_Ehdr eh;			/* elf-header is fixed size */
	Elf32_Shdr* sh_table;	/* section-header table is variable size */
	Elf32_Phdr* ph_table;
	ifstream file_handle;
	file_handle.open(argv[optind], ios::in|ios::binary);
	if (file_handle.is_open()) {
		read_elf_header(&file_handle, &eh);

		if (!is_ELF(eh)) {
			return -1;
		}

		ph_table = new Elf32_Phdr[eh.e_phnum];
		sh_table = new Elf32_Shdr[eh.e_shnum];

		/*
		 * ELF Header
		 */
		if (mode == ALL || mode == ELF) {
			display_elf_header(eh);
		}

		/*
		 * Program Header
		 */
		read_program_headers(&file_handle, eh, ph_table);
		if (mode == ALL || mode == PROGRAM) display_program_headers(ph_table, eh.e_phnum);	

		/*
		 * Sections Header
		 */
		read_section_headers(&file_handle, eh, sh_table);
		if (mode == ALL || mode == SECTION) display_section_headers(&file_handle, eh, sh_table);

		/*
		 * Symbols
		 */
		if (mode == ALL || mode == SYMBOL) display_symbols(&file_handle, eh, sh_table);

		if (mode == ALL || mode == DISASSEMBLE) disassemble(&file_handle, eh, sh_table);
		/*
		ofstream output_asm_file;
		string output_asm_file_name = argv[1] + string(".asm");
		output_asm_file.open(output_asm_file_name);
		output_asm_file << "bits 32\n\n";

		char * memblock = new char[0];
		int size = 0;
		file_handle.seekg(0, ios::beg);
		while (file_handle.read(memblock, 1)) {
			output_asm_file << "db 0x" << hex << (int(memblock[0]) & 0xff) << endl;
			size++;
		}
		output_asm_file.close();
		file_handle.close();
		cout << "Written " << to_string(size) << " bytes into " << output_asm_file_name << "!" << endl;
		*/
	}
	return 0;
}
