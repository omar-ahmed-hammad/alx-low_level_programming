#include <elf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

void check_elf(unsigned char *e_i);
void print_magic(unsigned char *e_i);
void print_class(unsigned char *e_i);
void print_data(unsigned char *e_i);
void print_version(unsigned char *e_i);
void print_abi(unsigned char *e_i);
void print_osabi(unsigned char *e_i);
void print_type(unsigned int e_t, unsigned char *e_i);
void print_entry(unsigned long int e_e, unsigned char *e_i);
void close_elf(int elf);

/**
 * check_elf - function to Check an ELF file
 * @e_i: pointer to the ELF magic numbers
 *
 * Description: function to Checks an ELF file - exit code 98
 */
void check_elf(unsigned char *e_i)
{
	int index;
	for (index = 0; index < 4; index++)
	{
		if (e_i[index] != 127 && e_i[index] != 'E' &&
		    e_i[index] != 'L' && e_i[index] != 'F')
		{
			dprintf(STDERR_FILENO, "Error: Not an ELF file\n");
			exit(98);
		}
	}
}

/**
 * print_magic - function to print the magic numbers
 * @e_i: pointer the ELF magic numbers
 *
 * Description: function to prints the magic numbers
 */
void print_magic(unsigned char *e_i)
{
	int index;

	printf(" Magic: ");

	for (index = 0; index < EI_NIDENT; index++)
	{
		printf("%02x", e_i[index]);

		if (index == EI_NIDENT - 1)
			printf("\n");
		else
			printf(" ");
	}
}

/**
 * print_class - Function to Print the class
 * @e_i: pointer to the ELF class
 *
 * Description: Function to Prints the class
 */
void print_class(unsigned char *e_i)
{
	printf(" Class: ");

	switch (e_i[EI_CLASS])
	{
	case ELFCLASSNONE:
		printf("none\n");
		break;
	case ELFCLASS32:
		printf("ELF32\n");
		break;
	case ELFCLASS64:
		printf("ELF64\n");
		break;
	default:
		printf("<unknown: %x>\n", e_i[EI_CLASS]);
	}
}


/**
 * print_data - function to Print data of an ELF header
 * @e_i: pointer to the ELF class
 *
 * Description: function to Prints data of an ELF header
 */
void print_data(unsigned char *e_i)
{
	printf(" Data: ");

	switch (e_i[EI_DATA])
	{
	case ELFDATANONE:
		printf("none\n");
		break;
	case ELFDATA2LSB:
		printf("2's complement, little endian\n");
		break;
	case ELFDATA2MSB:
		printf("2's complement, big endian\n");
		break;
	default:
		printf("<unknown: %x>\n", e_i[EI_CLASS]);
	}

}

/**
 * print_version - function to Print the version an ELF header
 * @e_i: pointer to the ELF version
 * 
 * Description: function to Prints the version an ELF header
 **/
void print_version(unsigned char *e_i)
{
	 printf(" Version: %d",
			  e_i[EI_VERSION]);

	switch (e_i[EI_VERSION])
	{
	case EV_CURRENT:
		printf(" (current)\n");
		break;
	default:
		printf("\n");
		break;
	}
}

/**
 * print_osabi - function to Print the OS/ABI of an ELF header
 * @e_i: A pointer to the ELF version.
 *
 * Description: function Prints the OS/ABI of an ELF header
 */
void print_osabi(unsigned char *e_i)
{
	printf(" OS/ABI: ");

	switch (e_i[EI_OSABI])
	{
	case ELFOSABI_NONE:
		printf("UNIX - System V\n");
		break;
	case ELFOSABI_HPUX:
		printf("UNIX - HP-UX\n");
		break;
	case ELFOSABI_NETBSD:
		printf("UNIX - NetBSD\n");
		break;
	case ELFOSABI_LINUX:
		printf("UNIX - Linux\n");
		break;
	case ELFOSABI_SOLARIS:
		printf("UNIX - Solaris\n");
		break;
	case ELFOSABI_IRIX:
		printf("UNIX - IRIX\n");
		break;
	case ELFOSABI_FREEBSD:
		printf("UNIX - FreeBSD\n");
		break;
	case ELFOSABI_TRU64:
		printf("UNIX - TRU64\n");
		break;
	case ELFOSABI_ARM:
		printf("ARM\n");
		break;
	case ELFOSABI_STANDALONE:
		printf("Standalone App\n");
		break;
	default:
		printf("<unknown: %x>\n", e_i[EI_OSABI]);
	}
}

/**
 * print_abi - function to Print the ABI version of an ELF header
 * @e_i:pointer to an array with the ELF ABI version
 *
 * Description: function to Print the ABI version of an ELF header
 */
void print_abi(unsigned char *e_i)
{
	printf(" ABI Version: %d\n",
		e_i[EI_ABIVERSION]);
}


/**
 * print_type - function to Print the type of an ELF header
 * @e_t: ELF type
 * @e_i: pointer to an array with the ELF class
 *
 * Description: function to Print the type of an ELF header
 */
void print_type(unsigned int e_t, unsigned char *e_i)
{
	if (e_i[EI_DATA] == ELFDATA2MSB)
		e_t >>= 8;

	printf(" Type: ");

	switch (e_t)
	{
	case ET_NONE:
		printf("NONE (None)\n");
		break;
	case ET_REL:
		printf("REL (Relocatable file)\n");
		break;
	case ET_EXEC:
		printf("EXEC (Executable file)\n");
		break;
	case ET_DYN:
		printf("DYN (Shared object file)\n");
		break;
	case ET_CORE:
		printf("CORE (Core file)\n");
		break;
	default:
		printf("<unknown: %x>\n", e_t);
	}
}


/**
 * print_entry - function to Print the entry point of an ELF header
 * @e_e: The address of the ELF entry point
 * @e_i: pointer to an array with the ELF class
 *
 * Description: function to Print the entry point of an ELF header
 */
void print_entry(unsigned long int e_e, unsigned char *e_i)
{
	printf(" Entry point address: ");

	if (e_i[EI_DATA] == ELFDATA2MSB)
	{
		e_e = ((e_e << 8) & 0xFF00FF00) |
			  ((e_e >> 8) & 0xFF00FF);
		e_e = (e_e << 16) | (e_e >> 16);
	}

	if (e_i[EI_CLASS] == ELFCLASS32)
		printf("%#x\n", (unsigned int)e_e);

	else
		printf("%#lx\n", e_e);
}

/**
 * close_elf - function that Closes an ELF file.
 * @elf:  file descriptor of the ELF file.
 *
 * Description: when the file cann't be closed - exit code 98.
 */
void close_elf(int elf)
{
	if (close(elf) == -1)
	{
		dprintf(STDERR_FILENO,
			"Error: Can't close fd %d\n", elf);
		exit(98);
	}
}


/**
 * main - function to Display the information contained in the ELF Header
 * @argc: number of arguments provided to the program
 * @argv: array of pointers to the arguments
 *
 * Return: 0 when successful
 * Description: If the function fails - exit code 98.
 */
int main(int __attribute__((__unused__)) argc, char *argv[])
{
	Elf64_Ehdr *header;
	int o, r;

	o = open(argv[1], O_RDONLY);
	if (o == -1)
	{
		dprintf(STDERR_FILENO, "Error: Can't read file %s\n", argv[1]);
		exit(98);
	}
	header = malloc(sizeof(Elf64_Ehdr));
	if (header == NULL)
	{
		close_elf(o);
		dprintf(STDERR_FILENO, "Error: Can't read file %s\n", argv[1]);
		exit(98);
	}
	r = read(o, header, sizeof(Elf64_Ehdr));
	if (r == -1)
	{
		free(header);
		close_elf(o);
		dprintf(STDERR_FILENO, "Error: `%s`: No such file\n", argv[1]);
		exit(98);
	}

	check_elf(header->e_ident);
	printf("ELF Header:\n");
	print_magic(header->e_ident);
	print_class(header->e_ident);
	print_data(header->e_ident);
	print_version(header->e_ident);
	print_osabi(header->e_ident);
	print_abi(header->e_ident);
	print_type(header->e_type, header->e_ident);
	print_entry(header->e_entry, header->e_ident);

	free(header);
	close_elf(o);
	return (0);
}
