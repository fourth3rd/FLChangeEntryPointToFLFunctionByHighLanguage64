#define _CRT_SECURE_NO_WARNINGS

#include<stdio.h>
#include<string>
#include<Windows.h>
#include<vector>


std::vector<std::pair<int32_t, std::pair<int32_t, int32_t > > > vctParseRelocation;
typedef struct Section
{
	char Name[8];
	int32_t VirtualSize;
	int32_t RVA;
	int32_t SizeOfRawData;
	int32_t PoitnerToRawData;
	int32_t POinterToRelocations;
	int32_t PointerToLineNumber;
	WORD NumberOfRelocations;
	WORD NumberOfLineNumbers;
	int32_t Characteristics;
	int32_t TempOffset;
}Section;

int main(int argc, char* argv[])
{
	if(argc != 3)
	{
		printf("FLProtection.exe Source Destion");
		return 1;
	}

	char pNameSrc[0x100] = { 0 };
	char pNameDes[0x100] = { 0 };

	memset(pNameDes, '\x00', sizeof(pNameDes));
	memset(pNameSrc, '\x00', sizeof(pNameSrc));

	strcpy(pNameSrc, argv[1]);
	strcpy(pNameDes, argv[2]);


	FILE* fp = fopen(pNameSrc, "rb");//

	if(fp)
	{
		fseek(fp, 0, SEEK_END);//
		size_t stSize = ftell(fp);

		int i32FLSize = 0x1000;

		char* buf = new char[stSize + i32FLSize];

		fseek(fp, 0, SEEK_SET);
		fread(buf, stSize, 1, fp);

		fclose(fp);

		PIMAGE_DOS_HEADER pDosH;
		PIMAGE_NT_HEADERS pNtH;
		PIMAGE_SECTION_HEADER pSecH;

		pDosH = (PIMAGE_DOS_HEADER)buf;
		pNtH = (PIMAGE_NT_HEADERS)((LPBYTE)buf + pDosH->e_lfanew);

		if(pNtH->Signature != 0x4550)
		{
			printf("윈도우 실행 파일이 아닙니다.\n");

			return 1;
		}

		fp = fopen(pNameDes, "wb");
		fseek(fp, 0, SEEK_SET);

		int64_t i32FileBaseAddress = pNtH->OptionalHeader.ImageBase;
		int32_t i32EntryPoint = pNtH->OptionalHeader.AddressOfEntryPoint;
		int32_t i32PointerToRawData = 0;
		int32_t i32RVA = 0;
		int32_t i32SizeOfRawData = 0;
		int32_t i32SizeOfCode = pNtH->OptionalHeader.SizeOfCode;
		int32_t i32SizeOfImage = pNtH->OptionalHeader.SizeOfImage;
		int32_t i32TextSizeOfCode = 0;
		int32_t i32FileEntryPointAddress = 0;
		int32_t i32TextSection = 0;

		int32_t i32cfgRVA = 0;
		int32_t i32cfgPointerToRawData = 0;
		int32_t i32cfgSizeofRawData = 0;
		int32_t i32cfgSection = 0;

		int32_t i32RelocRVA = 0;
		int32_t i32RelocPointerToRawData = 0;
		int32_t i32RelocSizeofRawData = 0;
		int32_t i32FileTextRva = 0;

		int32_t i32DataRVA = 0;
		int32_t i32DataSizeOfRawData = 0;
		int32_t i32DataPointerToRawData = 0;

		int32_t i32RscRVA = 0;
		int32_t i32RscSizeOfRawData = 0;
		int32_t i32RscPointerToRawData = 0;

		std::vector< Section> vctSection;

		int32_t* pModifiedTextCharacteristics = (int*)0xe0000060;
		int32_t i32FLStart = pDosH->e_lfanew + sizeof(IMAGE_NT_HEADERS);
		i32FileEntryPointAddress = pDosH->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + 0x10;

		int32_t i32Start = 0;
		int32_t OriginalImageOfSize = i32SizeOfImage;

		int32_t i32RdataSection = 0;

		for(int i = 0; i < pNtH->FileHeader.NumberOfSections; i++)
		{
			pSecH = (PIMAGE_SECTION_HEADER)((LPBYTE)buf + pDosH->e_lfanew + sizeof(IMAGE_NT_HEADERS64) + (i * sizeof(IMAGE_SECTION_HEADER)));

			Section Temp;
			int32_t i32SectionParse = pDosH->e_lfanew + sizeof(IMAGE_NT_HEADERS64) + (i * sizeof(IMAGE_SECTION_HEADER));

			int32_t i32OrigialSize = 0;

			memcpy((void*)&i32OrigialSize, (void*)&buf[i32SectionParse + 0x10], 4);

			if(i == pNtH->FileHeader.NumberOfSections - 1)
			{
				i32Start = pSecH->SizeOfRawData + pSecH->PointerToRawData;
				//i32Start /= 4;

				i32OrigialSize += i32FLSize;
				memcpy((void*)&buf[i32SectionParse + 0x10], (void*)&i32OrigialSize, 4);

				int32_t i32Original = 0;
				memcpy((void*)&i32Original, (void*)&buf[i32SectionParse + 0x8], 4);

				i32Original &= 0xfffff000;

				i32Original += 0x2000;
				memcpy((void*)&buf[i32SectionParse + 0x8], (void*)&i32Original, 4);


			}

			Temp.PoitnerToRawData = pSecH->PointerToRawData;
			Temp.RVA = pSecH->VirtualAddress;
			Temp.SizeOfRawData = pSecH->SizeOfRawData;
			strcpy(Temp.Name, (const char*)pSecH->Name);
			vctSection.push_back(Temp);

			memcpy((void*)&pSecH->Characteristics, (void*)&pModifiedTextCharacteristics, 4);
			i32FLStart += sizeof(IMAGE_SECTION_HEADER);

			if(!strcmp((const char*)pSecH->Name, ".text"))
			{
				i32PointerToRawData = pSecH->PointerToRawData;
				i32RVA = pSecH->VirtualAddress;
				i32SizeOfRawData = pSecH->SizeOfRawData;
				i32FileTextRva = pDosH->e_lfanew + sizeof(IMAGE_NT_HEADERS64) + (i * sizeof(IMAGE_SECTION_HEADER));
				i32FileTextRva += 0xc;
				i32TextSection = i;
				//i32TextSizeOfCode=
			}
			else if(!strcmp((const char*)pSecH->Name, ".reloc"))
			{
				i32RelocRVA = pSecH->VirtualAddress;
				i32RelocPointerToRawData = pSecH->PointerToRawData;
				i32RelocSizeofRawData = pSecH->SizeOfRawData;
			}
			else if(!strcmp((const char*)pSecH->Name, ".00cfg"))
			{
				i32cfgRVA = pSecH->VirtualAddress;
				i32cfgPointerToRawData = pSecH->PointerToRawData;
				i32cfgSizeofRawData = pSecH->SizeOfRawData;
				i32cfgSection = i;
			}
			else if(!strcmp((const char*)pSecH->Name, ".rdata"))
			{
				i32RdataSection = i;
			}
			else if(!strcmp((const char*)pSecH->Name, ".data"))
			{
				i32DataRVA = pSecH->VirtualAddress;
				i32DataSizeOfRawData = pSecH->SizeOfRawData;;
				i32DataPointerToRawData = pSecH->PointerToRawData;;
			}
			else if(!strcmp((const char*)pSecH->Name, ".rsrc"))
			{
				i32RscRVA = pSecH->VirtualAddress;
				i32RscSizeOfRawData = pSecH->SizeOfRawData;;
				i32RscPointerToRawData = pSecH->PointerToRawData;;
			}
		}

		int32_t i32RollBackEntryPoint = i32RelocRVA + i32Start - i32RelocPointerToRawData;

		int32_t* ModifiedSizeOfImage = (int32_t*)(pNtH->OptionalHeader.SizeOfImage + i32FLSize);
		int32_t* ModifiedEntryPoint = (int32_t*)(i32RelocRVA + i32Start - i32RelocPointerToRawData);
		WORD* NumberOfSection = (WORD*)(pNtH->FileHeader.NumberOfSections);

		memcpy((void*)&pNtH->OptionalHeader.SizeOfImage, (void*)&ModifiedSizeOfImage, 4);
		memcpy((void*)&pNtH->OptionalHeader.AddressOfEntryPoint, (void*)&ModifiedEntryPoint, 4);
		memcpy((void*)&pNtH->FileHeader.NumberOfSections, (void*)&NumberOfSection, 2);

		int32_t i32stSizeCnt = 0x0;
		bool bCheckIsDllorExe = false;


		//buf[stSize + i32stSizeCnt++] = '\xeb';
		//buf[stSize + i32stSizeCnt++] = '\xfe';

		if((pNtH->FileHeader.Characteristics & 0xf000) == 0x2000)
		{
			bCheckIsDllorExe = true;
		}


		buf[stSize + i32stSizeCnt++] = '\x50';
		buf[stSize + i32stSizeCnt++] = '\x53';
		buf[stSize + i32stSizeCnt++] = '\x51';
		buf[stSize + i32stSizeCnt++] = '\x52';
		buf[stSize + i32stSizeCnt++] = '\x57';
		buf[stSize + i32stSizeCnt++] = '\x56';
		buf[stSize + i32stSizeCnt++] = '\x41';
		buf[stSize + i32stSizeCnt++] = '\x50';
		buf[stSize + i32stSizeCnt++] = '\x41';
		buf[stSize + i32stSizeCnt++] = '\x51';
		buf[stSize + i32stSizeCnt++] = '\x41';
		buf[stSize + i32stSizeCnt++] = '\x52';
		buf[stSize + i32stSizeCnt++] = '\x41';
		buf[stSize + i32stSizeCnt++] = '\x53';
		buf[stSize + i32stSizeCnt++] = '\x41';
		buf[stSize + i32stSizeCnt++] = '\x54';
		buf[stSize + i32stSizeCnt++] = '\x41';
		buf[stSize + i32stSizeCnt++] = '\x55';
		buf[stSize + i32stSizeCnt++] = '\x41';
		buf[stSize + i32stSizeCnt++] = '\x56';
		buf[stSize + i32stSizeCnt++] = '\x41';
		buf[stSize + i32stSizeCnt++] = '\x57';

		std::string strReverseDesName;
		std::vector<std::string> vctReverseDesName;

		int32_t i32SizeNameDes = strlen(pNameDes);
		for(int32_t i = 0; i < i32SizeNameDes; i += 4)
		{
			for(int32_t j = 0; j < 4; j++)
			{
				strReverseDesName.push_back(pNameDes[i + j]);
			}
			vctReverseDesName.push_back(strReverseDesName);
			strReverseDesName.clear();
		}

		int32_t i32SizeVctDesName = vctReverseDesName.size();
		int32_t i32TotalStackPop = 0;

		if(bCheckIsDllorExe)
		{
			i32TotalStackPop = i32SizeVctDesName + 3;


			buf[stSize + i32stSizeCnt++] = '\x6a';
			buf[stSize + i32stSizeCnt++] = '\x00';//push 0x0

			for(int32_t i = i32SizeVctDesName - 1; i >= 0; i--)
			{
				buf[stSize + i32stSizeCnt++] = '\x48';
				buf[stSize + i32stSizeCnt++] = '\x31';
				buf[stSize + i32stSizeCnt++] = '\xc0';

				std::string strTemp = vctReverseDesName[i];
				buf[stSize + i32stSizeCnt++] = '\x48';
				buf[stSize + i32stSizeCnt++] = '\xb8';
				buf[stSize + i32stSizeCnt++] = strTemp[0];
				buf[stSize + i32stSizeCnt++] = '\x0';
				buf[stSize + i32stSizeCnt++] = strTemp[1];
				buf[stSize + i32stSizeCnt++] = '\x0';
				buf[stSize + i32stSizeCnt++] = strTemp[2];
				buf[stSize + i32stSizeCnt++] = '\x0';
				buf[stSize + i32stSizeCnt++] = strTemp[3];
				buf[stSize + i32stSizeCnt++] = '\x0';
				buf[stSize + i32stSizeCnt++] = '\x50';
			}
			vctReverseDesName.clear();


			buf[stSize + i32stSizeCnt++] = '\x54';//push rsp

			buf[stSize + i32stSizeCnt++] = '\x65';
			buf[stSize + i32stSizeCnt++] = '\x48';
			buf[stSize + i32stSizeCnt++] = '\x8b';
			buf[stSize + i32stSizeCnt++] = '\x04';
			buf[stSize + i32stSizeCnt++] = '\x25';
			buf[stSize + i32stSizeCnt++] = '\x30';
			buf[stSize + i32stSizeCnt++] = '\x0';
			buf[stSize + i32stSizeCnt++] = '\x0';
			buf[stSize + i32stSizeCnt++] = '\x0';//mov rax, qword ptr ds:[30]

			buf[stSize + i32stSizeCnt++] = '\x48';
			buf[stSize + i32stSizeCnt++] = '\x8b';
			buf[stSize + i32stSizeCnt++] = '\x40';
			buf[stSize + i32stSizeCnt++] = '\x60';// mov rax, qword ptr ds:[rax+0x60]

			buf[stSize + i32stSizeCnt++] = '\x48';
			buf[stSize + i32stSizeCnt++] = '\x8b';
			buf[stSize + i32stSizeCnt++] = '\x40';
			buf[stSize + i32stSizeCnt++] = '\x18';// mov rax, qword ptr ds:[rax+0x18]

			buf[stSize + i32stSizeCnt++] = '\x48';
			buf[stSize + i32stSizeCnt++] = '\x8b';
			buf[stSize + i32stSizeCnt++] = '\x58';
			buf[stSize + i32stSizeCnt++] = '\x30';// mov rbx, qword ptr ds:[rax+0x30]

			buf[stSize + i32stSizeCnt++] = '\x48';
			buf[stSize + i32stSizeCnt++] = '\x89';
			buf[stSize + i32stSizeCnt++] = '\xda';// mov rdx, rbx

			buf[stSize + i32stSizeCnt++] = '\x48';
			buf[stSize + i32stSizeCnt++] = '\x8b';
			buf[stSize + i32stSizeCnt++] = '\x7a';
			buf[stSize + i32stSizeCnt++] = '\x40';// mov rdi, qword tpr ds:[rdx+0x40]

			//buf[stSize + i32stSizeCnt++] = '\x48';
			//buf[stSize + i32stSizeCnt++] = '\x83';
			//buf[stSize + i32stSizeCnt++] = '\xff';
			//buf[stSize + i32stSizeCnt++] = '\x00';// cmp rdi,0

			////buf[stSize + i32stSizeCnt++] = '\x74';
			////buf[stSize + i32stSizeCnt++] = '\xfe';// 빙빙 도는거여

			buf[stSize + i32stSizeCnt++] = '\x57';// push rdi

			buf[stSize + i32stSizeCnt++] = '\x48';
			buf[stSize + i32stSizeCnt++] = '\x31';
			buf[stSize + i32stSizeCnt++] = '\xc9';// xor ecx

			buf[stSize + i32stSizeCnt++] = '\x48';
			buf[stSize + i32stSizeCnt++] = '\x8b';
			buf[stSize + i32stSizeCnt++] = '\x3c';
			buf[stSize + i32stSizeCnt++] = '\x24';// mov rdi,[rsp]


			buf[stSize + i32stSizeCnt++] = '\x48';
			buf[stSize + i32stSizeCnt++] = '\x8b';
			buf[stSize + i32stSizeCnt++] = '\x74';
			buf[stSize + i32stSizeCnt++] = '\x24';
			buf[stSize + i32stSizeCnt++] = '\x08';// mov rsi,[rsp+8]

			buf[stSize + i32stSizeCnt++] = '\x48';
			buf[stSize + i32stSizeCnt++] = '\x03';
			buf[stSize + i32stSizeCnt++] = '\xf9';// add rdi, rcx

			buf[stSize + i32stSizeCnt++] = '\x48';
			buf[stSize + i32stSizeCnt++] = '\x03';
			buf[stSize + i32stSizeCnt++] = '\xf1';// add rsi, rcx

			buf[stSize + i32stSizeCnt++] = '\x48';
			buf[stSize + i32stSizeCnt++] = '\x83';
			buf[stSize + i32stSizeCnt++] = '\xc1';
			buf[stSize + i32stSizeCnt++] = '\x01';// add rcx, 1

			i32SizeNameDes = (i32SizeNameDes + 1) * 2;
			char cSizeNameDes[4] = { 0 };
			memcpy((void*)&cSizeNameDes, (void*)&i32SizeNameDes, 4);

			buf[stSize + i32stSizeCnt++] = '\x48';
			buf[stSize + i32stSizeCnt++] = '\x81';
			buf[stSize + i32stSizeCnt++] = '\xf9';
			buf[stSize + i32stSizeCnt++] = cSizeNameDes[0];
			buf[stSize + i32stSizeCnt++] = cSizeNameDes[1];
			buf[stSize + i32stSizeCnt++] = cSizeNameDes[2];
			buf[stSize + i32stSizeCnt++] = cSizeNameDes[3];

			buf[stSize + i32stSizeCnt++] = '\x73';
			buf[stSize + i32stSizeCnt++] = '\xf'; // je

			buf[stSize + i32stSizeCnt++] = '\x48';
			buf[stSize + i32stSizeCnt++] = '\x31';
			buf[stSize + i32stSizeCnt++] = '\xdb';// add rsi, rcx

			buf[stSize + i32stSizeCnt++] = '\x8a';
			buf[stSize + i32stSizeCnt++] = '\x1e';// mov bl , word ptr ds:[rsi]

			buf[stSize + i32stSizeCnt++] = '\x38';
			buf[stSize + i32stSizeCnt++] = '\x1f';// cmp byte ptr ds:[rdi], bl

			buf[stSize + i32stSizeCnt++] = '\x74';
			buf[stSize + i32stSizeCnt++] = '\xdb';

			buf[stSize + i32stSizeCnt++] = '\x5f';// pop rdi



			buf[stSize + i32stSizeCnt++] = '\x48';
			buf[stSize + i32stSizeCnt++] = '\x8b';
			buf[stSize + i32stSizeCnt++] = '\x12';// mov rdx, qword ptr ds:[rdx]

			buf[stSize + i32stSizeCnt++] = '\xeb';
			buf[stSize + i32stSizeCnt++] = '\xcd';// jmp up

			//buf[stSize + i32stSizeCnt++] = '\xeb';
			//buf[stSize + i32stSizeCnt++] = '\xfe';

			buf[stSize + i32stSizeCnt++] = '\x48';
			buf[stSize + i32stSizeCnt++] = '\x83';
			buf[stSize + i32stSizeCnt++] = '\xc4';
			buf[stSize + i32stSizeCnt++] = '\x10';// add rsp, 8

			buf[stSize + i32stSizeCnt++] = '\xff';
			buf[stSize + i32stSizeCnt++] = '\x72';
			buf[stSize + i32stSizeCnt++] = '\x10';// push qword ptr ds:[rdx+0x10] <- Program BaseAddress 

			buf[stSize + i32stSizeCnt++] = '\xff';
			buf[stSize + i32stSizeCnt++] = '\x72';
			buf[stSize + i32stSizeCnt++] = '\x18';// push qword ptr ds:[rdx+0x18] <- Program EntryPoint



			//if(bCheckIsDllorExe)
			//{
			buf[stSize + i32stSizeCnt++] = '\x48';
			buf[stSize + i32stSizeCnt++] = '\x8b';
			buf[stSize + i32stSizeCnt++] = '\x0c';
			buf[stSize + i32stSizeCnt++] = '\x24';// mov rcx, qword ptr ds:[rsp]


			buf[stSize + i32stSizeCnt++] = '\x48';
			buf[stSize + i32stSizeCnt++] = '\x81';
			buf[stSize + i32stSizeCnt++] = '\xc1';
			buf[stSize + i32stSizeCnt++] = '\x6c';
			buf[stSize + i32stSizeCnt++] = '\x04';
			buf[stSize + i32stSizeCnt++] = '\x0';
			buf[stSize + i32stSizeCnt++] = '\x0';// add rcx,0x46c

			buf[stSize + i32stSizeCnt++] = '\x48';
			buf[stSize + i32stSizeCnt++] = '\x8b';
			buf[stSize + i32stSizeCnt++] = '\x09';// mov rcx, qword ptr ds:[rcx]

			//buf[stSize + i32stSizeCnt++] = '\x48';
			buf[stSize + i32stSizeCnt++] = '\x83';
			buf[stSize + i32stSizeCnt++] = '\xf9';
			buf[stSize + i32stSizeCnt++] = '\x01';// cmp ecx, 1

			buf[stSize + i32stSizeCnt++] = '\x72';
			buf[stSize + i32stSizeCnt++] = '\x22';// jb down

			char cSizeVctDesName[4] = { 0 };
			i32SizeVctDesName += 3;
			i32SizeVctDesName *= 4;
			memcpy((void*)&cSizeVctDesName, (void*)&i32SizeVctDesName, 4);


			buf[stSize + i32stSizeCnt++] = '\x48';
			buf[stSize + i32stSizeCnt++] = '\x81';
			buf[stSize + i32stSizeCnt++] = '\xc4';
			buf[stSize + i32stSizeCnt++] = cSizeVctDesName[0];
			buf[stSize + i32stSizeCnt++] = cSizeVctDesName[1];
			buf[stSize + i32stSizeCnt++] = cSizeVctDesName[2];
			buf[stSize + i32stSizeCnt++] = cSizeVctDesName[3];


			buf[stSize + i32stSizeCnt++] = '\x41';
			buf[stSize + i32stSizeCnt++] = '\x5f';

			buf[stSize + i32stSizeCnt++] = '\x41';
			buf[stSize + i32stSizeCnt++] = '\x5e';

			buf[stSize + i32stSizeCnt++] = '\x41';
			buf[stSize + i32stSizeCnt++] = '\x5d';

			buf[stSize + i32stSizeCnt++] = '\x41';
			buf[stSize + i32stSizeCnt++] = '\x5c';

			buf[stSize + i32stSizeCnt++] = '\x41';
			buf[stSize + i32stSizeCnt++] = '\x5b';

			buf[stSize + i32stSizeCnt++] = '\x41';
			buf[stSize + i32stSizeCnt++] = '\x5a';

			buf[stSize + i32stSizeCnt++] = '\x41';
			buf[stSize + i32stSizeCnt++] = '\x59';

			buf[stSize + i32stSizeCnt++] = '\x41';
			buf[stSize + i32stSizeCnt++] = '\x58';

			buf[stSize + i32stSizeCnt++] = '\x5e';
			buf[stSize + i32stSizeCnt++] = '\x5f';
			buf[stSize + i32stSizeCnt++] = '\x5a';
			buf[stSize + i32stSizeCnt++] = '\x59';
			buf[stSize + i32stSizeCnt++] = '\x5b';
			buf[stSize + i32stSizeCnt++] = '\x58';



			int i32AlreadyDecoding = i32stSizeCnt + i32RollBackEntryPoint;
			int i32FLfunctionToEntryPointDecoding = i32EntryPoint - i32AlreadyDecoding - 5;// -3;

			char cFLfunctionToEntryPointDecoding[4] = { 0, };

			memcpy((void*)&cFLfunctionToEntryPointDecoding, (void*)&i32FLfunctionToEntryPointDecoding, 4);

			buf[stSize + i32stSizeCnt++] = '\xe9';
			buf[stSize + i32stSizeCnt++] = cFLfunctionToEntryPointDecoding[0];
			buf[stSize + i32stSizeCnt++] = cFLfunctionToEntryPointDecoding[1];
			buf[stSize + i32stSizeCnt++] = cFLfunctionToEntryPointDecoding[2];
			buf[stSize + i32stSizeCnt++] = cFLfunctionToEntryPointDecoding[3];

		}
		else
		{
			i32TotalStackPop += 2;
			buf[stSize + i32stSizeCnt++] = '\x65';
			buf[stSize + i32stSizeCnt++] = '\x48';
			buf[stSize + i32stSizeCnt++] = '\x8b';
			buf[stSize + i32stSizeCnt++] = '\x04';
			buf[stSize + i32stSizeCnt++] = '\x25';
			buf[stSize + i32stSizeCnt++] = '\x30';
			buf[stSize + i32stSizeCnt++] = '\x0';
			buf[stSize + i32stSizeCnt++] = '\x0';
			buf[stSize + i32stSizeCnt++] = '\x0';//mov rax, qword ptr ds:[30]

			buf[stSize + i32stSizeCnt++] = '\x48';
			buf[stSize + i32stSizeCnt++] = '\x8b';
			buf[stSize + i32stSizeCnt++] = '\x40';
			buf[stSize + i32stSizeCnt++] = '\x60';// mov rax, qword ptr ds:[rax+0x60]

			buf[stSize + i32stSizeCnt++] = '\x48';
			buf[stSize + i32stSizeCnt++] = '\x8b';
			buf[stSize + i32stSizeCnt++] = '\x40';
			buf[stSize + i32stSizeCnt++] = '\x18';// mov rax, qword ptr ds:[rax+0x18]

			buf[stSize + i32stSizeCnt++] = '\x48';
			buf[stSize + i32stSizeCnt++] = '\x8b';
			buf[stSize + i32stSizeCnt++] = '\x58';
			buf[stSize + i32stSizeCnt++] = '\x10';// mov rbx, qword ptr ds:[rax+0x10]

			buf[stSize + i32stSizeCnt++] = '\xff';
			buf[stSize + i32stSizeCnt++] = '\x73';
			buf[stSize + i32stSizeCnt++] = '\x30';// 

			buf[stSize + i32stSizeCnt++] = '\xff';
			buf[stSize + i32stSizeCnt++] = '\x73';
			buf[stSize + i32stSizeCnt++] = '\x38';

		}


		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x14';
		buf[stSize + i32stSizeCnt++] = '\x24';

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x81';// 
		buf[stSize + i32stSizeCnt++] = '\xc2';
		buf[stSize + i32stSizeCnt++] = '\x00';
		buf[stSize + i32stSizeCnt++] = '\x04';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';

		buf[stSize + i32stSizeCnt++] = '\x52';


		buf[stSize + i32stSizeCnt++] = '\x65';
		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x04';
		buf[stSize + i32stSizeCnt++] = '\x25';
		buf[stSize + i32stSizeCnt++] = '\x30';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';//mov rax, qword ptr ds:[30]

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x40';
		buf[stSize + i32stSizeCnt++] = '\x60';// mov rax, qword ptr ds:[rax+0x60]

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x40';
		buf[stSize + i32stSizeCnt++] = '\x18';// mov rax, qword ptr ds:[rax+0x18]

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x58';
		buf[stSize + i32stSizeCnt++] = '\x10';// mov rbx, qword ptr ds:[rax+0x10]

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x89';
		buf[stSize + i32stSizeCnt++] = '\xda';// mov rdx, rbx

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x7a';
		buf[stSize + i32stSizeCnt++] = '\x60';// mov rdi, qword tpr ds:[rdx+0x60]

		buf[stSize + i32stSizeCnt++] = '\x57';// push rdi

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x31';
		buf[stSize + i32stSizeCnt++] = '\xc9';// xor ecx

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x3c';
		buf[stSize + i32stSizeCnt++] = '\x24';// mov rdi,[rsp]


		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x74';
		buf[stSize + i32stSizeCnt++] = '\x24';
		buf[stSize + i32stSizeCnt++] = '\x08';// mov rsi,[rsp+8]

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x03';
		buf[stSize + i32stSizeCnt++] = '\xf9';// add rdi, rcx

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x03';
		buf[stSize + i32stSizeCnt++] = '\xf1';// add rsi, rcx

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xc1';
		buf[stSize + i32stSizeCnt++] = '\x01';// add rcx, 1

		char cKernel32[] = "KERNELBASE.dll";
		int32_t i32KenrelSize = strlen(cKernel32);//

		i32KenrelSize = (i32KenrelSize + 1) * 2;
		char cSizeKernel32[4] = { 0 };
		memcpy((void*)&cSizeKernel32, (void*)&i32KenrelSize, 4);

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x81';
		buf[stSize + i32stSizeCnt++] = '\xf9';
		buf[stSize + i32stSizeCnt++] = cSizeKernel32[0];
		buf[stSize + i32stSizeCnt++] = cSizeKernel32[1];
		buf[stSize + i32stSizeCnt++] = cSizeKernel32[2];
		buf[stSize + i32stSizeCnt++] = cSizeKernel32[3];

		buf[stSize + i32stSizeCnt++] = '\x73';
		buf[stSize + i32stSizeCnt++] = '\x0f'; // je

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x31';
		buf[stSize + i32stSizeCnt++] = '\xd8';// xor rbx, rbx

		buf[stSize + i32stSizeCnt++] = '\x8a';
		buf[stSize + i32stSizeCnt++] = '\x1e';// mov bl , byte ptr ds:[rsi]

		buf[stSize + i32stSizeCnt++] = '\x38';
		buf[stSize + i32stSizeCnt++] = '\x1f';// cmp byte ptr ds:[rdi], bl

		buf[stSize + i32stSizeCnt++] = '\x74';
		buf[stSize + i32stSizeCnt++] = '\xdb';

		buf[stSize + i32stSizeCnt++] = '\x5f';// pop rdi

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x12';// mov rdx, qword ptr ds:[rdx]

		buf[stSize + i32stSizeCnt++] = '\xeb';
		buf[stSize + i32stSizeCnt++] = '\xcd';// jmp up

		//buf[stSize + i32stSizeCnt++] = '\xeb';
		//buf[stSize + i32stSizeCnt++] = '\xfe';

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xc4';
		buf[stSize + i32stSizeCnt++] = '\x08';// add rsp,8

		buf[stSize + i32stSizeCnt++] = '\xff';
		buf[stSize + i32stSizeCnt++] = '\x72';
		buf[stSize + i32stSizeCnt++] = '\x30';// push qword ptr ds:[rdx+0x30] <- KERNEL32 BaseAddress 



		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x04';
		buf[stSize + i32stSizeCnt++] = '\x24';// mov rax,[rsp+8]

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x89';
		buf[stSize + i32stSizeCnt++] = '\xc3';// mov rbx, rax

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xc3';
		buf[stSize + i32stSizeCnt++] = '\x3c';// add rbx, 0x3c

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x31';
		buf[stSize + i32stSizeCnt++] = '\xf6';//xor rsi, rsi

		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x33';// mov esi,[ebx]

		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xc6';
		buf[stSize + i32stSizeCnt++] = '\x08';// add esi,8

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x31';
		buf[stSize + i32stSizeCnt++] = '\xdb';// xor rbx, rbx

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x89';
		buf[stSize + i32stSizeCnt++] = '\xf3';// add rbx, rsi

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x01';
		buf[stSize + i32stSizeCnt++] = '\xc3';// add rbx, rax

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x81';
		buf[stSize + i32stSizeCnt++] = '\xc3';
		buf[stSize + i32stSizeCnt++] = '\x80';
		buf[stSize + i32stSizeCnt++] = '\x00';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';// add rbx,0x80

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x31';
		buf[stSize + i32stSizeCnt++] = '\xf6';//xor rsi, rsi

		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x33';// mov esi,[ebx]


		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x31';
		buf[stSize + i32stSizeCnt++] = '\xdb';// xor rbx, rbx

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x89';
		buf[stSize + i32stSizeCnt++] = '\xf3';// add rbx, rsi

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x01';
		buf[stSize + i32stSizeCnt++] = '\xc3';// add rbx, rax

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x89';
		buf[stSize + i32stSizeCnt++] = '\x5c';
		buf[stSize + i32stSizeCnt++] = '\x24';
		buf[stSize + i32stSizeCnt++] = '\xf8';// mov [rsp-0x8], rbx

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xc3';
		buf[stSize + i32stSizeCnt++] = '\x20';// add rbx, 0x20

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x31';
		buf[stSize + i32stSizeCnt++] = '\xf6';//xor rsi, rsi

		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x33';// mov esi,[rbx]

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x89';
		buf[stSize + i32stSizeCnt++] = '\xf3';// mov rbx, rsi

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x01';
		buf[stSize + i32stSizeCnt++] = '\xc3';// add rbx, rax

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x31';
		buf[stSize + i32stSizeCnt++] = '\xc0';// xor rax, rax

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x31';
		buf[stSize + i32stSizeCnt++] = '\xd2';// xor rdx, rdx

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x31';
		buf[stSize + i32stSizeCnt++] = '\xc9';// xor rcx, rcx

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x31';
		buf[stSize + i32stSizeCnt++] = '\xf6';// xor rsi, rsi

		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x33';// mov esi, [rbx]

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x03';
		buf[stSize + i32stSizeCnt++] = '\x34';
		buf[stSize + i32stSizeCnt++] = '\x24';// add rsi, qword ptr [rsp]

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x7c';
		buf[stSize + i32stSizeCnt++] = '\x24';
		buf[stSize + i32stSizeCnt++] = '\x10';// add rdi, qword ptr [rsp+0x10]

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x81';
		buf[stSize + i32stSizeCnt++] = '\xc7';
		buf[stSize + i32stSizeCnt++] = '\x00';
		buf[stSize + i32stSizeCnt++] = '\x05';
		buf[stSize + i32stSizeCnt++] = '\x00';
		buf[stSize + i32stSizeCnt++] = '\x00';// add rdi, 0x500


		buf[stSize + i32stSizeCnt++] = '\x8a';
		buf[stSize + i32stSizeCnt++] = '\x16';// mov dl,[rsi]

		buf[stSize + i32stSizeCnt++] = '\x8a';
		buf[stSize + i32stSizeCnt++] = '\x0f';// mov cl,[rdi]


		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xc6';
		buf[stSize + i32stSizeCnt++] = '\x01';// add rsi, 1

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xc7';
		buf[stSize + i32stSizeCnt++] = '\x01';// add rdi, 1

		buf[stSize + i32stSizeCnt++] = '\x38';
		buf[stSize + i32stSizeCnt++] = '\xd1';// cmp cl, dl

		buf[stSize + i32stSizeCnt++] = '\x74';
		buf[stSize + i32stSizeCnt++] = '\xf0';// je up

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xc3';
		buf[stSize + i32stSizeCnt++] = '\x04';// add rbx, 4

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xc0';
		buf[stSize + i32stSizeCnt++] = '\x01';// add rax, 1

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xf9';
		buf[stSize + i32stSizeCnt++] = '\x00';// cmp rcx, 0

		buf[stSize + i32stSizeCnt++] = '\x75';
		buf[stSize + i32stSizeCnt++] = '\xc7';

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x89';
		buf[stSize + i32stSizeCnt++] = '\xc1';// mov rcx, rax

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x5c';
		buf[stSize + i32stSizeCnt++] = '\x24';
		buf[stSize + i32stSizeCnt++] = '\xf8';//mov rbx,[rsp-8]

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xc3';
		buf[stSize + i32stSizeCnt++] = '\x24';//add rbx,24

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x04';
		buf[stSize + i32stSizeCnt++] = '\x24';//mov rax,[rsp]

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x31';
		buf[stSize + i32stSizeCnt++] = '\xf6';// xor rsi, rsi

		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x33';// add esi, [rbx]


		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x01';
		buf[stSize + i32stSizeCnt++] = '\xf0';// add rax, rsi

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x89';
		buf[stSize + i32stSizeCnt++] = '\xc3';//mov rbx, rax

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\xc7';
		buf[stSize + i32stSizeCnt++] = '\xc0';
		buf[stSize + i32stSizeCnt++] = '\x02';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';// mov rax, 2

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\xf7';
		buf[stSize + i32stSizeCnt++] = '\xe1';// mul rcx

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x01';
		buf[stSize + i32stSizeCnt++] = '\xc3';//add rbx, rax


		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x31';
		buf[stSize + i32stSizeCnt++] = '\xd2';//xor rdx, rdx


		buf[stSize + i32stSizeCnt++] = '\x66';
		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x13';//mov dx,[rbx]

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x89';
		buf[stSize + i32stSizeCnt++] = '\xd1';//mov rcx, rdx

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x44';
		buf[stSize + i32stSizeCnt++] = '\x24';
		buf[stSize + i32stSizeCnt++] = '\xf8';// mov rax,[rsp-8]

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x89';
		buf[stSize + i32stSizeCnt++] = '\xc3';// mov rbx, rax


		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xc3';
		buf[stSize + i32stSizeCnt++] = '\x1c';// add rbx,0x1c

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x04';
		buf[stSize + i32stSizeCnt++] = '\x24';// mov rax,[rsp]


		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x01';
		buf[stSize + i32stSizeCnt++] = '\xd8';// add rax, rbx

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x31';
		buf[stSize + i32stSizeCnt++] = '\xf6';// xor rsi,rsi

		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x33';// mov rsi, [rbx]

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x04';
		buf[stSize + i32stSizeCnt++] = '\x24';// mov rax,[rsp]

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x01';
		buf[stSize + i32stSizeCnt++] = '\xf0';// add arx, rsi

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x89';
		buf[stSize + i32stSizeCnt++] = '\xc3';// mov rbx, rax

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\xc7';
		buf[stSize + i32stSizeCnt++] = '\xc0';
		buf[stSize + i32stSizeCnt++] = '\x04';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';// mov rax, 4

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xe9';
		buf[stSize + i32stSizeCnt++] = '\x01';

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\xf7';
		buf[stSize + i32stSizeCnt++] = '\xe1';

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x01';
		buf[stSize + i32stSizeCnt++] = '\xc3';

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x31';
		buf[stSize + i32stSizeCnt++] = '\xf6';// xor rsi, rsi

		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x33';// mov esi,[rbx]

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x04';
		buf[stSize + i32stSizeCnt++] = '\x24';// mov rax,[rsp]

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x89';
		buf[stSize + i32stSizeCnt++] = '\xf3';// mov rbx, rsi

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x01';
		buf[stSize + i32stSizeCnt++] = '\xc3';// add rbx, rax

		buf[stSize + i32stSizeCnt++] = '\x53';// push rbx

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x4c';
		buf[stSize + i32stSizeCnt++] = '\x24';
		buf[stSize + i32stSizeCnt++] = '\x18';// mov rcx,[rsp+0x18]

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x81';
		buf[stSize + i32stSizeCnt++] = '\xc1';
		buf[stSize + i32stSizeCnt++] = '\x20';
		buf[stSize + i32stSizeCnt++] = '\x05';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';//add rcx,0x520

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x89';
		buf[stSize + i32stSizeCnt++] = '\xca';

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x89';
		buf[stSize + i32stSizeCnt++] = '\xc1';

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xec';
		buf[stSize + i32stSizeCnt++] = '\x20';

		buf[stSize + i32stSizeCnt++] = '\xff';
		buf[stSize + i32stSizeCnt++] = '\xd3';

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xc4';
		buf[stSize + i32stSizeCnt++] = '\x20';

		buf[stSize + i32stSizeCnt++] = '\x50';

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x4c';
		buf[stSize + i32stSizeCnt++] = '\x24';
		buf[stSize + i32stSizeCnt++] = '\x10';

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x54';
		buf[stSize + i32stSizeCnt++] = '\x24';
		buf[stSize + i32stSizeCnt++] = '\x20';


		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x81';
		buf[stSize + i32stSizeCnt++] = '\xc2';
		buf[stSize + i32stSizeCnt++] = '\x40';
		buf[stSize + i32stSizeCnt++] = '\x05';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xec';
		buf[stSize + i32stSizeCnt++] = '\x20';

		buf[stSize + i32stSizeCnt++] = '\xff';
		buf[stSize + i32stSizeCnt++] = '\xd3';

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xc4';
		buf[stSize + i32stSizeCnt++] = '\x20';

		buf[stSize + i32stSizeCnt++] = '\x50';

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x4c';
		buf[stSize + i32stSizeCnt++] = '\x24';
		buf[stSize + i32stSizeCnt++] = '\x18';

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x54';
		buf[stSize + i32stSizeCnt++] = '\x24';
		buf[stSize + i32stSizeCnt++] = '\x28';


		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x81';
		buf[stSize + i32stSizeCnt++] = '\xc2';
		buf[stSize + i32stSizeCnt++] = '\x80';
		buf[stSize + i32stSizeCnt++] = '\x05';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xec';
		buf[stSize + i32stSizeCnt++] = '\x20';

		buf[stSize + i32stSizeCnt++] = '\xff';
		buf[stSize + i32stSizeCnt++] = '\xd3';

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xc4';
		buf[stSize + i32stSizeCnt++] = '\x20';

		buf[stSize + i32stSizeCnt++] = '\x50';

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x4c';
		buf[stSize + i32stSizeCnt++] = '\x24';
		buf[stSize + i32stSizeCnt++] = '\x20';

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x54';
		buf[stSize + i32stSizeCnt++] = '\x24';
		buf[stSize + i32stSizeCnt++] = '\x30';

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x81';
		buf[stSize + i32stSizeCnt++] = '\xc2';
		buf[stSize + i32stSizeCnt++] = '\xa0';
		buf[stSize + i32stSizeCnt++] = '\x05';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xec';
		buf[stSize + i32stSizeCnt++] = '\x20';

		buf[stSize + i32stSizeCnt++] = '\xff';
		buf[stSize + i32stSizeCnt++] = '\xd3';

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xc4';
		buf[stSize + i32stSizeCnt++] = '\x20';

		buf[stSize + i32stSizeCnt++] = '\x50';

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x4c';
		buf[stSize + i32stSizeCnt++] = '\x24';
		buf[stSize + i32stSizeCnt++] = '\x28';

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x54';
		buf[stSize + i32stSizeCnt++] = '\x24';
		buf[stSize + i32stSizeCnt++] = '\x38';

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x81';
		buf[stSize + i32stSizeCnt++] = '\xc2';
		buf[stSize + i32stSizeCnt++] = '\x00';
		buf[stSize + i32stSizeCnt++] = '\x06';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xec';
		buf[stSize + i32stSizeCnt++] = '\x20';

		buf[stSize + i32stSizeCnt++] = '\xff';
		buf[stSize + i32stSizeCnt++] = '\xd3';


		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xc4';
		buf[stSize + i32stSizeCnt++] = '\x20';

		buf[stSize + i32stSizeCnt++] = '\x50';

		//////////////////////////////////////////////여기

		//buf[stSize + i32stSizeCnt++] = '\x48';
		//buf[stSize + i32stSizeCnt++] = '\x8b';
		//buf[stSize + i32stSizeCnt++] = '\x1c';
		//buf[stSize + i32stSizeCnt++] = '\x24';// mov rbx,[rsp]

		//buf[stSize + i32stSizeCnt++] = '\x48';
		//buf[stSize + i32stSizeCnt++] = '\x8b';
		//buf[stSize + i32stSizeCnt++] = '\x4c';
		//buf[stSize + i32stSizeCnt++] = '\x24';
		//buf[stSize + i32stSizeCnt++] = '\x40';// mov rcx,[rsp+0x40]

		//buf[stSize + i32stSizeCnt++] = '\x48';
		//buf[stSize + i32stSizeCnt++] = '\x81';
		//buf[stSize + i32stSizeCnt++] = '\xc1';
		//buf[stSize + i32stSizeCnt++] = '\x00';
		//buf[stSize + i32stSizeCnt++] = '\x06';
		//buf[stSize + i32stSizeCnt++] = '\x0';
		//buf[stSize + i32stSizeCnt++] = '\x0';// add rcx,0x600

		//buf[stSize + i32stSizeCnt++] = '\x48';
		//buf[stSize + i32stSizeCnt++] = '\x83';
		//buf[stSize + i32stSizeCnt++] = '\xec';
		//buf[stSize + i32stSizeCnt++] = '\x20';// sup rsp,0x20

		//buf[stSize + i32stSizeCnt++] = '\xff';
		//buf[stSize + i32stSizeCnt++] = '\xd3';

		//buf[stSize + i32stSizeCnt++] = '\x48';
		//buf[stSize + i32stSizeCnt++] = '\x83';
		//buf[stSize + i32stSizeCnt++] = '\xc4';
		//buf[stSize + i32stSizeCnt++] = '\x20';


		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x5c';
		buf[stSize + i32stSizeCnt++] = '\x24';
		buf[stSize + i32stSizeCnt++] = '\x20';// mov rbx,[rsp+0x20]


		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xec';
		buf[stSize + i32stSizeCnt++] = '\x38';// add rsp,0x38

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\xc7';
		buf[stSize + i32stSizeCnt++] = '\x44';
		buf[stSize + i32stSizeCnt++] = '\x24';
		buf[stSize + i32stSizeCnt++] = '\x30';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';

		buf[stSize + i32stSizeCnt++] = '\xc7';
		buf[stSize + i32stSizeCnt++] = '\x44';
		buf[stSize + i32stSizeCnt++] = '\x24';
		buf[stSize + i32stSizeCnt++] = '\x28';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';


		buf[stSize + i32stSizeCnt++] = '\xc7';
		buf[stSize + i32stSizeCnt++] = '\x44';
		buf[stSize + i32stSizeCnt++] = '\x24';
		buf[stSize + i32stSizeCnt++] = '\x20';
		buf[stSize + i32stSizeCnt++] = '\x03';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';

		buf[stSize + i32stSizeCnt++] = '\x4d';
		buf[stSize + i32stSizeCnt++] = '\x31';
		buf[stSize + i32stSizeCnt++] = '\xc9';

		buf[stSize + i32stSizeCnt++] = '\x4d';
		buf[stSize + i32stSizeCnt++] = '\x31';
		buf[stSize + i32stSizeCnt++] = '\xc0';

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x31';
		buf[stSize + i32stSizeCnt++] = '\xd2';

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x31';
		buf[stSize + i32stSizeCnt++] = '\xc9';

		buf[stSize + i32stSizeCnt++] = '\xba';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\xc0';

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x4c';
		buf[stSize + i32stSizeCnt++] = '\x24';
		buf[stSize + i32stSizeCnt++] = '\x78';// mov rcx,[rsp+0x70]

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x81';
		buf[stSize + i32stSizeCnt++] = '\xc1';
		buf[stSize + i32stSizeCnt++] = '\x20';
		buf[stSize + i32stSizeCnt++] = '\x04';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';

		buf[stSize + i32stSizeCnt++] = '\xff';
		buf[stSize + i32stSizeCnt++] = '\xd3';

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xc4';
		buf[stSize + i32stSizeCnt++] = '\x38';

		buf[stSize + i32stSizeCnt++] = '\x50';

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x5c';
		buf[stSize + i32stSizeCnt++] = '\x24';
		buf[stSize + i32stSizeCnt++] = '\x20';// mov rbx,[rsp+0x28]

		buf[stSize + i32stSizeCnt++] = '\xff';
		buf[stSize + i32stSizeCnt++] = '\xd3';

		buf[stSize + i32stSizeCnt++] = '\x50';

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x5c';
		buf[stSize + i32stSizeCnt++] = '\x24';
		buf[stSize + i32stSizeCnt++] = '\x30';// mov rbx,[rsp+0x30]

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x44';
		buf[stSize + i32stSizeCnt++] = '\x24';
		buf[stSize + i32stSizeCnt++] = '\x50';// mov rax,[rsp+0x50]

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x89';
		buf[stSize + i32stSizeCnt++] = '\xc6';// mov rsi, rax

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x81';
		buf[stSize + i32stSizeCnt++] = '\xc6';
		buf[stSize + i32stSizeCnt++] = '\x58';
		buf[stSize + i32stSizeCnt++] = '\x04';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';// add rsi,0x458

		buf[stSize + i32stSizeCnt++] = '\x4c';
		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x54';
		buf[stSize + i32stSizeCnt++] = '\x24';
		buf[stSize + i32stSizeCnt++] = '\x58';// r10 ,[rsp+0x58]

		buf[stSize + i32stSizeCnt++] = '\x4c';
		buf[stSize + i32stSizeCnt++] = '\x89';
		buf[stSize + i32stSizeCnt++] = '\x16';// mov [rsi], r10 <- BaseAddress

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xc6';
		buf[stSize + i32stSizeCnt++] = '\x08';//add rsi, 0x8

		buf[stSize + i32stSizeCnt++] = '\x4c';
		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x14';
		buf[stSize + i32stSizeCnt++] = '\x24';// r10,[rsp]

		buf[stSize + i32stSizeCnt++] = '\x4c';
		buf[stSize + i32stSizeCnt++] = '\x89';
		buf[stSize + i32stSizeCnt++] = '\x16';// mov [rsi],r10 <- PID



		char cOEP[4] = { 0 };
		memcpy((void*)&cOEP, (void*)&i32EntryPoint, 4);

		buf[stSize + i32stSizeCnt++] = '\x49';
		buf[stSize + i32stSizeCnt++] = '\xba';
		buf[stSize + i32stSizeCnt++] = cOEP[0];
		buf[stSize + i32stSizeCnt++] = cOEP[1];
		buf[stSize + i32stSizeCnt++] = cOEP[2];
		buf[stSize + i32stSizeCnt++] = cOEP[3];
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xc6';
		buf[stSize + i32stSizeCnt++] = '\x04';// add rsi, 0x4

		buf[stSize + i32stSizeCnt++] = '\x4c';
		buf[stSize + i32stSizeCnt++] = '\x89';
		buf[stSize + i32stSizeCnt++] = '\x16';// mov [rsi], r10<- OEP

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xc6';
		buf[stSize + i32stSizeCnt++] = '\x04';// add rsi, 0x4

		char cImageBase[8] = { 0 };
		memcpy((void*)&cImageBase, (void*)&pNtH->OptionalHeader.ImageBase, 8);


		buf[stSize + i32stSizeCnt++] = '\x49';
		buf[stSize + i32stSizeCnt++] = '\xba';

		buf[stSize + i32stSizeCnt++] = cImageBase[0];
		buf[stSize + i32stSizeCnt++] = cImageBase[1];
		buf[stSize + i32stSizeCnt++] = cImageBase[2];
		buf[stSize + i32stSizeCnt++] = cImageBase[3];
		buf[stSize + i32stSizeCnt++] = cImageBase[4];
		buf[stSize + i32stSizeCnt++] = cImageBase[5];
		buf[stSize + i32stSizeCnt++] = cImageBase[6];
		buf[stSize + i32stSizeCnt++] = cImageBase[7];

		buf[stSize + i32stSizeCnt++] = '\x4c';
		buf[stSize + i32stSizeCnt++] = '\x89';
		buf[stSize + i32stSizeCnt++] = '\x16';







		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x05';
		buf[stSize + i32stSizeCnt++] = '\x50';
		buf[stSize + i32stSizeCnt++] = '\x4';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';// add rax,0x450

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x89';
		buf[stSize + i32stSizeCnt++] = '\xc6';// mov rsi, rax

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xc0';
		buf[stSize + i32stSizeCnt++] = '\x08';// add rax, 4

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x89';
		buf[stSize + i32stSizeCnt++] = '\xc7';//mov rdi, rax

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x89';
		buf[stSize + i32stSizeCnt++] = '\xf1';// mov r9, rsi

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x89';
		buf[stSize + i32stSizeCnt++] = '\xfa';//mov rdx,rdi

		buf[stSize + i32stSizeCnt++] = '\x49';
		buf[stSize + i32stSizeCnt++] = '\xc7';
		buf[stSize + i32stSizeCnt++] = '\xc0';
		buf[stSize + i32stSizeCnt++] = '\x00';
		buf[stSize + i32stSizeCnt++] = '\x04';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';// mov r8,0x18

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xe8';
		buf[stSize + i32stSizeCnt++] = '\x04';//sub rax, 4

		buf[stSize + i32stSizeCnt++] = '\x49';
		buf[stSize + i32stSizeCnt++] = '\x89';
		buf[stSize + i32stSizeCnt++] = '\xc1';

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x4c';
		buf[stSize + i32stSizeCnt++] = '\x24';
		buf[stSize + i32stSizeCnt++] = '\x8';// mov rcx,[rsp+10]


		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xec';
		buf[stSize + i32stSizeCnt++] = '\x28';// sub rsp,0x28

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\xc7';
		buf[stSize + i32stSizeCnt++] = '\x44';
		buf[stSize + i32stSizeCnt++] = '\x24';
		buf[stSize + i32stSizeCnt++] = '\x20';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';// mov [rsp+0x20],0

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x5c';
		buf[stSize + i32stSizeCnt++] = '\x24';
		buf[stSize + i32stSizeCnt++] = '\x48';// mov rbx,[rsp+0x48] <- WriteFile

		buf[stSize + i32stSizeCnt++] = '\xff';
		buf[stSize + i32stSizeCnt++] = '\xd3';// call rbx

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xc4';
		buf[stSize + i32stSizeCnt++] = '\x28';

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\xc7';
		buf[stSize + i32stSizeCnt++] = '\xc1';
		buf[stSize + i32stSizeCnt++] = '\xe8';
		buf[stSize + i32stSizeCnt++] = '\x03';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';// mov rcx,0x3e8

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x5c';
		buf[stSize + i32stSizeCnt++] = '\x24';
		buf[stSize + i32stSizeCnt++] = '\x18';// mov rbx,[rsp+0x18]

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xec';
		buf[stSize + i32stSizeCnt++] = '\x20';

		buf[stSize + i32stSizeCnt++] = '\xff';
		buf[stSize + i32stSizeCnt++] = '\xd3';

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xc4';
		buf[stSize + i32stSizeCnt++] = '\x20';

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x44';
		buf[stSize + i32stSizeCnt++] = '\x24';
		buf[stSize + i32stSizeCnt++] = '\x50';

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x05';
		buf[stSize + i32stSizeCnt++] = '\x78';
		buf[stSize + i32stSizeCnt++] = '\x04';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';

		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x00';


		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xf8';
		buf[stSize + i32stSizeCnt++] = '\x01';

		buf[stSize + i32stSizeCnt++] = '\x75';
		buf[stSize + i32stSizeCnt++] = '\xd7';


		////////////////////
		i32TotalStackPop += 10;
		char cTotalStackPop[4] = { 0 };
		i32TotalStackPop *= 8;
		memcpy((void*)&cTotalStackPop, (void*)&i32TotalStackPop, 4);


		buf[stSize + i32stSizeCnt++] = '\x48';
		buf[stSize + i32stSizeCnt++] = '\x81';
		buf[stSize + i32stSizeCnt++] = '\xc4';
		buf[stSize + i32stSizeCnt++] = cTotalStackPop[0];
		buf[stSize + i32stSizeCnt++] = cTotalStackPop[1];
		buf[stSize + i32stSizeCnt++] = cTotalStackPop[2];
		buf[stSize + i32stSizeCnt++] = cTotalStackPop[3];


		buf[stSize + i32stSizeCnt++] = '\x41';
		buf[stSize + i32stSizeCnt++] = '\x5f';

		buf[stSize + i32stSizeCnt++] = '\x41';
		buf[stSize + i32stSizeCnt++] = '\x5e';

		buf[stSize + i32stSizeCnt++] = '\x41';
		buf[stSize + i32stSizeCnt++] = '\x5d';

		buf[stSize + i32stSizeCnt++] = '\x41';
		buf[stSize + i32stSizeCnt++] = '\x5c';

		buf[stSize + i32stSizeCnt++] = '\x41';
		buf[stSize + i32stSizeCnt++] = '\x5b';

		buf[stSize + i32stSizeCnt++] = '\x41';
		buf[stSize + i32stSizeCnt++] = '\x5a';

		buf[stSize + i32stSizeCnt++] = '\x41';
		buf[stSize + i32stSizeCnt++] = '\x59';

		buf[stSize + i32stSizeCnt++] = '\x41';
		buf[stSize + i32stSizeCnt++] = '\x58';

		buf[stSize + i32stSizeCnt++] = '\x5e';
		buf[stSize + i32stSizeCnt++] = '\x5f';
		buf[stSize + i32stSizeCnt++] = '\x5a';
		buf[stSize + i32stSizeCnt++] = '\x59';
		buf[stSize + i32stSizeCnt++] = '\x5b';
		buf[stSize + i32stSizeCnt++] = '\x58';






		int i32FLLast = i32stSizeCnt + i32RollBackEntryPoint;
		int i32FLfunctionToEntryPoint = i32EntryPoint - i32FLLast - 5;// -3;

		char cFLfunctionToEntryPoint[4] = { 0, };

		memcpy((void*)&cFLfunctionToEntryPoint, (void*)&i32FLfunctionToEntryPoint, 4);


		buf[stSize + i32stSizeCnt++] = '\xe9';

		buf[stSize + i32stSizeCnt++] = cFLfunctionToEntryPoint[0];
		buf[stSize + i32stSizeCnt++] = cFLfunctionToEntryPoint[1];
		buf[stSize + i32stSizeCnt++] = cFLfunctionToEntryPoint[2];
		buf[stSize + i32stSizeCnt++] = cFLfunctionToEntryPoint[3];


		char cPipe[] = "\\\\.\\pipe\\FLProtectionPipe";
		int i32PipeSize = strlen(cPipe);
		int i32Name = strlen(pNameDes);

		for(int i = 0; i < i32KenrelSize; i++)
		{
			buf[stSize + 0x400 + 2 * i] = cKernel32[i];
			buf[stSize + 0x400 + 2 * i + 1] = '\x00';
			if(i == i32KenrelSize - 1)
			{
				buf[stSize + 0x400 + 2 * (i + 1)] = '\x00';
				buf[stSize + 0x400 + 2 * (i + 1) + 1] = '\x00';

			}
			i32stSizeCnt += 2;
		}

		for(int i = 0; i < i32PipeSize; i++)
		{
			buf[stSize + 0x420 + 2 * i] = cPipe[i];
			buf[stSize + 0x420 + 2 * i + 1] = '\x00';
			if(i == i32PipeSize - 1)
			{
				buf[stSize + 0x420 + 2 * (i + 1)] = '\x00';
				buf[stSize + 0x420 + 2 * (i + 1) + 1] = '\x00';

			}
			i32stSizeCnt += 2;
		}


		for(int i = 0; i < i32Name; i++)
		{
			buf[stSize + 0x480 + 2 * i] = pNameDes[i];
			buf[stSize + 0x480 + 2 * i + 1] = '\x00';
			if(i == i32Name - 1)
			{
				buf[stSize + 0x480 + 2 * (i + 1)] = '\x00';
				buf[stSize + 0x480 + 2 * (i + 1) + 1] = '\x00';

			}
		}

		char cGetProcAddress[] = "GetProcAddress";
		int32_t i32GetProcAddressSize = strlen(cGetProcAddress);
		for(int i = 0; i < i32GetProcAddressSize; i++)
		{
			buf[stSize + 0x500 + i] = cGetProcAddress[i];
			if(i == i32GetProcAddressSize - 1)
			{
				buf[stSize + 0x500 + i + 1] = '\x00';
				buf[stSize + 0x500 + i + 2] = '\x00';
			}
		}

		char cGetCreateFileW[] = "CreateFileW";
		int32_t i32GetCreateFileW = strlen(cGetCreateFileW);
		for(int i = 0; i < i32GetCreateFileW; i++)
		{
			buf[stSize + 0x520 + i] = cGetCreateFileW[i];
			if(i == i32GetCreateFileW - 1)
			{
				buf[stSize + 0x520 + i + 1] = '\x00';
				buf[stSize + 0x520 + i + 2] = '\x00';
			}
		}

		char cGetCurrentProcessId[] = "GetCurrentProcessId";
		int32_t i32GetCurrentProcessId = strlen(cGetCurrentProcessId);
		for(int i = 0; i < i32GetCurrentProcessId; i++)
		{
			buf[stSize + 0x540 + i] = cGetCurrentProcessId[i];
			if(i == i32GetCurrentProcessId - 1)
			{
				buf[stSize + 0x540 + i + 1] = '\x00';
				buf[stSize + 0x540 + i + 2] = '\x00';
			}
		}

		char cGetWrtieFile[] = "WriteFile";
		int32_t i32GetWrtieFile = strlen(cGetWrtieFile);
		for(int i = 0; i < i32GetWrtieFile; i++)
		{
			buf[stSize + 0x580 + i] = cGetWrtieFile[i];
			if(i == i32GetWrtieFile - 1)
			{
				buf[stSize + 0x580 + i + 1] = '\x00';
				buf[stSize + 0x580 + i + 2] = '\x00';
			}
		}


		char cGetSleep[] = "Sleep";
		int32_t i32GetSleep = strlen(cGetSleep);
		for(int i = 0; i < i32GetSleep; i++)
		{
			buf[stSize + 0x5a0 + i] = cGetSleep[i];
			if(i == i32GetSleep - 1)
			{
				buf[stSize + 0x5a0 + i + 1] = '\x00';
				buf[stSize + 0x5a0 + i + 2] = '\x00';
			}
		}



		char cGetNameDes[0x50] = { 0, };
		strcpy(cGetNameDes, pNameDes);
		int32_t i32GetNameDes = strlen(cGetNameDes);
		for(int i = 0; i < i32GetNameDes; i++)
		{
			buf[stSize + 0x5c0 + 2 * i] = cGetNameDes[i];
			buf[stSize + 0x5c0 + 2 * i + 1] = '\x00';
			if(i == i32GetNameDes - 1)
			{
				buf[stSize + 0x5c0 + 2 * (i + 1)] = '\x00';
				buf[stSize + 0x5c0 + 2 * (i + 1) + 1] = '\x00';
			}
		}

		char cGetOutPutDebugString[] = "OutputDebugStringA";
		int32_t i32GetOutPutDebugString = strlen(cGetOutPutDebugString);
		for(int i = 0; i < i32GetOutPutDebugString; i++)
		{
			buf[stSize + 0x600 + i] = cGetOutPutDebugString[i];
			if(i == i32GetOutPutDebugString - 1)
			{
				buf[stSize + 0x600 + i + 1] = '\x00';
				buf[stSize + 0x600 + i + 2] = '\x00';
			}
		}

		buf[stSize + 0x46c] = '\x00';
		buf[stSize + 0x46d] = '\x00';
		buf[stSize + 0x46e] = '\x00';
		buf[stSize + 0x46f] = '\x00';

		buf[stSize + 0x470] = '\x00';
		buf[stSize + 0x471] = '\x00';
		buf[stSize + 0x472] = '\x00';
		buf[stSize + 0x473] = '\x00';


		std::vector<std::pair<int, int> > vctRelocationVector;

		int RvaOfBlock = 0;
		int SizeOfBlock = 0;

		int i32RelocPointerToRawDataToRelocSizeOfBlock = i32RelocPointerToRawData + 4;

		memcpy((void*)&RvaOfBlock, (void*)&i32RelocPointerToRawData, 4);
		memcpy((void*)&SizeOfBlock, (void*)&i32RelocPointerToRawDataToRelocSizeOfBlock, 4);

		if(i32RelocRVA != 0)
		{
			vctRelocationVector.push_back({ RvaOfBlock,SizeOfBlock });
			while(1)
			{
				int TempRelocPointerToRawData = 0;
				memcpy((void*)&TempRelocPointerToRawData, (void*)&buf[SizeOfBlock], 4);
				i32RelocPointerToRawData += TempRelocPointerToRawData;

				i32RelocPointerToRawDataToRelocSizeOfBlock = i32RelocPointerToRawData + 4;

				int i32TempSizeOfBlock = 0;
				memcpy((void*)&i32TempSizeOfBlock, (void*)&buf[SizeOfBlock], 4);
				if(i32TempSizeOfBlock == 0)
					break;
				memcpy((void*)&RvaOfBlock, (void*)&i32RelocPointerToRawData, 4);
				memcpy((void*)&SizeOfBlock, (void*)(&i32RelocPointerToRawDataToRelocSizeOfBlock), 4);
				vctRelocationVector.push_back({ RvaOfBlock,SizeOfBlock });
			}
		}

		for(int i = 0; i < vctRelocationVector.size(); i++)
		{
			int RvaOfBlock = vctRelocationVector[i].first;
			int DeicdeToRvaOfBlock = 0;
			memcpy((void*)&DeicdeToRvaOfBlock, (void*)&buf[RvaOfBlock], 4);
			int Section = 0;
			for(int j = 0; j < vctSection.size() - 1; j++)
			{
				int FromRvaOfBlock = vctSection[j].RVA;
				int ToRvaOfBlock = vctSection[j + 1].RVA;

				if(FromRvaOfBlock <= DeicdeToRvaOfBlock && DeicdeToRvaOfBlock < ToRvaOfBlock)
				{
					Section = j;
					break;
				}
			}

			int Size = 0;
			memcpy((void*)&Size, (void*)&buf[vctRelocationVector[i].second], 4);

			int Start = vctRelocationVector[i].second + 4;

			for(int j = 0; j < Size - 8; j += 2)
			{
				WORD Data = 0;
				int i32RvaOfBlock = 0;

				memcpy((void*)&i32RvaOfBlock, (void*)&buf[RvaOfBlock], 4);
				memcpy((void*)&Data, (void*)&buf[Start], 2);
				if(Data == 0)
				{
					//Start += 2;
					//break;
					continue;
				}
				Data &= 0x0fff;

				int RelocData = i32RvaOfBlock + Data;

				//			RelocData -= vctSection[Section].RVA;
			//				RelocData += vctSection[Section].PoitnerToRawData;
							//RelocData += 2;

				int i32FileRelocOffset = Data + i32RvaOfBlock - vctSection[Section].RVA + vctSection[Section].PoitnerToRawData;// +2;


				vctParseRelocation.push_back({ Section,{RelocData,i32FileRelocOffset} });

				Start += 2;
			}
		}


		for(int i = i32PointerToRawData; i < i32SizeOfCode + i32PointerToRawData; i++)
		{
			buf[i] = ~buf[i];
			//buf[i] = 0x18;
		}


		for(int i = i32DataPointerToRawData; i < i32DataPointerToRawData + i32DataSizeOfRawData; i++)
		{
			buf[i] = ~buf[i];
			//buf[i] = 0x18;
		}

	/*	for(int i = i32RscPointerToRawData; i < i32RscPointerToRawData + i32RscSizeOfRawData; i++)
		{
			buf[i] = ~buf[i];
		}*/


		for(int i = 0; i < vctParseRelocation.size(); i++)
		{
			int32_t i32Section = vctParseRelocation[i].first;
			int32_t i32ParseReloc = vctParseRelocation[i].second.second;
			if(i32ParseReloc < i32SizeOfCode + i32PointerToRawData)
			{
				for(int j = 0; j < 8; j++)
				{
					buf[i32ParseReloc + j] = ~buf[i32ParseReloc + j];
				}
			}
			else if(i32DataPointerToRawData <= i32ParseReloc && i32ParseReloc < i32DataPointerToRawData + i32DataSizeOfRawData)
			{
				for(int j = 0; j < 8; j++)
				{
					buf[i32ParseReloc + j] = ~buf[i32ParseReloc + j];
				}
			}
		}


		fwrite(buf, sizeof(char), stSize + i32FLSize, fp);
		fclose(fp);
	}

}