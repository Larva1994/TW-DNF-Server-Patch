#include "hook.h"

char szGamePath[256];
int n_sleep_time = 10000;
bool bGMMode = false, bFairPVP = false, bPickupRout = false;

fnPacketGuard PacketGuard = (fnPacketGuard)0x0858DD4C;
fnGetVectorUserCharacInfo GetVectorUserCharacInfo = (fnGetVectorUserCharacInfo)0x081A0BB8;
fndoDispatch doDispatch = (fndoDispatch)0x08594922;
fnaddServerHackCnt addServerHackCnt = (fnaddServerHackCnt)0x080F8C7E;
fnput_header put_header = (fnput_header)0x080CB8FC;
fnIsRoutingItem IsRoutingItem = (fnIsRoutingItem)0x08150F18;
fnsetCharacInfoDetail setCharacInfoDetail = (fnsetCharacInfoDetail)0x0864AC1A;
fnIsGameMasterMode IsGameMasterMode = (fnIsGameMasterMode)0x0811EDEE;
fnisGMUser isGMUser = (fnisGMUser)0x0814589C;
fnGetPvPTeamCount GetPvPTeamCount = (fnGetPvPTeamCount)0x08568CE0;
fnisGM isGM = (fnisGM)0x08109346;
fnisGM1 isGM1 = (fnisGM1)0x0829948C;
fnset_add_info set_add_info = (fnset_add_info)0x080CB884;
fnget_dispatcher get_dispatcher = (fnget_dispatcher)0x085948E2;
fndispatch_template dispatch_template = (fndispatch_template)0x081258B6;
fnisSocketAvatar isSocketAvatar = (fnisSocketAvatar)0x082F9228;

subhook_t hdoDispatch, haddServerHackCnt, hput_header, hIsRoutingItem, hsetCharacInfoDetail
	, hIsGameMasterMode, hisGMUser, hGetPvPTeamCount, hisGM, hisGM1, hset_add_info
	, hisSocketAvatar, hdispatch_template;

#define SUBHOOK_SETUP(name) h##name = subhook_new((void *)name, (void *)_##name, (subhook_flags_t)0);subhook_install(h##name)
#define MAIN_OFFSET(offset) ((void*)((0x8048000)+(offset)))

void print_backtrace(int i)
{
	static const char tag[] = "----------------------\n";

	void *bt[1024];
	int bt_size;
	char **bt_syms;

	bt_size = backtrace(bt, 1024);
	bt_syms = backtrace_symbols(bt, bt_size);
	printf(tag);
	for (; i < bt_size; i++) {
		//size_t len = strlen(bt_syms[i]);
		printf(bt_syms[i]);
		printf("\n");
	}
	printf(tag);
	free(bt_syms);
}

bool safe_write(void *address, void *data, size_t size)
{
	long pagesize = sysconf(_SC_PAGESIZE);
	void *pageaddr = (void *)((long)address & ~(pagesize - 1));
	if (mprotect(pageaddr, pagesize, PROT_READ | PROT_WRITE | PROT_EXEC))
	{
		printf("mprotect failed!!!!!!!\n");
		return false;
	}
	memcpy(address, data, size);
	return true;
}

bool safe_write_byte(void *address, unsigned char data)
{
	//1
	return safe_write(address, &data, 1);
}

bool safe_write_uint(void *address, unsigned int data)
{
	//4
	return safe_write(address, &data, 4);
}

int checkGame(const char *pName)
{
	char path[256];
	char* path_end;

	memset(path, 0, sizeof(path));
	if(readlink("/proc/self/exe", path, sizeof(path)) <= 0)return -1;
	path_end = strrchr(path, '/');
	if(!path_end || strlen(path_end) < 9)return -1;
	return strcmp(pName, ++path_end);
}

int open_main_module_file()
{
	char path[256];
	memset(path, 0, sizeof(path));
	if (readlink("/proc/self/exe", path, sizeof(path)) <= 0)return -1;
	return open(path, O_RDONLY);
}

int getargs(char **&argv)
{
	size_t buflen = 1024, readlen = 0, maxlen = buflen;
	int fd = open ("/proc/self/cmdline", O_RDONLY);
	if (fd == -1)return 0;
	char *buf = (char*)malloc (buflen);
	while (1)
	{
		ssize_t n = read (fd, buf + readlen, buflen - readlen);
		if (n == -1)
		{
			free(buf);
			close (fd);
			return 0;
		}
		readlen += n;
		if (!n || readlen < buflen)break;
		maxlen += buflen;
		buf = (char*)realloc (buf, maxlen);
	}
	close(fd);
	int argc = 0;
	char *cp = buf;
	do
	{
		while(*cp != '\0')cp++;
		argc++;
	} while (++cp < buf + readlen);
	argv = (char**)malloc (argc * sizeof (char*));
	argc = 0;
	cp = buf;
	do
	{
		argv[argc] = (char*)malloc(strlen(cp)+1);
		strcpy(argv[argc], cp);
		argc++;
		while(*cp != '\0')cp++;
	} while (++cp < buf + readlen);
	free(buf);
	return argc;
}

int getConfigPath(char *pPath, size_t nSize)
{
	if(readlink("/proc/self/exe", pPath, nSize) <= 0)return -1;
	char **argv = NULL;
	int argc = getargs(argv);
	if (!argv || argc < 2)
	{
		if (argv)
		{
			for (int i = 0; i < argc; i++)
			{
				if(argv[i])free(argv[i]);
			}
			free(argv);
		}
		return -1;
	}
	*strrchr(pPath, '/') = '\0';
	sprintf(pPath, "%s/cfg/%s.cfg", pPath, argv[1]);
	for (int i = 0; i < argc; i++)
	{
		if(argv[i])free(argv[i]);
	}
	free(argv);
	return 0;
}

int GetProfileString(const char *profile, const char *section, const char *key, char* &val)
{
	int hFile = open (profile, O_RDONLY);
	if (hFile == -1)return -1;
	struct stat st;
	fstat(hFile, &st);
	void *pFileData = mmap(0, st.st_size, PROT_READ, MAP_SHARED, hFile, 0);
	if (!pFileData)
	{
		close(hFile);
		return -1;
	}
	unsigned char readSection = 0, readKey = 1, readValue = 0, got = 0, notes = 0;
	char *cur = (char*)pFileData, *end = (char*)pFileData + st.st_size;
	char *sectionbuf = (char*)malloc(1024)
		, *keybuf = (char*)malloc(1024)
		, *valuebuf = (char*)malloc(1024);
	memset(sectionbuf, 0, 1024);
	memset(keybuf, 0, 1024);
	memset(valuebuf, 0, 1024);
	int i = 0;
	do
	{
		if (notes && *cur != '\n')continue;
		switch(*cur)
		{
		case '#':
			notes = 1;
			break;
		case ' ':
		case '\t':
			//jump space
			break;
		case '\n':
			//new line
			if (readValue)
			{
				valuebuf[i] = '\0';
				if (!strcmp(section, sectionbuf) && !strcmp(key, keybuf))
				{
					val = (char*)malloc(i + 1);
					memset(val, 0, i + 1);
					strcpy(val, valuebuf);
					got = 1;
				}
				//printf("value:%s\n", valuebuf);
			}
			notes = 0, readSection = 0, readKey = 1, readValue = 0, i = 0;
			break;
		case '[':
			//section begin
			readSection = 1;
			readKey = 0;
			readValue = 0;
			i = 0;
			break;
		case ']':
			//section end
			if (readSection)
			{
				sectionbuf[i] = '\0';
				//printf("section:%s\n", sectionbuf);
				readSection = 0;
			}
			break;
		case '=':
			if (readKey)
			{
				keybuf[i] = '\0';
				//printf("key:%s\n", keybuf);
				readSection = 0;
				readKey = 0;
				readValue = 1;
				i = 0;
			}
			break;
		default:
			if (readSection)
			{
				sectionbuf[i++] = *cur;
			}
			else if (readKey)
			{
				keybuf[i++] = *cur;
			}
			else if (readValue)
			{
				valuebuf[i++] = *cur;
			}
			break;
		}
	} while (++cur != end && !got);
	free(sectionbuf);
	free(keybuf);
	free(valuebuf);
	munmap(pFileData, st.st_size);
	return 0;
}

int GetProfileInt(const char *profile, const char *section, const char *key)
{
	int ival = 0;
	char *pValue = NULL;
	if (GetProfileString(profile, section, key, pValue) || !pValue)return 0;
	ival = atoi(pValue);
	free(pValue);
	return ival;
}

Elf32_Shdr* get_section_by_type(Elf32_Ehdr* pHeader, Elf32_Shdr* pSectionHeaderTable, Elf32_Word sh_type)
{
	Elf32_Half i = 0;
	do
	{
		if (pSectionHeaderTable[i].sh_type == sh_type)
		{
			return &pSectionHeaderTable[i];
		}
	} while (++i < pHeader->e_shnum);
	return NULL;
}

Elf32_Shdr* get_section_by_index(Elf32_Ehdr* pHeader, Elf32_Shdr* pSectionHeaderTable, Elf32_Half i)
{
	if (i < pHeader->e_shnum)
	{
		return &pSectionHeaderTable[i];
	}
	return NULL;
}

Elf32_Shdr* get_section_by_name(Elf32_Ehdr* pHeader, Elf32_Shdr* pSectionHeaderTable, const char *pSymStrTbl, const char *pName)
{
	Elf32_Half i = 0;
	do
	{
		if (!strcmp(pName, &pSymStrTbl[pSectionHeaderTable[i].sh_name]))
		{
			return &pSectionHeaderTable[i];
		}
	} while (++i < pHeader->e_shnum);
	return NULL;
}

int get_symbol_index_by_name(Elf32_Sym *pSymbolTbl, int nSymbols, const char *pSymStrTbl, const char *pName)
{
	int i = 0;
	do
	{
		if (ELF32_ST_TYPE(pSymbolTbl[i].st_info) == STT_FUNC && !strcmp(pName, &pSymStrTbl[pSymbolTbl[i].st_name]))
		{
			return i;
		}
	} while(++i < nSymbols);
	return 0;
}

void* replaceIAT(const char *pName, void *pAddr)
{
	void *pOrgAddr = NULL;

	int hFile = open_main_module_file();
	if (hFile != -1)
	{
		struct stat st;
		fstat(hFile, &st);
		void *pFileData = mmap(0, st.st_size, PROT_READ, MAP_SHARED, hFile, 0);
		if (pFileData)
		{
			Elf32_Ehdr* pHeader = (Elf32_Ehdr*)pFileData;
			Elf32_Shdr* pSectionHeaderTable = (Elf32_Shdr*)((char*)pHeader + pHeader->e_shoff);
			Elf32_Shdr* pSymSection = get_section_by_type(pHeader, pSectionHeaderTable, SHT_DYNSYM);
			Elf32_Shdr* pSymStrSection = get_section_by_index(pHeader, pSectionHeaderTable, pSymSection->sh_link);
			Elf32_Sym* pSymbolTbl = (Elf32_Sym*)((char*)pHeader + pSymSection->sh_offset);
			const char* pSymStrTbl = (const char *)((char*)pHeader + pSymStrSection->sh_offset);
			unsigned int iSymbol = get_symbol_index_by_name(pSymbolTbl, pSymSection->sh_size / sizeof(Elf32_Sym), pSymStrTbl, pName);
			Elf32_Shdr* pStrSection = get_section_by_index(pHeader, pSectionHeaderTable, pHeader->e_shstrndx);
			const char* pStrTbl = (const char *)((char*)pHeader + pStrSection->sh_offset);
			Elf32_Shdr* pRelPltSection = get_section_by_name(pHeader, pSectionHeaderTable, pStrTbl, ".rel.plt");
			Elf32_Shdr* pRelDynSection = get_section_by_name(pHeader, pSectionHeaderTable, pStrTbl, ".rel.dyn");
			Elf32_Rel* pRelPlt = (Elf32_Rel*)(0x8047000 + pRelPltSection->sh_offset);
			Elf32_Rel* pRelDyn = (Elf32_Rel*)(0x8047000 + pRelDynSection->sh_offset);
			int nRelPlt = pRelPltSection->sh_size / sizeof(Elf32_Rel);
			int nRelDyn = pRelDynSection->sh_size / sizeof(Elf32_Rel);
			for (int i = 0; i < nRelPlt; i++)
			{
				if (ELF32_R_SYM(pRelPlt[i].r_info) == iSymbol && pRelPlt[i].r_offset)
				{
					pOrgAddr = *(void**)pRelPlt[i].r_offset;
					*(void**)pRelPlt[i].r_offset = pAddr;
					break;
				}
			}
			if (!pOrgAddr)
			{
				for (int i = 0; i < nRelDyn; i++)
				{
					if (ELF32_R_SYM(pRelDyn[i].r_info) == iSymbol && pRelDyn[i].r_offset)
					{
						void** jmpAddr = (void**)pRelDyn[i].r_offset;
						//printf("jmpaddr::::::::::::::::::::%X\n", pRelDyn[i].r_offset);
						pOrgAddr = (void*)((char*)(*jmpAddr) + (int)jmpAddr + sizeof(void*));
						safe_write(pOrgAddr, &pAddr, sizeof(pAddr));
						break;
					}
				}
			}
			munmap(pFileData, st.st_size);
		}
		close(hFile);
	}
	return pOrgAddr;
}

extern "C" int my_select (int __nfds, fd_set *__restrict __readfds,
		   fd_set *__restrict __writefds,
		   fd_set *__restrict __exceptfds,
		   struct timeval *__restrict __timeout)
{
	if (!__nfds && !__readfds && !__writefds && !__exceptfds)
	{
		if (!__timeout->tv_sec && __timeout->tv_usec >= 0 && __timeout->tv_usec <= 1000)
		{
			__timeout->tv_usec = n_sleep_time;
		}
	}
	return select(__nfds, __readfds, __writefds, __exceptfds, __timeout);
}

extern "C" int my_usleep (__useconds_t __useconds)
{
	if (__useconds >= 0 && __useconds <= 1000)
	{
		__useconds = n_sleep_time;
	}
	return usleep(__useconds);
}

/*void* my_malloc (size_t __size)
{
	if (__size > 100 * 1024 * 1024)
	{
		char path[256];
		memset(path, 0, sizeof(path));
		readlink("/proc/self/exe", path, sizeof(path));
		printf("**********************************[%s][malloc]: %.2f\n", path, (double)__size / 1024 / 1024);
		print_backtrace(2);
	}
	return malloc(__size);
}*/

int _doDispatch(void *pPacketDispatcher, void *pUser, int a3, int a4, void *src, int a6, int a7, int a8)
{
#ifdef Debug
	void *pAction = *get_dispatcher(pPacketDispatcher, a4);
	if (pAction)
	{
		printf("Recv() cs:%d cmd:%d len:%d callback:%p\t%p\t%p\t%p\t%p\t%p\n"
			, a3
			, a4
			, a6
			, *((void**)pAction)
			, (void*)*((unsigned int*)pAction + 12)
			, (void*)*((unsigned int*)pAction + 16)
			, (void*)*((unsigned int*)pAction + 20)
			, (void*)*((unsigned int*)pAction + 24)
			, (void*)*((unsigned int*)pAction + 28)
		);
	}
	else
	{
		printf("Recv() cs:%d cmd:%d len:%d\n"
			, a3
			, a4
			, a6);
	}
#endif
	return ((fndoDispatch)subhook_get_trampoline(hdoDispatch))(pPacketDispatcher, pUser, a3, a4, src, a6, a7, a8);
}

int _dispatch_template(void *pInst, void *pUser, void *pPacketBuf)
{
	char *buf = (char*)(*((unsigned int*)pPacketBuf + 5));
	printf("Recv() cs:%d cmd:%d len:%d callback:%p|%p|%p|%p|%p\n"
		, buf[0]
		, *((unsigned short*)&buf[1])
		, *((unsigned int*)&buf[3])
		, *((void**)*((unsigned int*)pInst + 12))
		, *((void**)*((unsigned int*)pInst + 16))
		, *((void**)*((unsigned int*)pInst + 20))
		, *((void**)*((unsigned int*)pInst + 24))
		, *((void**)*((unsigned int*)pInst + 28))
	);
	return ((fndispatch_template)subhook_get_trampoline(hdispatch_template))(pInst, pUser, pPacketBuf);
}

int _addServerHackCnt(void *pCHackAnalyzer, void *pCUserCharacInfo, int HackType, int Cnt, int a5, int a6)
{
	//printf("addServerHackCnt() HackType:%d \n", HackType);
	//char pack_buf[0xC];
	//PacketGuard(pack_buf);
	return ((fnaddServerHackCnt)subhook_get_trampoline(haddServerHackCnt))(pCHackAnalyzer, pCUserCharacInfo, HackType, Cnt, a5, a6);
}

int _put_header(void *pInterfacePacketBuf, int Type, int Cmd)
{
#ifdef Debug
	printf("Send() cmd:%d\n", Cmd);
	print_backtrace(2);
#endif
	return ((fnput_header)subhook_get_trampoline(hput_header))(pInterfacePacketBuf, Type, Cmd);
}

int _IsRoutingItem(void *pItem)
{
	//拾取掷点
	return bPickupRout && (*((unsigned int *)pItem + 14) == 4 || *((unsigned char *)pItem + 189));
}

int _setCharacInfoDetail(void *pUser, int a2, int a3, void *pCHARAC_DATA)
{
	//下线位置
	unsigned char curArea = *((unsigned char*)pCHARAC_DATA + 34);
	int ret = ((fnsetCharacInfoDetail)subhook_get_trampoline(hsetCharacInfoDetail))(pUser, a2, a3, pCHARAC_DATA);
	if (curArea == 12 || curArea == 13)
	{
		*((char*)GetVectorUserCharacInfo((char*)pUser + 497384, a2) + 34) = 11;
	}
	return ret;
}

int _IsGameMasterMode(void *pUser)
{
	//gm
	return bGMMode || *((unsigned char*)pUser + 463320) != 0;
}

int _isGMUser(void *pUser)
{
	//gm
	return bGMMode || (*((unsigned char*)pUser + 463320) != 0);
}

bool _isGM(void *pGMAccounts, unsigned int a2)
{
	//gm
	return bGMMode || ((fnisGM)subhook_get_trampoline(hisGM))(pGMAccounts, a2);
}

bool _isGM1(void *pGM_Manager)
{
	//gm
	return bGMMode || ((fnisGM1)subhook_get_trampoline(hisGM1))(pGM_Manager);
}

int _GetPvPTeamCount(void *pDataManager)
{
	if (bFairPVP)return 10;
	return *((unsigned int*)pDataManager + 11540);
}

void* _set_add_info(void *pInven_Item, int a2)
{
	if((unsigned int)__builtin_return_address(0) == 0x0820156C)
	{
		char *_esp = NULL;
		__asm__ __volatile__ ("movl %%esp, %[a1];":[a1]"=m"(_esp));
		if (_esp){
			for (int i = 0; i < 200; i++){
				if (897 == *((unsigned int*)&_esp[i]))
				{
					//printf("Get !!! %X\n", i);
					a2 = GetProfileInt(szGamePath, "", "val");
				}
			}
		}
		//printf("====================_set_add_info======================%d\n", a2);
	}
	return ((fnset_add_info)subhook_get_trampoline(hset_add_info))(pInven_Item, a2);
}

bool _isSocketAvatar(void *pAvatarItemMgr1, void *pAvatarItemMgr2)
{
	return true;
}

int patchGame()
{
	getConfigPath(szGamePath, sizeof(szGamePath));
	printf("GameConfigPath:%s\n", szGamePath);

	replaceIAT("select", (void*)my_select);
	replaceIAT("usleep", (void*)my_usleep);
	//replaceIAT("malloc", (void*)my_malloc);

	if (!checkGame("df_coserver_r"))
	{
		n_sleep_time = 13000;
	}
	else if (!checkGame("df_game_r"))
	{
		int nMaxClientNum_Game = GetProfileInt(szGamePath, "", "max_client");
		bool bHumanCertify = GetProfileInt(szGamePath, "", "random_human_certify") != 0;
		unsigned int nMaxGrade = GetProfileInt(szGamePath, "", "max_grade");
		if (nMaxGrade > 255)nMaxGrade = 255;
		//if (nMaxGrade < 70)nMaxGrade = 70;
		bGMMode = GetProfileInt(szGamePath, "", "force_gm_mode") != 0;
		bFairPVP = GetProfileInt(szGamePath, "", "fair_pvp") != 0;
		bPickupRout = GetProfileInt(szGamePath, "", "pickup_rout") != 0;
		bool bDespirTowerUnlimit = GetProfileInt(szGamePath, "", "despir_tower_unlimit") != 0;
		printf("GM Mode: %s\n", bGMMode ? "on" : "off");
		printf("Human Certify: %s\n", bHumanCertify ? "on" : "off");
		printf("Fair PVP: %s\n", bFairPVP ? "on" : "off");
		printf("Pickup Rout: %s\n", bPickupRout ? "on" : "off");
		printf("Despir Tower Unlimit: %s\n", bDespirTowerUnlimit ? "on" : "off");
		if (bGMMode)
		{
			safe_write_byte(MAIN_OFFSET(0x2512DA + 1), 1);
		}
		/*safe_write_byte(MAIN_OFFSET(0x1B954E), 0x68);
		safe_write_uint(MAIN_OFFSET(0x1B954E + 1), (int)_hook_item_897);
		safe_write_byte(MAIN_OFFSET(0x1B954E + 5), 0xC3);
		safe_write_byte(MAIN_OFFSET(0x1B954E), 0xB8);
		safe_write_byte(MAIN_OFFSET(0x1B954F), 0x64);
		safe_write_byte(MAIN_OFFSET(0x1B9550), 0x00);
		safe_write_byte(MAIN_OFFSET(0x1B9551), 0x00);
		safe_write_byte(MAIN_OFFSET(0x1B9552), 0x00);
		safe_write_uint(MAIN_OFFSET(0x1B9553), 0x90909090);
		safe_write_byte(MAIN_OFFSET(0x1B9557), 0x90);
		safe_write_byte(MAIN_OFFSET(0x1B9558), 0x90);
		safe_write_byte(MAIN_OFFSET(0x1B9559), 0x90);*/
		if (bDespirTowerUnlimit)
		{
			safe_write_byte(MAIN_OFFSET(0x5FC1AC), 0xEB);
		}
		safe_write((void*)(0x080EE403 + 1), &nMaxClientNum_Game, sizeof(nMaxClientNum_Game));
		safe_write((void*)(0x080EE423 + 1), &nMaxClientNum_Game, sizeof(nMaxClientNum_Game));
		safe_write((void*)(0x080EE463 + 1), &nMaxClientNum_Game, sizeof(nMaxClientNum_Game));
		safe_write((void*)(0x080EE483 + 1), &nMaxClientNum_Game, sizeof(nMaxClientNum_Game));
		safe_write((void*)(0x082AE3F1 + 2), &nMaxClientNum_Game, sizeof(nMaxClientNum_Game));
		safe_write((void*)(0x082AE88B + 2), &nMaxClientNum_Game, sizeof(nMaxClientNum_Game));
		safe_write((void*)(0x082AEAE9 + 2), &nMaxClientNum_Game, sizeof(nMaxClientNum_Game));
		safe_write((void*)(0x082AEFB9 + 2), &nMaxClientNum_Game, sizeof(nMaxClientNum_Game));
		int for_num = nMaxClientNum_Game - 1;
		safe_write((void*)(0x082AE3FF + 1), &for_num, sizeof(for_num));
		safe_write((void*)(0x082AE431 + 1), &for_num, sizeof(for_num));
		safe_write((void*)(0x082AE4FF + 3), &for_num, sizeof(for_num));
		safe_write((void*)(0x082AE899 + 1), &for_num, sizeof(for_num));
		safe_write((void*)(0x082AE8CB + 1), &for_num, sizeof(for_num));
		safe_write((void*)(0x082AE999 + 3), &for_num, sizeof(for_num));
		safe_write((void*)(0x082AEAF7 + 1), &for_num, sizeof(for_num));
		safe_write((void*)(0x082AEB29 + 1), &for_num, sizeof(for_num));
		safe_write((void*)(0x082AEBF7 + 3), &for_num, sizeof(for_num));
		safe_write((void*)(0x082AEFC7 + 1), &for_num, sizeof(for_num));
		safe_write((void*)(0x082AEFF9 + 1), &for_num, sizeof(for_num));
		safe_write((void*)(0x082AF0C7 + 3), &for_num, sizeof(for_num));
		unsigned int val = 4 + 0x8EC3C * nMaxClientNum_Game;
		safe_write((void*)(0x082AE3E1 + 3), &val, sizeof(val));
		val = 4 + 0x1B08 * nMaxClientNum_Game;
		safe_write((void*)(0x082AE87B + 3), &val, sizeof(val));
		val = 4 + 0x6F0 * nMaxClientNum_Game;
		safe_write((void*)(0x082AEAD9 + 3), &val, sizeof(val));
		val = 4 + 0xB6C * nMaxClientNum_Game;
		safe_write((void*)(0x082AEFA9 + 3), &val, sizeof(val));
#if 0
		safe_write_byte(MAIN_OFFSET(0x135E32), 0xEB);
		safe_write_byte(MAIN_OFFSET(0x22069B), 0x01);
		safe_write_byte(MAIN_OFFSET(0x220894), 0x01);
		safe_write_byte(MAIN_OFFSET(0x254D78), 0xEB);
		safe_write_byte(MAIN_OFFSET(0x258E80), 0xEB);
		safe_write_byte(MAIN_OFFSET(0x314ECB), 0xEB);
		safe_write_byte(MAIN_OFFSET(0x314FCB), 0xEB);
		safe_write_byte(MAIN_OFFSET(0x318CC8), 0xE6);
		safe_write_byte(MAIN_OFFSET(0x31C128), 0x7E);
		safe_write_byte(MAIN_OFFSET(0x31C129), 0x06);

		safe_write_byte(MAIN_OFFSET(0x602DAF), 0x7C);

		safe_write_byte(MAIN_OFFSET(0x61AF55), 0x55);
		safe_write_byte(MAIN_OFFSET(0x61B0F3), 0x55);
		safe_write_byte(MAIN_OFFSET(0x61DD28), 0x54);
		safe_write_byte(MAIN_OFFSET(0x61E86A), 0x57);
		safe_write_byte(MAIN_OFFSET(0x61EE9C), 0x54);
		safe_write_byte(MAIN_OFFSET(0x6224A8), 0x54);
		safe_write_byte(MAIN_OFFSET(0x622929), 0x55);
		safe_write_byte(MAIN_OFFSET(0x641D4B), 0x54);
		safe_write_byte(MAIN_OFFSET(0x647ECE), 0x55);
		safe_write_byte(MAIN_OFFSET(0x647EDA), 0x55);
		safe_write_byte(MAIN_OFFSET(0x647F82), 0x56);
		safe_write_byte(MAIN_OFFSET(0x647F88), 0x56);
		safe_write_byte(MAIN_OFFSET(0x66521D), 0x56);
		safe_write_byte(MAIN_OFFSET(0x665223), 0x56);
#else
		//AradAppSystem::AradAppInit
		safe_write_byte(MAIN_OFFSET(0x135E32), 0xEB);
		//ServerParameterScript::setDungeonOpen
		safe_write_byte(MAIN_OFFSET(0x22069B), 0x01);
		//ServerParameterScript::isDungeonOpen
		safe_write_byte(MAIN_OFFSET(0x220894), 0x01);
		//AntiBot init
		safe_write_byte(MAIN_OFFSET(0x254D78), 0xEB);
		//Init DataManager
		safe_write_byte(MAIN_OFFSET(0x258E80), 0xEB);
		//Init Level Exp
		safe_write_byte(MAIN_OFFSET(0x314ECB), 0xEB);
		//Init Mob Reward
		safe_write_byte(MAIN_OFFSET(0x314FCB), 0xEB);
		//CDataManager::GetSpAtLevelUp
		safe_write_byte(MAIN_OFFSET(0x318CC8), 0xE6);
		//fixbug
		safe_write_byte(MAIN_OFFSET(0x31C128), 0x7E);
		safe_write_byte(MAIN_OFFSET(0x31C129), 0x06);
		//pickup rout
		safe_write_byte(MAIN_OFFSET(0x107D53), 0x90);
		safe_write_byte(MAIN_OFFSET(0x107D54), 0x90);
		safe_write_byte(MAIN_OFFSET(0x55D6D1), 0x90);
		safe_write_byte(MAIN_OFFSET(0x55D6D2), 0x90);
		safe_write_byte(MAIN_OFFSET(0x6382F4), bHumanCertify);
		safe_write_byte(MAIN_OFFSET(0x547005), nMaxGrade);
		safe_write_byte(MAIN_OFFSET(0x61AF55), nMaxGrade);
		safe_write_byte(MAIN_OFFSET(0x61B0F3), nMaxGrade);
		safe_write_byte(MAIN_OFFSET(0x61DD28), nMaxGrade-1);
		safe_write_byte(MAIN_OFFSET(0x61E86A), nMaxGrade);
		safe_write_byte(MAIN_OFFSET(0x61EE9C), nMaxGrade-1);
		safe_write_byte(MAIN_OFFSET(0x6224A8), nMaxGrade-1);
		safe_write_byte(MAIN_OFFSET(0x622929), nMaxGrade);
		safe_write_byte(MAIN_OFFSET(0x641D4B), nMaxGrade-1);
		safe_write_byte(MAIN_OFFSET(0x647ECE), nMaxGrade);
		safe_write_byte(MAIN_OFFSET(0x647EDA), nMaxGrade);
		safe_write_byte(MAIN_OFFSET(0x647F82), nMaxGrade);
		safe_write_byte(MAIN_OFFSET(0x647F88), nMaxGrade);
		safe_write_byte(MAIN_OFFSET(0x66521D), nMaxGrade);
		safe_write_byte(MAIN_OFFSET(0x665223), nMaxGrade);
		if (nMaxGrade > 70)
		{
			//以下需要扩充类大小, 修改偏移
			safe_write_uint(MAIN_OFFSET(0x87162 + 3), 0xB678 + nMaxGrade*4 + nMaxGrade*12);
			//CDataManager::set_reward_sp
			safe_write_uint(MAIN_OFFSET(0x318C26 + 2), 10836 + 840);
			safe_write_byte(MAIN_OFFSET(0x318C3B), nMaxGrade);
			safe_write_uint(MAIN_OFFSET(0x318C68 + 2), 10836 + 840);
			safe_write_byte(MAIN_OFFSET(0x318C79), nMaxGrade);
			//CDataManager::GetSpAtLevelUp
			safe_write_byte(MAIN_OFFSET(0x318CC4), nMaxGrade);
			safe_write_uint(MAIN_OFFSET(0x318CD4 + 2), 10836 + 840);
#if 0
			//CDataManager::getDailyTrainingQuest
			safe_write_uint(MAIN_OFFSET(0x31C110 + 1), 0xB678 + nMaxGrade*4);
			//CDataManager::isThereDailyTrainingQuestList
			safe_write_byte(MAIN_OFFSET(0x31C12D), nMaxGrade);
			//CDataManager::reselectDailyTrainingQuest
			//扩充栈内存
			unsigned int incsize = (nMaxGrade-70)*4*6;
			safe_write_uint(MAIN_OFFSET(0x31BCE6 + 2), 0x70C + incsize);
			safe_write_uint(MAIN_OFFSET(0x31BD03 + 2), 0xFFFFF91C - incsize);
			safe_write_uint(MAIN_OFFSET(0x31BD2E + 2), 0xFFFFF914 - incsize);
			safe_write_uint(MAIN_OFFSET(0x31BD5E + 2), 0xFFFFF914 - incsize);
			safe_write_uint(MAIN_OFFSET(0x31BD77 + 2), 0xFFFFF91C - incsize);
			safe_write_uint(MAIN_OFFSET(0x31BDD2 + 2), 0xFFFFF91C - incsize);
			safe_write_uint(MAIN_OFFSET(0x31BEED + 2), 0xFFFFF91C - incsize);
			safe_write_uint(MAIN_OFFSET(0x31C098 + 2), 0xFFFFF91C - incsize);
			safe_write_uint(MAIN_OFFSET(0x31C0AA + 2), 0xFFFFF91C - incsize);
			safe_write_uint(MAIN_OFFSET(0x31C0B6 + 2), 0xFFFFF91C - incsize);
			safe_write_uint(MAIN_OFFSET(0x31C0D9 + 2), 0xFFFFF91C - incsize);

			safe_write_byte(MAIN_OFFSET(0x31BD0B + 1), nMaxGrade-1);
			safe_write_byte(MAIN_OFFSET(0x31BD38 + 1), nMaxGrade-1);
			safe_write_byte(MAIN_OFFSET(0x31C084 + 3), nMaxGrade);
			safe_write_uint(MAIN_OFFSET(0x31BDA4 + 1), 0xB678 + nMaxGrade*4);
			safe_write_uint(MAIN_OFFSET(0x31BEBC + 1), 0xB678 + nMaxGrade*4);
			safe_write_uint(MAIN_OFFSET(0x31BF4A + 1), 0xB678 + nMaxGrade*4);
			safe_write_uint(MAIN_OFFSET(0x31BF82 + 1), 0xB678 + nMaxGrade*4);
			safe_write_uint(MAIN_OFFSET(0x31BFAE + 1), 0xB678 + nMaxGrade*4);
			//TrainingQuestScript::getApplyLevel
			safe_write_byte(MAIN_OFFSET(0xA67AFB + 3), nMaxGrade);
			//TrainingQuestScript::suffleTrainingQuests
			safe_write_byte(MAIN_OFFSET(0xA67DAA + 3), nMaxGrade);
			//CDataManager::CDataManager
			safe_write_uint(MAIN_OFFSET(0x30DF24 + 2), 0xB678 + nMaxGrade*4);
			safe_write_byte(MAIN_OFFSET(0x30DF2C + 1), nMaxGrade-1);
			safe_write_byte(MAIN_OFFSET(0x30DF56 + 1), nMaxGrade-1);
#endif
		}
		safe_write_byte(MAIN_OFFSET(0x61B8F6), nMaxGrade);
		safe_write_byte(MAIN_OFFSET(0x622659), nMaxGrade);
		safe_write_byte(MAIN_OFFSET(0x622941), nMaxGrade);
		safe_write_byte(MAIN_OFFSET(0x622941), nMaxGrade);

		SUBHOOK_SETUP(doDispatch);
		//SUBHOOK_SETUP(addServerHackCnt);
		SUBHOOK_SETUP(put_header);
		SUBHOOK_SETUP(IsRoutingItem);
		SUBHOOK_SETUP(setCharacInfoDetail);
		//SUBHOOK_SETUP(IsGameMasterMode);
		SUBHOOK_SETUP(isGMUser);
		SUBHOOK_SETUP(isGM);
		SUBHOOK_SETUP(isGM1);
		SUBHOOK_SETUP(GetPvPTeamCount);
		SUBHOOK_SETUP(set_add_info);
		SUBHOOK_SETUP(isSocketAvatar);
#endif
	}
	else if (!checkGame("df_channel_r"))
	{
		int nMaxClientNum_Gate = GetProfileInt(szGamePath, "server", "max_client");

		int for_num = nMaxClientNum_Gate - 1;
		unsigned int val = 4 + 0x1C * nMaxClientNum_Gate;
		safe_write((void*)(0x0805361E + 3), &val, sizeof(val));
		safe_write((void*)(0x0805362E + 2), &nMaxClientNum_Gate, sizeof(nMaxClientNum_Gate));
		safe_write((void*)(0x0805363C + 1), &for_num, sizeof(for_num));
		safe_write((void*)(0x080536B8 + 4), &nMaxClientNum_Gate, sizeof(nMaxClientNum_Gate));
		safe_write((void*)(0x08053783 + 3), &for_num, sizeof(for_num));
		val = 4 + 0x140060 * nMaxClientNum_Gate;
		safe_write((void*)0x0805380D, &val, sizeof(val));
		safe_write((void*)0x0805381C, &nMaxClientNum_Gate, sizeof(nMaxClientNum_Gate));
		safe_write((void*)0x08053829, &for_num, sizeof(for_num));
		safe_write((void*)0x080538A4, &nMaxClientNum_Gate, sizeof(nMaxClientNum_Gate));
		safe_write((void*)0x08053964, &for_num, sizeof(for_num));
	}
	else if (!checkGame("df_bridge_r"))
	{
		int nMaxClientNum_Gate = GetProfileInt(szGamePath, "server", "max_client");

		int for_num = nMaxClientNum_Gate - 1;
		unsigned int val = 4 + 0x1C * nMaxClientNum_Gate;
		safe_write((void*)(0x08058018 + 3), &val, sizeof(val));
		safe_write((void*)(0x08058028 + 2), &nMaxClientNum_Gate, sizeof(nMaxClientNum_Gate));
		safe_write((void*)(0x08058036 + 1), &for_num, sizeof(for_num));
		safe_write((void*)(0x080580B2 + 4), &nMaxClientNum_Gate, sizeof(nMaxClientNum_Gate));
		safe_write((void*)(0x0805817D + 3), &for_num, sizeof(for_num));
		val = 4 + 0x140060 * nMaxClientNum_Gate;
		safe_write((void*)0x08058207, &val, sizeof(val));
		safe_write((void*)0x08058216, &nMaxClientNum_Gate, sizeof(nMaxClientNum_Gate));
		safe_write((void*)0x08058223, &for_num, sizeof(for_num));
		safe_write((void*)0x0805829E, &nMaxClientNum_Gate, sizeof(nMaxClientNum_Gate));
		safe_write((void*)0x0805835E, &for_num, sizeof(for_num));
	}
	return 0;
}

void PrintTag()
{
	printf("\n");
	printf("**********************************************************\n");
	printf("*              DNF Server Plugin V%d.%02d                   *\n", Ver, Patch);
	printf("*                                                        *\n");
	printf("*         /\\  /\\                                         *\n");
	printf("*                                                        *\n");
	printf("*           __                       Auther:Larva        *\n");
	printf("*                                    QQ Group:81411049   *\n");
	printf("**********************************************************\n");
}

void __attribute__ ((constructor)) my_init(void)
{
	PrintTag();
	patchGame();
}