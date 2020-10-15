#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <unistd.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <elf.h>
#include <fcntl.h>
#include <errno.h>

#include "subhook/subhook.h"

#define MOVEPOINT(p,i) (void*)((char*)p+i)
#define MAKEPOINTER(t, p, offset) ((t)((unsigned char*)(p) + (long)offset))
#define PADALIGN(x,mask) ((x+mask)&(~(x%mask)))
#define DEF_PAGE_SIZE 4096
#define Ver 1
#define Patch 2
//#define Debug 1

class PacketBuf
{
public:
	PacketBuf (const void* pData = NULL, int iLength = 0, int bCopy = 0)
	{
		if (pData && iLength && bCopy)
		{
			this->pBuf = malloc (iLength);
			if (!this->pBuf)return;
			this->iLen = iLength;
			memcpy (this->pBuf, pData, iLength);
			this->bCopy = 1;
		}
		else if (pData && iLength && !bCopy)
		{
			this->pBuf = (void*)pData;
			this->iLen = iLength;
			this->bCopy = 0;
		}
		else if (!pData && iLength)
		{
			this->pBuf = malloc (DEF_PAGE_SIZE);
			this->iLen = DEF_PAGE_SIZE;
			this->bCopy = 1;
		}
		else
		{
			this->pBuf = NULL;
			this->iLen = 0;
			this->bCopy = 0;
		}
	}
	~PacketBuf ()
	{
		if (bCopy && this->pBuf)free (this->pBuf);
	}
	void setReadPos (size_t iPos)
	{
		this->iRead = iPos;
	}
	size_t getReadPos ()
	{
		return this->iRead;
	}
	char* getReadPtr ()
	{
		return (char*)this->pBuf + this->iRead;
	}
	void setWritePos (size_t iPos)
	{
		if (iLen <= iPos)
		{
			size_t nNewSize = iPos;
			nNewSize = PADALIGN (nNewSize, DEF_PAGE_SIZE);
			pBuf = !pBuf ? malloc (nNewSize) : realloc (pBuf, nNewSize);
			iLen = nNewSize;
		}
		this->iWrite = iPos;
	}
	size_t getWritePos ()
	{
		return this->iWrite;
	}
	char* getWritePtr ()
	{
		return (char*)this->pBuf + this->iWrite;
	}
	template<typename T>
	void get (T& val)
	{
		if (!this->pBuf || iLen < sizeof (T))return;
		val = *(T*)((char*)pBuf + iRead);
		iRead += sizeof (T);
	}
	void get (void* pBuf, size_t nSize)
	{
		if (!this->pBuf || !pBuf || !nSize || iLen < nSize)return;
		memcpy (pBuf, this->getReadPtr (), nSize);
		this->setReadPos (this->getReadPos () + nSize);
	}
	template<typename T>
	void put (T val)
	{
		if (iLen <= iWrite + sizeof (T))
		{
			size_t nNewSize = iWrite + sizeof (T);
			nNewSize = PADALIGN (nNewSize, DEF_PAGE_SIZE);
			pBuf = !pBuf ? malloc (nNewSize) : realloc (pBuf, nNewSize);
			iLen = nNewSize;
		}
		memcpy ((char*)pBuf + iWrite, &val, sizeof (T));
		iWrite += sizeof (T);
	}
	void put (const void* pData, size_t len)
	{
		if (iLen <= iWrite + len)
		{
			size_t nNewSize = iWrite + len;
			nNewSize = PADALIGN (nNewSize, DEF_PAGE_SIZE);
			pBuf = !pBuf ? malloc (nNewSize) : realloc (pBuf, nNewSize);
			iLen = nNewSize;
		}
		memcpy ((char*)pBuf + iWrite, pData, len);
		iWrite += len;
	}
	void* FinalData ()
	{
		return this->pBuf;
	}
	size_t size ()
	{
		return this->iLen;
	}
private:
	void* pBuf = NULL;
	size_t iLen = 0;
	size_t bCopy = 0;
	size_t iRead = 0;
	size_t iWrite = 0;
};

typedef struct _PACK
{
	unsigned char way;
	unsigned short cmd;
	unsigned int len;
	unsigned int hash;
	unsigned int cmphash;
}Pack, *PPack;

__BEGIN_DECLS

typedef int (*fnPacketGuard)(void *pInst);

typedef int (*fnaddServerHackCnt)(void *pCHackAnalyzer, void *pCUserCharacInfo, int HackType, int Cnt, int a5, int a6);

typedef int (*fnParsing)(void *pUser, int nSize);

typedef int (*fnput_header)(void *pInterfacePacketBuf, int Type, int Cmd);

typedef int (*fnIsRoutingItem)(void *pItem);

typedef int (*fnsetCharacInfoDetail)(void *pUser, int a2, int a3, void *pCHARAC_DATA);

typedef void* (*fnGetVectorUserCharacInfo)(void *pUser, int a2);

typedef int (*fnIsGameMasterMode)(void *pUser);

typedef int (*fnisGMUser)(void *pUser);

typedef int (*fnGetPvPTeamCount)(void *pDataManager);

typedef bool (*fnisGM)(void *pGMAccounts, unsigned int a2);

typedef bool (*fnisGM1)(void *pGM_Manager);

typedef void* (*fnset_add_info)(void *pInven_Item, int a2);

typedef int (*fndoDispatch)(void *pPacketDispatcher, void *pUser, int a3, int a4, void *src, int a6, int a7, int a8);

typedef void** (*fnget_dispatcher)(void *pPacketDispatcher, int a2);

typedef bool (*fnisSocketAvatar)(void *pAvatarItemMgr1, void *pAvatarItemMgr2);

typedef int (*fndispatch_template)(void *pInst, void *pUser, void *pPacketBuf);




typedef int (*fnselect) (int __nfds, fd_set *__restrict __readfds,
		   fd_set *__restrict __writefds,
		   fd_set *__restrict __exceptfds,
		   struct timeval *__restrict __timeout);

typedef int (*fnusleep) (__useconds_t __useconds);

typedef void* (*fnmalloc) (size_t __size);

__END_DECLS