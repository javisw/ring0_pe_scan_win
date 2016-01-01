#include <windows.h>
#include <tchar.h> 
#include <stdio.h>
#include <strsafe.h>
#include <fstream>
#include <iostream>
#include <string>
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <time.h>
#include <uuids.h>
#include <rpcdce.h>
#include "md5.h"
#include <ctime>
#include <process.h>
#include <Mscat.h>
#include <vector>
#include <Winternl.h>
#include <ntstatus.h>

#pragma comment(lib, "User32.lib")
#pragma comment(lib, "wintrust")
#pragma comment(lib, "rpcrt4")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ntdll.lib")

#define MAX 255

string ExePath();

unsigned __stdcall listFile( void* pArguments );
void listDir(string basePath);

std::wstring utf8_decode(const std::string &str);

int VerifyEmbeddedSignature(LPCWSTR pwszSourceFile);

char* ANSIToUTF8(char * pszCode);

void toUpper(char* pArray, int arrayLength);

HANDLE getFileHandle(string &path);
HANDLE getMapHandle(HANDLE hFile);
LPCTSTR fileMap(HANDLE &hMap);
int checkPEnew(LPCTSTR pMapping);

struct data {
  string path;
  string md5;
  string type;
  BOOL signature;
  DWORD datecreateyear;
  DWORD datecreatemonth;
  DWORD datecreateday;
  DWORD datemodifiedyear;
  DWORD datemodifiedmonth;
  DWORD datemodifiedday;
  DWORD dateaccessedyear;
  DWORD dateaccessedmonth;
  DWORD dateaccessedday;
  ULONGLONG size;
};

typedef vector<string> DIRLIST;