#include "ScanDir.h"

using namespace std;

string systemDrive =""; //initialize system drive string
ofstream exeFiles; // initialize file output

int totalfile=0; //total file count
int filteredfile=0; //number of files filtered

vector<data> data1; //data storage

int dataCount=0; //number of data to be wrriten to file

DIRLIST dir; //Directory listing
DIRLIST filelist; //File listing

int DAYS=30; //Default scanning days range

struct tm * timeinfo; //initialize timeinformation structure

//--normal declaration of main
int _tmain(int argc, TCHAR *argv[])
//--Declaration to hide window console
//int wWinMain(HINSTANCE hInst, HINSTANCE prevInst, LPWSTR  szCmdLine, int nCmdShow)
{
	//switch to enable scanning of different days range
	if(argc>1)
		if(_tcscmp(_T("-d"),argv[1])==0) {
			if(argv[2]!=NULL)
				DAYS=atoi(argv[2]);
			if(DAYS==0) {
				cout<<"Only numbers allowed, using default 30 days to run.."<<endl;
				DAYS=30;
			}
		}
		else {
			cout<<"Usage: autoscan.exe -d <number of days>"<<endl;
			return 0;
		}
	else
		cout<<"Optional usage: autoscan.exe -d <specify number of days>\n";

	/* initialize working directory path */
	string dirPath = ExePath() +"\\reports\\";
	CreateDirectory (dirPath.c_str(), NULL);

	clock_t begin = clock(); //timing start

	/* Varibles for timestamp */
	char pathsend[200] = {0};
	char reportPath[200]= {0};
	char buffer [100]= {0};
	time_t rawtime;

	/* Variables for UUID creation */
	UUID* pUUID=NULL;
	unsigned char* sTemp;
	string uuid="";

	string szDir;
	size_t length_of_arg;

	/* Getting timestamp as part of filename */
	time ( &rawtime );
	timeinfo = localtime ( &rawtime );
	strftime (buffer,100,"%Y%m%d-%H%M%S",timeinfo);

	/* Generate unique UUID(MAC based) */
	pUUID = new UUID;
	HRESULT hr;
	hr = UuidCreateSequential(pUUID);
	hr = UuidToString(pUUID, &sTemp);
	strcat(reportPath,dirPath.c_str());

	/* Preparing string create file */
	strcat (buffer,"-");
	strcat (buffer,reinterpret_cast<char *>(sTemp));
	strcat (pathsend," ");

	toUpper(buffer,100);

	strcat (buffer,".pad");
	strcat(pathsend,buffer);
	strcat(reportPath,buffer);

	exeFiles.open(reportPath, ios::out); //Report file creation

	systemDrive = getenv("SystemDrive"); //Get system drive label
	cout<<"Scanning.."<<systemDrive<<endl;

	dir.push_back(systemDrive +"\\"); //Initialize directory listing
	listDir(systemDrive +"\\"); //Get directory listing

	/* Get file listing thread */
	HANDLE hThread;
	unsigned threadID;
	hThread = (HANDLE)_beginthreadex( NULL, 0, &listFile, NULL, 0, &threadID );
	WaitForSingleObject(hThread,INFINITE);

	/* Scanning based on file listing */
	string pathWithFile=""; //File path
	HANDLE hFile; // Handle to file
	WIN32_FIND_DATA fileInfo; // File information
	MD5 md5; //MD5 hash

	DIRLIST::iterator theIterator; //Iterator for file list vector

	// Loop through file list vector.

	for (theIterator = filelist.begin(); theIterator != filelist.end();
		theIterator++)
	{

		pathWithFile = *theIterator;

		int checkPEval; //PE header checking return value

		HANDLE h=getFileHandle(pathWithFile); //File handle
		HANDLE h2 =getMapHandle(h); //Mapping handle
		if ( h2 == 0 )
		{
			checkPEval = -1;
		}
		else {
			LPCTSTR h3 = fileMap(h2); //File mapping

			checkPEval = checkPEnew(h3); //PE checking
		}

		/* PE is exe */
		if(checkPEval==8)
		{
			bool write=true;
			/* Character filter */
			for(int i=0;i<strlen(fileInfo.cFileName);i++) {
				if(fileInfo.cFileName[i] == '&' || fileInfo.cFileName[i] == '!') {
					
					write = false;
					break;
				}
			}

			/* prepare conversion from string to wide string format */
			string be = pathWithFile;
			wstring stemp = wstring(be.begin(), be.end());
			LPCWSTR sw = stemp.c_str();

			int sigval = VerifyEmbeddedSignature(sw); //Signature checking

			/* File unsigned */
			if(write && sigval==0) {
				GetFileAttributesExW(sw, GetFileExInfoStandard, &fileInfo); //Obtain file attributes

				/* Get file size info */
				ULONGLONG FileSize = fileInfo.nFileSizeHigh;
				FileSize <<= sizeof( fileInfo.nFileSizeHigh ) * 8; 
				FileSize |= fileInfo.nFileSizeLow;

				wstring stemp = wstring(pathWithFile.begin(), pathWithFile.end());
				LPCWSTR sw = stemp.c_str();
				SHFILEINFO sfi;
				SHGetFileInfo(const_cast<char *>( pathWithFile.c_str() ),FILE_ATTRIBUTE_NORMAL,&sfi,sizeof(SHFILEINFO),SHGFI_TYPENAME | SHGFI_USEFILEATTRIBUTES);   

				/* Get creation,modified and accessed date */
				SYSTEMTIME outCreate;
				FILETIME inCreate;
				inCreate.dwHighDateTime = fileInfo.ftCreationTime.dwHighDateTime;
				inCreate.dwLowDateTime =fileInfo.ftCreationTime.dwLowDateTime;
				FileTimeToSystemTime(&inCreate,&outCreate);

				SYSTEMTIME outModi;
				FILETIME inModi;
				inModi.dwHighDateTime = fileInfo.ftLastWriteTime.dwHighDateTime;
				inModi.dwLowDateTime =fileInfo.ftLastWriteTime.dwLowDateTime;
				FileTimeToSystemTime(&inModi,&outModi);

				SYSTEMTIME outAccess;
				FILETIME inAccess;
				inAccess.dwHighDateTime = fileInfo.ftLastAccessTime.dwHighDateTime;
				inAccess.dwLowDateTime = fileInfo.ftLastAccessTime.dwLowDateTime;
				FileTimeToSystemTime(&inAccess,&outAccess);

				/* Fill data for file report output */
				char *a=new char[pathWithFile.size()+1];
				a[pathWithFile.size()]=0;
				memcpy(a,pathWithFile.c_str(),pathWithFile.size());
				data1.push_back(data());
				data1[dataCount].path = ANSIToUTF8(a);
				data1[dataCount].md5 =md5.digestFile(const_cast<char *>( pathWithFile.c_str() )); //md5 hashing
				data1[dataCount].type = "EXE";
				data1[dataCount].signature = sigval;
				data1[dataCount].datecreateyear = outCreate.wYear;
				data1[dataCount].datecreatemonth = outCreate.wMonth;
				data1[dataCount].datecreateday = outCreate.wDay;
				data1[dataCount].datemodifiedyear = outModi.wYear;
				data1[dataCount].datemodifiedmonth = outModi.wMonth;
				data1[dataCount].datemodifiedday = outModi.wDay;
				data1[dataCount].dateaccessedyear = outAccess.wYear;
				data1[dataCount].dateaccessedmonth = outAccess.wMonth;
				data1[dataCount].dateaccessedday = outAccess.wDay;
				data1[dataCount].size = FileSize;
				dataCount++;				

			}
			/* PE is DLL */
			else if(checkPEval==9)
			{
				bool write=true;
				/* Character filtering */
				for(int i=0;i < strlen(fileInfo.cFileName);i++) {
					if(fileInfo.cFileName[i] == '&' || fileInfo.cFileName[i] == '!') {
						//cout<<"Filtered dll "<<fileInfo.cFileName<<endl;
						write = false;
						break;
					}
				}
				/* prepare conversion from string to wide string format */
				string be = pathWithFile;
				wstring stemp = wstring(be.begin(), be.end());
				LPCWSTR sw = stemp.c_str();

				int sigval = VerifyEmbeddedSignature(sw); //Signature checking

				/* File unsigned */
				if(write && sigval==0) {
					GetFileAttributesExW(sw, GetFileExInfoStandard, &fileInfo); //Obtain file attributes

					/* Get file size */
					ULONGLONG FileSize = fileInfo.nFileSizeHigh;
					FileSize <<= sizeof( fileInfo.nFileSizeHigh ) * 8; 
					FileSize |= fileInfo.nFileSizeLow;

					wstring stemp = wstring(pathWithFile.begin(), pathWithFile.end());
					LPCWSTR sw = stemp.c_str();

					SHFILEINFO sfi;
					SHGetFileInfo(const_cast<char *>( pathWithFile.c_str() ),FILE_ATTRIBUTE_NORMAL,&sfi,sizeof(SHFILEINFO),SHGFI_TYPENAME | SHGFI_USEFILEATTRIBUTES);   

					/* Get creation,modified and accessed date */
					SYSTEMTIME outCreate;
					FILETIME inCreate;
					inCreate.dwHighDateTime = fileInfo.ftCreationTime.dwHighDateTime;
					inCreate.dwLowDateTime =fileInfo.ftCreationTime.dwLowDateTime;
					FileTimeToSystemTime(&inCreate,&outCreate);

					SYSTEMTIME outModi;
					FILETIME inModi;
					inModi.dwHighDateTime = fileInfo.ftLastWriteTime.dwHighDateTime;
					inModi.dwLowDateTime =fileInfo.ftLastWriteTime.dwLowDateTime;
					FileTimeToSystemTime(&inModi,&outModi);

					SYSTEMTIME outAccess;
					FILETIME inAccess;
					inAccess.dwHighDateTime = fileInfo.ftLastAccessTime.dwHighDateTime;
					inAccess.dwLowDateTime = fileInfo.ftLastAccessTime.dwLowDateTime;
					FileTimeToSystemTime(&inAccess,&outAccess);

					/* Fill data for file report output */
					char *a=new char[pathWithFile.size()+1];
					a[pathWithFile.size()]=0;
					memcpy(a,pathWithFile.c_str(),pathWithFile.size());
					data1.push_back(data());
					data1[dataCount].path = ANSIToUTF8(a);
					data1[dataCount].md5 =md5.digestFile(const_cast<char *>( pathWithFile.c_str() )); //md5 hashing
					data1[dataCount].type = "DLL";
					data1[dataCount].signature =sigval;
					data1[dataCount].datecreateyear = outCreate.wYear;
					data1[dataCount].datecreatemonth = outCreate.wMonth;
					data1[dataCount].datecreateday = outCreate.wDay;
					data1[dataCount].datemodifiedyear = outModi.wYear;
					data1[dataCount].datemodifiedmonth = outModi.wMonth;
					data1[dataCount].datemodifiedday = outModi.wDay;
					data1[dataCount].dateaccessedyear = outAccess.wYear;
					data1[dataCount].dateaccessedmonth = outAccess.wMonth;
					data1[dataCount].dateaccessedday = outAccess.wDay;
					data1[dataCount].size = FileSize;
					dataCount++;

				}
			}
		}


	}

	/* Write data into file */
	exeFiles<<"<REPORT>\n\t<IMAGES>"; 
	for(int i=0;i<dataCount;i++ ) {

		exeFiles <<"\n\t\t<IMAGE>"<<
			"\n\t\t\t<PATH>";
		exeFiles << data1[i].path;
		exeFiles <<"</PATH>"<<
			"\n\t\t\t<MD5>"<<data1[i].md5<<"</MD5>"<<
			"\n\t\t\t<EXE_TYPE>"<<data1[i].type<<"</EXE_TYPE>"<<
			"\n\t\t\t<ISSIGNED>"<<data1[i].signature<<"</ISSIGNED>"<<
			"\n\t\t\t<DATE_CREATED>"<<data1[i].datecreateyear<<"-"<<data1[i].datecreatemonth<<"-"<<data1[i].datecreateday<<"</DATE_CREATED>"<<
			"\n\t\t\t<DATE_MODIFIED>"<<data1[i].datemodifiedyear<<"-"<<data1[i].datemodifiedmonth<<"-"<<data1[i].datemodifiedday<<"</DATE_MODIFIED>"<<
			"\n\t\t\t<DATE_ACCESSED>"<<data1[i].dateaccessedyear<<"-"<<data1[i].dateaccessedmonth<<"-"<<data1[i].dateaccessedday<<"</DATE_ACCESSED>"<<
			"\n\t\t\t<PE_STATIC_FLAGS>\n\t\t\t\t<FILE_SIZE>"<<data1[i].size<<"</FILE_SIZE>\n\t\t\t</PE_STATIC_FLAGS>"
			"\n\t\t</IMAGE>";
	}

	exeFiles<<"\n\t</IMAGES>\n</REPORT>";
	exeFiles.close();

	/* Zip report directory */
	SHELLEXECUTEINFO ShExecInfo = {0};
	ShExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);
	ShExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
	ShExecInfo.hwnd = NULL;
	ShExecInfo.lpVerb = NULL;
	ShExecInfo.lpFile = "7za.exe";
	ShExecInfo.lpParameters = " a -tzip reports.zip .\\reports";
	string direc = ExePath()+"\\";
	ShExecInfo.lpDirectory = direc.c_str();
	ShExecInfo.nShow = SW_HIDE;
	ShExecInfo.hInstApp = NULL;	
	ShellExecuteEx(&ShExecInfo);
	WaitForSingleObject(ShExecInfo.hProcess,INFINITE);

	clock_t end = clock(); //timing end
	double elapsed_secs = double(end - begin) / CLOCKS_PER_SEC;
	cout<<elapsed_secs/60<<endl;

	return 0;

}
/* Get working directory path */
string ExePath() {
    char buffer[MAX_PATH];
    GetModuleFileName( NULL, buffer, MAX_PATH );
    string::size_type pos = string( buffer ).find_last_of( "\\/" );
    return string( buffer ).substr( 0, pos);
}

/* Get directory listing */
void listDir(string basePath) {

	string tempStr = "";
	HANDLE          hFile;                   // Handle to file
	WIN32_FIND_DATA fileInfo;         // File information
	tempStr = basePath + "\\*";
	hFile = FindFirstFile(tempStr.c_str(), &fileInfo);

	do
	{
		if (fileInfo.cFileName[0] != '.') //filter current directory .
		{
			if (fileInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY && fileInfo.cFileName != "." && fileInfo.cFileName != "..")//If a it is a folder
			{
				tempStr = basePath + fileInfo.cFileName + "\\";

				dir.push_back(tempStr);

				listDir(tempStr);

			}
		}

	}while (FindNextFile(hFile, &fileInfo) != 0); 

	FindClose(hFile);

}

/* Get file listing */
unsigned __stdcall listFile( void* pArguments ) {

	string tempStr = "";
	HANDLE          hFile;                   // Handle to file
	WIN32_FIND_DATA fileInfo;         // File information
	string pathWithFile="";

	DIRLIST::iterator theIterator; //Iterate directory to find files

	//non leap year month format
	int monthFormat[]= {31,28,31,30,31,30,31,31,30,31,30,31};

	//current time
	int year = timeinfo->tm_year+1900;
	int month = timeinfo->tm_mon;
	int day = timeinfo->tm_mday;

	int sumDays =0;
	int totalDaysThisYear= 0;
	int filedays;

	//current year days calculation
	for(int i=0;i<month;i++)
	{
		totalDaysThisYear+=monthFormat[i];
	}
	totalDaysThisYear+=day;

	// Iterate through directory listing for files
	for (theIterator = dir.begin(); theIterator != dir.end();
		theIterator++)
	{
		tempStr = *theIterator+ "*";

		hFile = FindFirstFile(tempStr.c_str(), &fileInfo);

		do
		{
			if (fileInfo.cFileName[0] != '.')
			{

				if (!(fileInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY && fileInfo.cFileName != "." && fileInfo.cFileName != ".."))//If a it is a folder
				{

					totalfile++; //total file count
					ULONGLONG FileSize = fileInfo.nFileSizeHigh;
					FileSize <<= sizeof( fileInfo.nFileSizeHigh ) * 8; 
					FileSize |= fileInfo.nFileSizeLow;

					//file may be accessed within 30 days
					SYSTEMTIME outAcc;
					FILETIME inAcc;
					inAcc.dwHighDateTime = fileInfo.ftLastAccessTime.dwHighDateTime;
					inAcc.dwLowDateTime =fileInfo.ftLastAccessTime.dwLowDateTime;
					FileTimeToSystemTime(&inAcc,&outAcc);

					//Initialize days count
					sumDays = totalDaysThisYear;
					filedays=0;

					/* Filtering based on days range */
					if(outAcc.wYear!=year) {
						for(int i=11;i>outAcc.wMonth-1;i--)
							filedays+=monthFormat[i];
						filedays+=(monthFormat[outAcc.wMonth]-outAcc.wDay);
						if((year-outAcc.wYear-1)>0) {
							filedays+=365*(year-outAcc.wYear-1);
						}
						sumDays+=filedays;
					}
					else {
						for(int i=0;i<outAcc.wMonth-1;i++)
						{
							filedays+=monthFormat[i];
						}
						filedays+=outAcc.wDay;
						sumDays-=filedays;
					}

					//file may be modified within 30 days
					if(sumDays>DAYS) {

						SYSTEMTIME outModi;
						FILETIME inModi;
						inModi.dwHighDateTime = fileInfo.ftLastWriteTime.dwHighDateTime;
						inModi.dwLowDateTime =fileInfo.ftLastWriteTime.dwLowDateTime;
						FileTimeToSystemTime(&inModi,&outModi);

						sumDays = totalDaysThisYear;
						filedays=0;

						if(outModi.wYear!=year) {
							for(int i=11;i>outModi.wMonth-1;i--)
								filedays+=monthFormat[i];
							filedays+=(monthFormat[outModi.wMonth]-outModi.wDay);
							if((year-outAcc.wYear-1)>0) {
								filedays+=365*(year-outModi.wYear-1);
							}
							sumDays+=filedays;
						}
						else {
							for(int i=0;i<outModi.wMonth-1;i++)
							{
								filedays+=monthFormat[i];
							}
							filedays+=outModi.wDay;
							sumDays-=filedays;
						}
					}
					//file may be moved or created within 30 days
					if(sumDays>DAYS) {

						SYSTEMTIME outCreate;
						FILETIME inCreate;
						inCreate.dwHighDateTime = fileInfo.ftCreationTime.dwHighDateTime;
						inCreate.dwLowDateTime =fileInfo.ftCreationTime.dwLowDateTime;
						FileTimeToSystemTime(&inCreate,&outCreate);

						sumDays = totalDaysThisYear;
						filedays=0;
						if(outCreate.wYear!=year) {
							for(int i=11;i>outCreate.wMonth-1;i--)
								filedays+=monthFormat[i];
							filedays+=(monthFormat[outCreate.wMonth]-outCreate.wDay);
							if((year-outCreate.wYear-1)>0) {
								filedays+=365*(year-outCreate.wYear-1);
							}
							sumDays+=filedays;
						}
						else {
							for(int i=0;i<outCreate.wMonth-1;i++)
							{
								filedays+=monthFormat[i];
							}
							filedays+=outCreate.wDay;
							sumDays-=filedays;
						}
					}

					if(sumDays>DAYS) {
						filteredfile++;
					}
					else if(FileSize<(sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS)) || FileSize>5242880) {
						filteredfile++;
					}
					else {
						pathWithFile = *theIterator + fileInfo.cFileName;

						filelist.push_back(pathWithFile);
					}

					
				}
			}

		}while (FindNextFile(hFile, &fileInfo) != 0); //While there are still files in the folder

		FindClose(hFile);
	}
	cout<<"Total files "<<totalfile<<endl;
	cout<<"Filtered files "<<filteredfile<<endl;
	return 0;
}
/* Character to upper case */
void toUpper(char* pArray, int arrayLength)
{
	for(int i = 0; i < arrayLength; i++)
	{
		if(pArray[i] >= 'a' && pArray[i] <= 'z')
			pArray[i] -= ' ';
	}
}
/* Signature checking */
BOOL VerifyEmbeddedSignature(LPCWSTR pwszSourceFile) 
{ 
	// Signature check based on DRIVER_ACTION_VERIFY of WINVERIFYTRUST
	LONG lStatus; 
	GUID WintrustVerifyGuid = DRIVER_ACTION_VERIFY;
	GUID DriverActionGuid = DRIVER_ACTION_VERIFY; 
	HANDLE hFile; 
	DWORD dwHash; 
	BYTE bHash[100]; 
	HCATINFO hCatInfo; 
	HCATADMIN hCatAdmin; 
	WINTRUST_DATA wd = { 0 }; 
	WINTRUST_FILE_INFO wfi = { 0 }; 
	WINTRUST_CATALOG_INFO wci = { 0 }; 
	DRIVER_VER_INFO dvi = {0}; 

	dvi.cbStruct = sizeof(dvi); 

	//set up structs to verify files with cert signatures 
	memset(&wfi, 0, sizeof(wfi)); 
	wfi.cbStruct = sizeof( WINTRUST_FILE_INFO ); 
	wfi.pcwszFilePath = pwszSourceFile; 
	wfi.hFile = NULL; 
	wfi.pgKnownSubject = NULL; 

	memset(&wd, 0, sizeof(wd)); 
	wd.cbStruct = sizeof( WINTRUST_DATA ); 
	wd.dwUnionChoice = WTD_CHOICE_FILE; 
	wd.pFile = &wfi; 
	wd.dwUIChoice = WTD_UI_NONE; 
	wd.fdwRevocationChecks = WTD_REVOKE_NONE; 
	wd.dwStateAction = 0; 
	wd.dwProvFlags = WTD_SAFER_FLAG; 
	wd.hWVTStateData = NULL; 
	wd.pwszURLReference = NULL; 
	wd.pPolicyCallbackData = &dvi; 
	wd.pSIPClientData = NULL; 
	wd.dwUIContext = 0; 

	lStatus = WinVerifyTrust( NULL, &WintrustVerifyGuid, &wd ); 

	//If failed checking with DRIVER_ACTION_VERIFY
	//Check by WINTRUST_ACTION_GENERIC_VERIFY_V2
	if(lStatus != ERROR_SUCCESS) {
		GUID WintrustVerifyGuid2 = WINTRUST_ACTION_GENERIC_VERIFY_V2;
		lStatus = WinVerifyTrust( NULL, &WintrustVerifyGuid2, &wd ); 

	}
	//If failed, try to verify using catalog files 
	if (lStatus != ERROR_SUCCESS) 
	{ 
		//Initialize object for kernel operation open
		OBJECT_ATTRIBUTES Oa = {0};
		UNICODE_STRING Name_U;
		IO_STATUS_BLOCK IoSb;

		RtlInitUnicodeString(&Name_U, pwszSourceFile);

		Oa.Length = sizeof(Oa);
		Oa.ObjectName = &Name_U;
		Oa.Attributes = OBJ_CASE_INSENSITIVE;
		clock_t start2 = clock();
		NTSTATUS Status = NtOpenFile(&hFile, GENERIC_READ, &Oa, &IoSb, FILE_SHARE_READ, FILE_SEQUENTIAL_ONLY);

		// If failed, cleanup
		if (Status != STATUS_SUCCESS) {

			wd.dwStateAction = WTD_STATEACTION_CLOSE; 
			WinVerifyTrust(NULL, &WintrustVerifyGuid, &wd); 
			return FALSE; 
		}

		dwHash = sizeof(bHash); 
		clock_t checkstart = clock();
		if (!CryptCATAdminCalcHashFromFileHandle(hFile, &dwHash, bHash, 0)) 
		{ 

			CloseHandle(hFile); 

			wd.dwStateAction = WTD_STATEACTION_CLOSE; 
			WinVerifyTrust(NULL, &WintrustVerifyGuid, &wd); 
			return FALSE; 
		} 

		//Create a string form of the hash (used later in pszMemberTag) 
		LPWSTR pszMemberTag = new WCHAR[dwHash * 2 + 1]; 
		for ( DWORD dw = 0; dw < dwHash; ++dw ) 
		{ 
			wsprintfW( &pszMemberTag[dw * 2], L"%02X", bHash[dw] ); 
		} 

		if (!CryptCATAdminAcquireContext(&hCatAdmin, &DriverActionGuid, 0)) 
		{ 
			CloseHandle(hFile); 
			wd.dwStateAction = WTD_STATEACTION_CLOSE; 
			WinVerifyTrust(NULL, &WintrustVerifyGuid, &wd); 
			return FALSE; 
		} 

		//find the catalog which contains the hash 
		hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, bHash, dwHash, 0, NULL); 

		if ( hCatInfo ) 
		{ 
			CATALOG_INFO ci = { 0 }; 
			CryptCATCatalogInfoFromContext( hCatInfo, &ci, 0 ); 

			memset(&wci, 0, sizeof(wci)); 
			wci.cbStruct = sizeof( WINTRUST_CATALOG_INFO ); 
			wci.pcwszCatalogFilePath = ci.wszCatalogFile; 
			wci.pcwszMemberFilePath = pwszSourceFile; 
			wci.pcwszMemberTag = pszMemberTag; 

			memset(&wd, 0, sizeof(wd)); 
			wd.cbStruct = sizeof( WINTRUST_DATA ); 
			wd.dwUnionChoice = WTD_CHOICE_CATALOG; 
			wd.pCatalog = &wci; 
			wd.dwUIChoice = WTD_UI_NONE; 
			wd.fdwRevocationChecks = WTD_STATEACTION_VERIFY; 
			wd.dwProvFlags = 0; 
			wd.hWVTStateData = NULL; 
			wd.pwszURLReference = NULL; 
			wd.pPolicyCallbackData = &dvi; 
			wd.pSIPClientData = NULL; 
			wd.dwUIContext = 0; 
			//Verify action of Guid
			lStatus = WinVerifyTrust( NULL, &WintrustVerifyGuid, &wd ); 

			//Release catalog context
			CryptCATAdminReleaseCatalogContext( hCatAdmin, hCatInfo, 0 ); 
		} 

		CryptCATAdminReleaseContext( hCatAdmin, 0 ); 
		delete[] pszMemberTag; 
		CloseHandle(hFile); 
	} 

	//printf( "version:%S/nsigner:%S\n", dvi.wszVersion, dvi.wszSignedBy ); 

	//Cleanup cert context
	CertFreeCertificateContext(dvi.pcSignerCertContext); 
	// If failed, cleanup
	if (lStatus != ERROR_SUCCESS) {

		wd.dwStateAction = WTD_STATEACTION_CLOSE; 
		WinVerifyTrust(NULL, &WintrustVerifyGuid, &wd); 
		return false; 
	}
	else  {

		wd.dwStateAction = WTD_STATEACTION_CLOSE; 
		WinVerifyTrust(NULL, &WintrustVerifyGuid, &wd); 
		return true;
	}
} 

std::wstring utf8_decode(const std::string &str)
{
	int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
	std::wstring wstrTo( size_needed, 0 );
	MultiByteToWideChar                  (CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
	return wstrTo;
}

/* Character ANSI to UTF8 */
char* ANSIToUTF8(char * pszCode)
{
	int		nLength, nLength2;
	BSTR	bstrCode; 
	char	*pszUTFCode = NULL;

	nLength = MultiByteToWideChar(CP_ACP, 0, pszCode, lstrlen(pszCode), NULL, NULL); 
	bstrCode = SysAllocStringLen(NULL, nLength); 
	MultiByteToWideChar(CP_ACP, 0, pszCode, lstrlen(pszCode), bstrCode, nLength);


	nLength2 = WideCharToMultiByte(CP_UTF8, 0, bstrCode, -1, pszUTFCode, 0, NULL, NULL); 
	pszUTFCode = (char*)malloc(nLength2+1); 
	WideCharToMultiByte(CP_UTF8, 0, bstrCode, -1, pszUTFCode, nLength2, NULL, NULL); 

	return pszUTFCode;
}

/* Getting file handle based on file path */
HANDLE getFileHandle(string &path) {

	HANDLE Handle;

	OBJECT_ATTRIBUTES Oa = {0};
	UNICODE_STRING Name_U;
	IO_STATUS_BLOCK IoSb;
	string path2 = "\\??\\" + path;
	wstring stemp = wstring(path2.begin(), path2.end());
	LPCWSTR sw = stemp.c_str();
	RtlInitUnicodeString(&Name_U, sw); //convert to unicode string

	Oa.Length = sizeof(Oa);
	Oa.ObjectName = &Name_U;
	Oa.Attributes = OBJ_CASE_INSENSITIVE;

	NTSTATUS Status = NtOpenFile(&Handle, GENERIC_READ, &Oa, &IoSb, FILE_SHARE_READ, FILE_SEQUENTIAL_ONLY);

	if(Status == STATUS_SUCCESS)
		return Handle;
	else
		return INVALID_HANDLE_VALUE;
}
/* Getting file mapping handle */
HANDLE getMapHandle(HANDLE hFile) {

	HANDLE hMap = nullptr;
	if(hFile == INVALID_HANDLE_VALUE) {
	}
	else {
		hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY | SEC_COMMIT, 0, 0, 0);

		CloseHandle(hFile);
	}

	return hMap;
}
/* File mapping */
LPCTSTR fileMap(HANDLE &hMap) {

	LPCTSTR pMapping =nullptr;
	pMapping = (LPTSTR)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
	CloseHandle(hMap);
	if ( pMapping  == 0 )
	{

	}

	return (LPCTSTR)pMapping;
}

/* PE checking */
int checkPEnew(LPCTSTR pMapping) {

	IMAGE_DOS_HEADER *idh ={0};
	IMAGE_NT_HEADERS *inh = {0};

	idh  = (IMAGE_DOS_HEADER*)pMapping ;

	if(idh==0) {
		cout<<"failed";
		return -9;
	}
	if (idh->e_magic == IMAGE_DOS_SIGNATURE)
	{
		//printf("dos headers found\n");
		inh = (IMAGE_NT_HEADERS*)(pMapping + idh->e_lfanew); 

		// Matching dos header length and nt header
		if (((DWORD)inh&0xFFFF0000) != ((DWORD)idh&0xFFFF0000)) {

			return -9;
		}
		if (inh->Signature == IMAGE_NT_SIGNATURE)
		{	
			//DLL files
			if (inh->FileHeader.Characteristics & IMAGE_FILE_DLL) {
				UnmapViewOfFile(pMapping);

				return 9;

			}
			//System files
			else if(inh->FileHeader.Characteristics &IMAGE_FILE_SYSTEM) {
				UnmapViewOfFile(pMapping);

				return -7;
			}
			//Exe files
			else if(inh->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) {
				//cout<<"Exe\n";
				UnmapViewOfFile(pMapping);
				return 8;

			}
			else {
				UnmapViewOfFile(pMapping);

				return -6;
			}

		}
		//File unmapping
		else {
			UnmapViewOfFile(pMapping);

			return -5;
		}

	}
	//Not PE
	else {
		
		UnmapViewOfFile(pMapping);
		return -4;
	}

}