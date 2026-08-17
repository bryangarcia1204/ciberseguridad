// process_list.cpp
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <sstream>

extern "C" {

// Estructura para devolver información de un proceso
struct ProcessInfo {
    DWORD pid;
    wchar_t name[260];  // MAX_PATH
    DWORD parent_pid;
};

// Función que llena un array con procesos y devuelve el número de procesos.
// El parámetro 'outArray' debe ser un puntero a un array de ProcessInfo
// suficientemente grande. 'maxCount' indica el tamaño máximo.
__declspec(dllexport) int GetProcessList(ProcessInfo* outArray, int maxCount) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return -1;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return -1;
    }

    int count = 0;
    do {
        if (count >= maxCount) break;
        outArray[count].pid = pe32.th32ProcessID;
        wcscpy(outArray[count].name, pe32.szExeFile);
        outArray[count].parent_pid = pe32.th32ParentProcessID;
        count++;
    } while (Process32NextW(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return count;
}

} // extern "C"