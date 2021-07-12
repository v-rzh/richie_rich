#include <richie_rich.h>

#ifdef _WINDOWS
int get_file_data(const char *path, struct pe_file *pe)
{
    HANDLE fd, proc_heap;
    DWORD file_size, bytes_read;

    fd = CreateFileA(path, GENERIC_READ, 0, NULL, OPEN_EXISTING,
                     FILE_ATTRIBUTE_NORMAL, NULL);
    if (fd == INVALID_HANDLE_VALUE) {
        ELOG("[err] CreateFileA: (ERR: %ld)\n", GetLastError());
        return -1;
    }

    file_size = GetFileSize(fd, NULL);

    if (file_size == INVALID_FILE_SIZE) {
        ELOG("[err] GetFileSize: (ERR: %ld)\n", GetLastError());
        return -1;
    }

    if (!(proc_heap = GetProcessHeap())) {
        ELOG("[err] GetProcessHeap: (ERR: %ld)\n", GetLastError());
        return -1;
    }

    if (!(pe->data = (uint8_t *)HeapAlloc(proc_heap, 0, file_size))) {
        ELOG("[err] HeapAlloc: An exception has occured\n");
        return -1;
    }

    if (!ReadFile(fd, pe->data, file_size, &bytes_read, NULL)) {
        ELOG("[err] ReadFile: (ERR: %ld)\n", GetLastError());
        CloseHandle(fd);
        return -1;
    }

    pe->len = file_size;

    CloseHandle(fd);
    return 0;
}
#else
int get_file_data(const char *path, struct pe_file *pe)
{
    int fd, errno_save;
    struct stat pe_stat;

    memset(&pe_stat, 0, sizeof(struct stat));

    if (stat(path, &pe_stat) == -1) {
        ELOG("[err] stat: %s\n", strerror(errno));
        return -1;
    }

    if ((fd = open(path, O_RDWR)) == -1) {
        ELOG("[err] open: %s\n", strerror(errno));
        return -1;
    }

    pe->len = pe_stat.st_size;

    pe->data = mmap(NULL, pe->len, PROT_READ | PROT_WRITE, MAP_PRIVATE,
                    fd, 0);

    errno_save = errno;
    close(fd);

    if (pe->data == MAP_FAILED) {
        ELOG("[err] mmap: %s\n", strerror(errno_save));
        return -1;
    }
    return 0;
}
#endif

#ifdef _WINDOWS
int write_file(const char *path, uint8_t *data, size_t len)
{
    HANDLE fd;
    DWORD bytes_written;
    fd = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                     FILE_ATTRIBUTE_NORMAL, NULL);

    if (fd == INVALID_HANDLE_VALUE) {
        ELOG("[err] CreateFileA: (ERR: %ld)\n", GetLastError());
        return -1;
    }

    if (!WriteFile(fd, data, len, &bytes_written, NULL)) {
        ELOG("[err] WriteFile: (ERR: %ld)\n", GetLastError());
        return -1;
    }

    CloseHandle(fd);
    return 0;
}
#else
int write_file(const char *path, uint8_t *data, size_t len)
{
    int fd;

    if ((fd = creat(path, 0755)) == -1) {
        ELOG("creat: %s\n", strerror(errno));
        return -1;
    }

    if (write(fd, data, len) == -1) {
        ELOG("write: %s\n", strerror(errno));
        return -1;
    }
    close(fd);
    return 0;
}
#endif
