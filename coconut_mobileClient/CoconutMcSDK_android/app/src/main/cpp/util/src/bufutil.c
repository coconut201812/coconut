/*############################################################################
  # Copyright 2018 BITMAINTECH PTE LTD.
  #
  # Licensed under the Apache License, Version 2.0 (the "License");
  # you may not use this file except in compliance with the License.
  # You may obtain a copy of the License at
  #
  #     http://www.apache.org/licenses/LICENSE-2.0
  #
  # Unless required by applicable law or agreed to in writing, software
  # distributed under the License is distributed on an "AS IS" BASIS,
  # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  # See the License for the specific language governing permissions and
  # limitations under the License.
############################################################################*/
/*!
 * \file
 * \brief Buffer handling utilities implementation.
 */


#include <stdio.h>
#include <stdlib.h>
#include "util/buffutil.h"


bool FileExists(char const* filename)
{
    FILE* fp = NULL;
    if (!filename || !filename[0])
    {
        return false;
    }

    fp = fopen(filename, "rb");
    if (fp)
    {
        fclose(fp);
        return true;
    }

    return false;
}

size_t GetFileSize(char const* filename)
{
    size_t file_length = 0;
    FILE* fp = fopen(filename, "rb");
    if (fp)
    {
        fseek(fp, 0, SEEK_END);
        file_length = ftell(fp);
        fclose(fp);
    }

    return file_length;
}

size_t GetFileSize_S(char const* filename, size_t max_size)
{
    size_t size = GetFileSize(filename);
    if (size > max_size)
    {
        return 0;
    }
    else
    {
        return size;
    }
}

void* AllocBuffer(size_t size)
{
    void* buffer = NULL;
    if (size)
    {
        buffer = malloc(size);
    }

    return buffer;
}

void* NewBufferFromFile(const char* filename, size_t* size)
{
    void* buffer = NULL;

    do
    {
        size_t len = 0;
        if (!FileExists(filename))
        {
            break;
        }

        len = GetFileSize_S(filename, SIZE_MAX);
        if (len == 0)
        {
            break;
        }

        buffer = AllocBuffer(len);
        if (buffer)
        {
            if (0 != ReadLoud(filename, buffer, len))
            {
                free(buffer);
                buffer = NULL;
                break;
            }
        }

        if (size)
        {
            *size = len;
        }
    } while (0);

    return buffer;
}

int ReadBufferFromFile(const char* filename, void* buffer, size_t size)
{
    int result = 0;
    FILE* file = NULL;
    do
    {
        size_t bytes_read = 0;
        size_t file_size = 0;
        file = fopen(filename, "rb");
        if (!file)
        {
            result = -1;
            break;
        }
        fseek(file, 0, SEEK_END);
        file_size = ftell(file);
        fseek(file, 0, SEEK_SET);
        if ((size_t)file_size != size)
        {
            result = -1;
            break;
        }

        if (buffer && (0 != size))
        {
            bytes_read = fread(buffer, 1, size, file);
            if (bytes_read != size)
            {
                result = -1;
                break;
            }
        }
    } while (0);

    if (file)
    {
        fclose(file);
    }

    return result;
}

int WriteBufferToFile(const void* buffer, size_t size, const char* filename)
{
    int result = 0;
    FILE* file = NULL;

    do
    {
        size_t bytes_written = 0;

        file = fopen(filename, "wb");
        if (!file)
        {
            result = -1;
            break;
        }
        bytes_written = fwrite(buffer, 1, size, file);
        if (bytes_written != size)
        {
            result = -1;
            break;
        }
    } while (0);

    if (file)
    {
        fclose(file);
    }

    return result;
}

int ReadLoud(char const* filename, void* buf, size_t size)
{
    int result;

    if (!buf || 0 == size)
    {
        return -1;
    }

    if (!FileExists(filename))
    {
        return -1;
    }
    if (size != GetFileSize(filename))
    {
        return -1;
    }

    result = ReadBufferFromFile(filename, buf, size);
    if (0 != result)
    {
        return result;
    }

    return result;
}

int WriteLoud(void* buf, size_t size, char const* filename)
{
    int result = -1;

    if (!buf || 0 == size)
    {
        return -1;
    }

    result = WriteBufferToFile(buf, size, filename);

    if (0 != result)
    {
        return result;
    }

    return result;
}

int AppendBufferToFile(const void* buffer, size_t size, const char* filename)
{
    int result = 0;
    FILE* file = NULL;

    do
    {
        size_t bytes_written = 0;
        file = fopen(filename, "ab+");
        if (!file)
        {
            result = -1;
            break;
        }
        bytes_written = fwrite(buffer, 1, size, file);
        if (bytes_written != size)
        {
            result = -1;
            break;
        }
    } while (0);

    if (file)
    {
        fclose(file);
    }

    return result;
}

int AppendLoud(void* buf, size_t size, char const* filename)
{
    int result = -1;

    if (!buf || 0 == size)
    {
        return -1;
    }

    result = AppendBufferToFile(buf, size, filename);
    if (0 != result)
    {
        return result;
    }

    return result;
}
