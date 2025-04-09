/*
 * Copyright (c) 2010 SURFnet bv
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 UUID.cpp

 UUID generation helper functions
 *****************************************************************************/

#include "config.h"
#include "UUID.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdexcept>
#include <fcntl.h>
#include <unistd.h>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <iomanip>

class SecureRandom {
public:
    static std::string generate(size_t length = 16) {
        return generate_unix(length);
    }

    static std::string bytes_to_hex(const std::string& input) {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        
        for (unsigned char c : input) {
            oss << std::setw(2) << static_cast<int>(c);
        }
        
        return oss.str();
    }
	
private:
    static std::string generate_unix(size_t length) {
        std::string buffer(length, '\0');
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd == -1) {
            throw std::runtime_error("Failed to open /dev/urandom: "
                + std::to_string(errno));
        }

        ssize_t bytes_read = read(fd, &buffer[0], length);
        close(fd);

        if (bytes_read != static_cast<ssize_t>(length)) {
            throw std::runtime_error("Failed to read from /dev/urandom: "
                + std::to_string(bytes_read) + "/" 
                + std::to_string(length) + " bytes read");
        }

        return buffer;
    }
};

class DateTimeFormatter {
public:
    static std::string getCurrentTimeString() {
        using namespace std::chrono;
        
        // 获取当前时间点
        auto now = system_clock::now();
        
        // 转换为日历时间
        time_t now_c = system_clock::to_time_t(now);
        
        // 转换为本地时间结构
        struct tm time_info;
        
        localtime_r(&now_c, &time_info);
        
        // 计算毫秒部分
        auto since_epoch = now.time_since_epoch();
        auto millis = duration_cast<milliseconds>(since_epoch).count() % 1000;
        
        // 格式化输出
        std::ostringstream oss;
        oss << std::setfill('0')
            << std::setw(4) << time_info.tm_year + 1900  // 年份（4位）
            << std::setw(2) << time_info.tm_mon + 1      // 月份（补零）
            << std::setw(2) << time_info.tm_mday         // 日期（补零）
            << std::setw(2) << time_info.tm_hour         // 小时（24小时制）
            << std::setw(2) << time_info.tm_min          // 分钟
            << std::setw(2) << time_info.tm_sec          // 秒钟
            << std::setw(3) << millis;                   // 毫秒（3位）
            
        return oss.str();
    }
};

// Generate a new UUID string
std::string UUID::newUUID()
{
    return DateTimeFormatter::getCurrentTimeString() + "@" + SecureRandom::bytes_to_hex(SecureRandom::generate(7));
}
