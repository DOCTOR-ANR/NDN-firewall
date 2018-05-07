/*    
Copyright (C) 2017-2018  Xavier MARCHAL

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <iostream>
#include <fstream>
#include <sstream>
#include <mutex>
#include <vector>

namespace logger {
    enum Level {
        INFO,
        WARNING,
        ERROR,
    };

    namespace {
        std::mutex mutex;
        std::ofstream file;
        bool is_tee = false;
        Level level = INFO;
    }

    void setFilename(const std::string &filename);

    void isTee(bool state);

    void setMinimalLogLevel(Level level);

    void log(Level level, const std::string &message);
};