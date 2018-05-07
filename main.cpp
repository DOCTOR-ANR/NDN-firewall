/*    
Copyright (C) 2017-2018  Daishi KONDO

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

#include <cstdio>
#include <cctype>
#include <ndn-cxx/common.hpp>
#include "ndn-firewall.h"
#include "log/logger.h"

bool checkUnsignedInt(char *p) {
    size_t len = strlen(p);
    int result = 1;
    for (int i = 0; i < len && result; i++) {
        result = isdigit(p[i]);
    }
    return result != 0;
}

static bool stop = false;
static boost::asio::io_service ios;

static void signal_handler(int signum) {
    ios.stop();
    stop = true;
}

int main(int argc, char *argv[]) {
    logger::setFilename("log.txt");
    logger::isTee(true);
    logger::setMinimalLogLevel(logger::INFO);

    boost::asio::io_service::work work(ios);

    // default parameters
    std::string mode = "accept";
    size_t totalItemsInWhitelist = 1000000;
    size_t totalItemsInBlacklist = 1000000;
    uint16_t localPort = 6361;
    uint16_t localPortForCommand = 6362;
    std::string remoteAddress = "127.0.0.1";
    uint16_t remotePort = 6363;

    bool breakCheck = false;

    for (uint8_t i = 1; i < argc; i += 2) {
        if (!strcmp(argv[i], "-h")) {
            breakCheck = true;
            break;
        }
        if ((i + 1) == argc) {
            std::cout << "invalid option: " << argv[i] << std::endl;
            breakCheck = true;
            break;
        }
        if (!strcmp(argv[i], "-m")) {
            if (!strcmp(argv[i + 1], "accept") || !strcmp(argv[i + 1], "drop")) {
                mode = std::string(argv[i + 1]);
            } else {
                std::cout << "invalid option: " << argv[i] << " " << argv[i + 1] << std::endl;
                breakCheck = true;
                break;
            }
        } else if (!strcmp(argv[i], "-w")) {
            if (checkUnsignedInt(argv[i + 1])) {
                totalItemsInWhitelist = (size_t) atoi(argv[i + 1]);
            } else {
                std::cout << "invalid option: " << argv[i] << " " << argv[i + 1] << std::endl;
                breakCheck = true;
                break;
            }
        } else if (!strcmp(argv[i], "-b")) {
            if (checkUnsignedInt(argv[i + 1])) {
                totalItemsInBlacklist = (size_t) atoi(argv[i + 1]);
            } else {
                std::cout << "invalid option: " << argv[i] << " " << argv[i + 1] << std::endl;
                breakCheck = true;
                break;
            }
        } else if (!strcmp(argv[i], "-lp")) {
            if (checkUnsignedInt(argv[i + 1])) {
                localPort = (uint16_t) atoi(argv[i + 1]);
            } else {
                std::cout << "invalid option: " << argv[i] << " " << argv[i + 1] << std::endl;
                breakCheck = true;
                break;
            }
        } else if (!strcmp(argv[i], "-lpc")) {
            if (checkUnsignedInt(argv[i + 1])) {
                localPortForCommand = (uint16_t) atoi(argv[i + 1]);
            } else {
                std::cout << "invalid option: " << argv[i] << " " << argv[i + 1] << std::endl;
                breakCheck = true;
                break;
            }
        } else if (!strcmp(argv[i], "-ra")) {
            remoteAddress = std::string(argv[i + 1]);
            boost::system::error_code ec;
            boost::asio::ip::address::from_string(remoteAddress, ec);
            if (ec) {
                std::cout << "invalid option: " << argv[i] << " " << argv[i + 1] << std::endl;
                breakCheck = true;
                break;
            }
        } else if (!strcmp(argv[i], "-rp")) {
            if (checkUnsignedInt(argv[i + 1])) {
                remotePort = (uint16_t) atoi(argv[i + 1]);
            } else {
                std::cout << "invalid option: " << argv[i] << " " << argv[i + 1] << std::endl;
                breakCheck = true;
                break;
            }
        } else {
            std::cout << "invalid option: " << argv[i] << " " << argv[i + 1] << std::endl;
            breakCheck = true;
            break;
        }
    }
    if (breakCheck) {
        std::cout << "version: 0.1.0\n"
                  << "usage: " << argv[0] << " [options...]\n"
                  << " -m\tmode ([-m accept] or [-m drop])\t\t\t# default = accept\n"
                  << " -w\t# of items in whitelist (e.g., [-w 1000000])\t# default = 1000000\n"
                  << " -b\t# of items in blacklist (e.g., [-b 1000000])\t# default = 1000000\n"
                  << " -lp\tlocal port # (e.g., [-lp 6361])\t\t\t# default = 6361\n"
                  << " -lpc\tlocal port # for command (e.g., [-lpc 6362])\t# default = 6362\n"
                  << " -ra\tremote address (e.g., [-ra 127.0.0.1])\t\t# default = 127.0.0.1\n"
                  << " -rp\tremote port # (e.g., [-rp 6363])\t\t# default = 6363\n"
                  << " -h\thelp"
                  << std::endl;
        return 1;
    }

    cuckooFilterForNdnFirewall cuckooFilterForWhitelist(totalItemsInWhitelist);
    cuckooFilterForNdnFirewall cuckooFilterForBlacklist(totalItemsInBlacklist);

    NdnFirewall ndnFirewall(ios, mode, totalItemsInWhitelist, totalItemsInBlacklist, cuckooFilterForWhitelist,
                            cuckooFilterForBlacklist, localPort, localPortForCommand, remoteAddress, remotePort);
    ndnFirewall.start();

    signal(SIGINT, signal_handler);

    do {
        ios.run();
    } while (!stop);

    return 0;
}