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

#include "ndn-firewall.h"

#include <boost/bind.hpp>
#include <algorithm>

#include "network/tcp_master_face.h"
#include "network/tcp_face.h"
#include "network/udp_master_face.h"
#include "network/udp_face.h"
#include "log/logger.h"

NdnFirewall::NdnFirewall(boost::asio::io_service &ios, std::string &mode,
                         size_t &totalItemsInWhitelist, size_t &totalItemsInBlacklist,
                         cuckooFilterForNdnFirewall &cuckooFilterForWhitelist,
                         cuckooFilterForNdnFirewall &cuckooFilterForBlacklist,
                         const uint16_t &localPort, const uint16_t &localPortForCommand,
                         const std::string &remoteAddress, const uint16_t &remotePort) :
        m_ios(ios), m_mode(mode),
        m_totalItemsInWhitelist(totalItemsInWhitelist), m_totalItemsInBlacklist(totalItemsInBlacklist),
        m_cuckooFilterForWhitelist(cuckooFilterForWhitelist), m_cuckooFilterForBlacklist(cuckooFilterForBlacklist),
        m_slashCounterForWhitelist(1, std::make_pair(0, 0)), m_slashCounterForBlacklist(1, std::make_pair(0, 0)),
        m_commandSocket(ios, {boost::asio::ip::udp::v4(), localPortForCommand}),
        m_egressFace(std::make_shared<TcpFace>(ios, remoteAddress, remotePort)),
        m_ingressMasterFace(std::make_shared<TcpMasterFace>(ios, 128, localPort)),
        m_pit(1000000) {
}

void NdnFirewall::start() {
    commandRead();
    m_egressFace->open(boost::bind(&NdnFirewall::onEgressInterest, this, _1, _2),
                       boost::bind(&NdnFirewall::onEgressData, this, _1, _2),
                       boost::bind(&NdnFirewall::onFaceError, this, _1));
    m_ingressMasterFace->listen(boost::bind(&NdnFirewall::onMasterFaceNotification, this, _1, _2),
                                boost::bind(&NdnFirewall::onIngressInterest, this, _1, _2),
                                boost::bind(&NdnFirewall::onIngressData, this, _1, _2),
                                boost::bind(&NdnFirewall::onMasterFaceError, this, _1, _2));
}

void NdnFirewall::onIngressInterest(const std::shared_ptr<Face> &face, const ndn::Interest &interest) {
    std::string uri = interest.getName().toUri();
    if (interestNameFilter(uri)) {
        if (m_pit.insert(interest, face)) {
            m_egressFace->send(interest);
        }
    } else {
        std::stringstream ss;
        ss << "the Interest name " << uri << " was dropped";
        logger::log(logger::INFO, ss.str());
    }
}

void NdnFirewall::onIngressData(const std::shared_ptr<Face> &face, const ndn::Data &data) {
//    m_egressFace->send(data);
}

void NdnFirewall::onEgressInterest(const std::shared_ptr<Face> &face, const ndn::Interest &interest) {
//    m_ingressMasterFace->sendToAllFaces(interest);
}

void NdnFirewall::onEgressData(const std::shared_ptr<Face> &face, const ndn::Data &data) {
//    m_ingressMasterFace->sendToAllFaces(data);
    auto faces = m_pit.get(data);
    for (const auto &f : faces) {
        f->send(data);
    }
}

void NdnFirewall::onMasterFaceNotification(const std::shared_ptr<MasterFace> &master_face,
                                           const std::shared_ptr<Face> &face) {
    std::stringstream ss;
    ss << "new " << "face with ID = " << face->getFaceId() << " from master face with ID = "
       << master_face->getMasterFaceId();
    logger::log(logger::INFO, ss.str());
}

void NdnFirewall::onMasterFaceError(const std::shared_ptr<MasterFace> &master_face, const std::shared_ptr<Face> &face) {
    std::stringstream ss;
    ss << "face with ID = " << face->getFaceId() << " from master face with ID = " << master_face->getMasterFaceId()
       << " can't process normally";
    logger::log(logger::ERROR, ss.str());
}

void NdnFirewall::onFaceError(const std::shared_ptr<Face> &face) {
    std::stringstream ss;
    ss << "face with ID = " << face->getFaceId() << " can't process normally";
    logger::log(logger::ERROR, ss.str());
    if (face == m_egressFace) {
        exit(-1);
    }
}

bool NdnFirewall::interestNameFilter(std::string uri) {
    if (m_slashCounterForWhitelist.back().first == 0 &&
        m_slashCounterForBlacklist.back().first == 0) { // rules do not exist in both lists
        if (m_mode == "accept") {
            return true;
        } else if (m_mode == "drop") {
            return false;
        }
    } else {
        uint16_t slashCounter = 0;
        std::vector<uint16_t> lengthOfEachNamePrefix;
        uint16_t characterCounter = 0;
        bool breakCheck = false;

        // linear search for slashes
        for (const auto &character : uri) {
            if (character == '/') {
                slashCounter++;
                if (slashCounter != 1) {
                    lengthOfEachNamePrefix.push_back(characterCounter);
                    if (slashCounter ==
                        std::max(m_slashCounterForWhitelist.back().first, m_slashCounterForBlacklist.back().first)) {
                        breakCheck = true;
                        break;
                    }
                }
            }
            characterCounter++;
        }
        // full name also can be name prefix depending on std::max(..., ...)
        if (!breakCheck) {
            lengthOfEachNamePrefix.push_back(characterCounter);
        }

        bool whitelistCheck = false;
        bool blacklistCheck = false;

        std::vector<uint16_t>::reverse_iterator it = lengthOfEachNamePrefix.rbegin();
        while (it != lengthOfEachNamePrefix.rend()) {
            std::string namePrefix = uri.substr(0, *it);
            size_t hash = std::hash<std::string>()(namePrefix);
            if (m_slashCounterForWhitelist.back().first >= slashCounter &&
                m_cuckooFilterForWhitelist.Contain(hash) == cuckoofilter::Ok) {
                whitelistCheck = true;
                break;
            } else if (m_slashCounterForBlacklist.back().first >= slashCounter &&
                       m_cuckooFilterForBlacklist.Contain(hash) == cuckoofilter::Ok) {
                blacklistCheck = true;
                break;
            }
            slashCounter--;
            it++;
        }

        if (whitelistCheck) {
            return true;    // e.g., accept /a
        } else if (blacklistCheck) {
            return false;   // e.g., drop /a
        } else {
            if (m_mode == "accept") {   // accept Interest if the Interest is listed in neither whitelist nor blacklist
                return true;
            } else if (m_mode == "drop") {// drop Interest if the Interest is listed in neither whitelist nor blacklist
                return false;
            }
        }
    }
}

void NdnFirewall::commandRead() {
    m_commandSocket.async_receive_from(boost::asio::buffer(m_commandBuffer, 65536), m_remoteEndpoint,
                                       boost::bind(&NdnFirewall::commandReadHandler, this, _1, _2));
}

void NdnFirewall::commandReadHandler(const boost::system::error_code &err, size_t bytes_transferred) {
    if (!err) {
        rapidjson::Document document;
        document.Parse(m_commandBuffer, bytes_transferred);
        if (!document.HasParseError()) {
            bool syntaxCheck = true;
            for (const auto &pair : document.GetObject()) {
                std::string memberName = pair.name.GetString();
                if (memberName != "get" && memberName != "post") {
                    std::string response = R"({"status":"syntax error", "reason":"only 'get' and 'post' are supported"})";
                    m_commandSocket.send_to(boost::asio::buffer(response), m_remoteEndpoint);
                    syntaxCheck = false;
                    break;
                }
            }
            if (syntaxCheck) {
                for (const auto &pair : document.GetObject()) {
                    std::string memberName = pair.name.GetString();
                    if (memberName == "get") {
                        commandGet(document);
                    } else if (memberName == "post") {
                        commandPost(document);
                    }
                }
            }
        } else {
            std::string response = R"({"status":"syntax error", "reason":"error while parsing"})";
            m_commandSocket.send_to(boost::asio::buffer(response), m_remoteEndpoint);
        }
        commandRead();
    } else {
        std::cerr << "command socket error!" << std::endl;
    }
}

void NdnFirewall::commandGet(const rapidjson::Document &document) {
    if (document["get"].IsObject()) {
        bool syntaxCheck = true;
        for (const auto &pair : document["get"].GetObject()) {
            std::string memberName = pair.name.GetString();
            if (memberName != "mode" && memberName != "rules") {
                std::string response = R"({"status":"syntax error", "reason":"only 'mode' or 'rules' are supported in 'get' method"})";
                m_commandSocket.send_to(boost::asio::buffer(response), m_remoteEndpoint);
                syntaxCheck = false;
                break;
            }
            if (!document["get"][memberName.c_str()].IsArray()) {
                std::string response = R"({"status":"syntax error", "reason":"value has to be array"})";
                m_commandSocket.send_to(boost::asio::buffer(response), m_remoteEndpoint);
                syntaxCheck = false;
                break;
            }
            for (const auto &value : document["get"][memberName.c_str()].GetArray()) {
                if (memberName == "mode") {
                    std::string response = R"({"status":"syntax error", "reason":"'mode' array has to be empty"})";
                    m_commandSocket.send_to(boost::asio::buffer(response), m_remoteEndpoint);
                    syntaxCheck = false;
                    break;
                } else if (memberName == "rules" && (value != "white" && value != "black")) {
                    std::string response = R"({"status":"syntax error", "reason":"value in 'rules' array has to be 'white' or 'black'"})";
                    m_commandSocket.send_to(boost::asio::buffer(response), m_remoteEndpoint);
                    syntaxCheck = false;
                    break;
                }
            }
            if (!syntaxCheck) {
                break;
            }
        }
        if (syntaxCheck) {
            for (const auto &pair : document["get"].GetObject()) {
                std::string memberName = pair.name.GetString();
                if (memberName == "mode") {
                    std::string response = R"({"mode":")" + m_mode + R"("})";
                    m_commandSocket.send_to(boost::asio::buffer(response), m_remoteEndpoint);
                } else if (memberName == "rules") {
                    for (const auto &value : document["get"]["rules"].GetArray()) {
                        if (value == "white") {
                            getRules(m_whitelist, value.GetString());
                        } else if (value == "black") {
                            getRules(m_blacklist, value.GetString());
                        }
                    }
                }
            }
        }
    } else {
        std::string response = R"({"status":"syntax error", "reason":"value has to be object"})";
        m_commandSocket.send_to(boost::asio::buffer(response), m_remoteEndpoint);
    }
}

void NdnFirewall::getRules(const std::set<std::string> &list, const std::string &value) {
    std::string response("[");
    for (const auto &namePrefix : list) {
        response = response + "\"" + namePrefix + "\", ";
    }
    if (response != "[") {   // rules do not exist in whitelist or blacklist
        response.pop_back();    // ' '
        response.pop_back();    // ','
    }
    response.push_back(']');
    if (value == "white") {
        response = R"({"whitelist":)" + response + R"(})";
    } else if (value == "black") {
        response = R"({"blacklist":)" + response + R"(})";
    }
    m_commandSocket.send_to(boost::asio::buffer(response), m_remoteEndpoint);
}

void NdnFirewall::commandPost(const rapidjson::Document &document) {
    if (document["post"].IsObject()) {
        bool syntaxCheck = true;
        for (const auto &pair : document["post"].GetObject()) {
            std::string memberName = pair.name.GetString();
            if (memberName != "mode" && memberName != "append-accept" && memberName != "append-drop" &&
                memberName != "delete-accept" && memberName != "delete-drop") {
                std::string response = R"({"status":"syntax error", "reason":"only 'mode', 'append-accept', 'append-drop', 'delete-accept', or 'delete-drop' are supported in 'post' method"})";
                m_commandSocket.send_to(boost::asio::buffer(response), m_remoteEndpoint);
                syntaxCheck = false;
                break;
            }
            if (!document["post"][memberName.c_str()].IsArray()) {
                std::string response = R"({"status":"syntax error", "reason":"value has to be array"})";
                m_commandSocket.send_to(boost::asio::buffer(response), m_remoteEndpoint);
                syntaxCheck = false;
                break;
            }
            for (const auto &value : document["post"][memberName.c_str()].GetArray()) {
                if (memberName == "mode" && (value != "accept" && value != "drop")) {
                    std::string response = R"({"status":"syntax error", "reason":"value in 'mode' array has to be 'accept' or 'drop'"})";
                    m_commandSocket.send_to(boost::asio::buffer(response), m_remoteEndpoint);
                    syntaxCheck = false;
                    break;
                } else if (!value.IsString()) {
                    std::string response = R"({"status":"syntax error", "reason":"value in array has to be string"})";
                    m_commandSocket.send_to(boost::asio::buffer(response), m_remoteEndpoint);
                    syntaxCheck = false;
                    break;
                }
            }
            if (!syntaxCheck) {
                break;
            }
        }
        if (syntaxCheck) {
            for (const auto &pair : document["post"].GetObject()) {
                std::string memberName = pair.name.GetString();
                if (memberName == "mode") {
                    for (const auto &mode : document["post"]["mode"].GetArray()) {
                        m_mode = mode.GetString();
                    }
                } else if (memberName == "append-accept") {
                    for (const auto &namePrefix : document["post"]["append-accept"].GetArray()) {
                        std::string allowedNamePrefix = namePrefix.GetString();
                        if (m_blacklist.find(allowedNamePrefix) != m_blacklist.end()) {
                            std::string response = allowedNamePrefix;
                            response = R"({"status":"warning", "reason":"')" + response +
                                       R"(' has been already appended in blacklist, so that it cannot be appended in whitelist"})";
                            m_commandSocket.send_to(boost::asio::buffer(response), m_remoteEndpoint);
                        } else if (m_whitelist.find(allowedNamePrefix) == m_whitelist.end()) {
                            if (m_totalItemsInWhitelist >= (m_whitelist.size() + 1)) {
                                if (!appendRules(m_whitelist, allowedNamePrefix, m_cuckooFilterForWhitelist,
                                                 m_slashCounterForWhitelist)) {
                                    std::string response = R"({"status":"warning", "reason":"cuckoo filter for whitelist does not have enough space"})";
                                    m_commandSocket.send_to(boost::asio::buffer(response), m_remoteEndpoint);
                                }
                            } else {
                                std::string response = R"({"status":"warning", "reason":"whitelist has been already full"})";
                                m_commandSocket.send_to(boost::asio::buffer(response), m_remoteEndpoint);
                            }
                        } else {
                            std::string response = allowedNamePrefix;
                            response = R"({"status":"warning", "reason":"')" + response +
                                       R"(' has been already appended in whitelist"})";
                            m_commandSocket.send_to(boost::asio::buffer(response), m_remoteEndpoint);
                        }
                    }
                } else if (memberName == "append-drop") {
                    for (const auto &namePrefix : document["post"]["append-drop"].GetArray()) {
                        std::string deniedNamePrefix = namePrefix.GetString();
                        if (m_whitelist.find(deniedNamePrefix) != m_whitelist.end()) {
                            std::string response = deniedNamePrefix;
                            response = R"({"status":"warning", "reason":"')" + response +
                                       R"(' has been already appended in whitelist, so that it cannot be appended in blacklist"})";
                            m_commandSocket.send_to(boost::asio::buffer(response), m_remoteEndpoint);
                        } else if (m_blacklist.find(deniedNamePrefix) == m_blacklist.end()) {
                            if (m_totalItemsInBlacklist >= (m_blacklist.size() + 1)) {
                                if (!appendRules(m_blacklist, deniedNamePrefix, m_cuckooFilterForBlacklist,
                                                 m_slashCounterForBlacklist)) {
                                    std::string response = R"({"status":"warning", "reason":"cuckoo filter for blacklist does not have enough space"})";
                                    m_commandSocket.send_to(boost::asio::buffer(response), m_remoteEndpoint);
                                }
                            } else {
                                std::string response = R"({"status":"warning", "reason":"blacklist has been already full"})";
                                m_commandSocket.send_to(boost::asio::buffer(response), m_remoteEndpoint);
                            }
                        } else {
                            std::string response = deniedNamePrefix;
                            response = R"({"status":"warning", "reason":"')" + response +
                                       R"(' has been already appended in blacklist"})";
                            m_commandSocket.send_to(boost::asio::buffer(response), m_remoteEndpoint);
                        }
                    }
                } else if (memberName == "delete-accept") {
                    for (const auto &namePrefix : document["post"]["delete-accept"].GetArray()) {
                        std::string allowedNamePrefix = namePrefix.GetString();
                        auto deletionCheck = m_whitelist.erase(allowedNamePrefix);
                        if (deletionCheck == 0) {
                            std::string response = allowedNamePrefix;
                            response = R"({"status":"warning", "reason":"')" + response +
                                       R"(' does not exist in whitelist"})";
                            m_commandSocket.send_to(boost::asio::buffer(response), m_remoteEndpoint);
                        } else {
                            deleteRules(allowedNamePrefix, m_cuckooFilterForWhitelist, m_slashCounterForWhitelist);
                        }
                    }
                } else if (memberName == "delete-drop") {
                    for (const auto &namePrefix : document["post"]["delete-drop"].GetArray()) {
                        std::string deniedNamePrefix = namePrefix.GetString();
                        auto deletionCheck = m_blacklist.erase(deniedNamePrefix);
                        if (deletionCheck == 0) {
                            std::string response = deniedNamePrefix;
                            response = R"({"status":"warning", "reason":"')" + response +
                                       R"(' does not exist in blacklist"})";
                            m_commandSocket.send_to(boost::asio::buffer(response), m_remoteEndpoint);
                        } else {
                            deleteRules(deniedNamePrefix, m_cuckooFilterForBlacklist, m_slashCounterForBlacklist);
                        }
                    }
                }
            }
        }
    } else {
        std::string response = R"({"status":"syntax error", "reason":"value has to be object"})";
        m_commandSocket.send_to(boost::asio::buffer(response), m_remoteEndpoint);
    }
}

bool NdnFirewall::appendRules(std::set<std::string> &list, const std::string &namePrefix,
                              cuckooFilterForNdnFirewall &cuckooFilter,
                              std::vector<std::pair<uint16_t, uint16_t>> &slashCounter) {
    size_t hash = std::hash<std::string>()(namePrefix);
    if (cuckooFilter.Add(hash) != cuckoofilter::Ok) {
        return false;
    } else {
        list.insert(namePrefix);
        if (slashCounter.back().first < (std::count(namePrefix.begin(), namePrefix.end(), '/') + 1)) {
            slashCounter.emplace_back(
                    static_cast<uint16_t>(std::count(namePrefix.begin(), namePrefix.end(), '/') + 1), 1);
        } else {
            bool counterCheck = false;
            for (auto &eachCounter : slashCounter) {
                if (eachCounter.first == (std::count(namePrefix.begin(), namePrefix.end(), '/') + 1)) {
                    eachCounter.second++;
                    counterCheck = true;
                    break;
                }
            }
            if (!counterCheck) {
                slashCounter.emplace_back(
                        static_cast<uint16_t>(std::count(namePrefix.begin(), namePrefix.end(), '/') + 1), 1);
                sort(slashCounter.begin(), slashCounter.end());
            }
        }
        return true;
    }
}

// note that deleteRules function does not erase rules from m_whitelist or m_blacklist, which means erase functions of them have to be called
void NdnFirewall::deleteRules(const std::string &namePrefix, cuckooFilterForNdnFirewall &cuckooFilter,
                              std::vector<std::pair<uint16_t, uint16_t>> &slashCounter) {
    uint16_t i = 0;
    for (auto &eachCounter : slashCounter) {
        if (eachCounter.first == (std::count(namePrefix.begin(), namePrefix.end(), '/') + 1)) {
            eachCounter.second--;
            if (eachCounter.second == 0) {
                slashCounter.erase(slashCounter.begin() + i);
            }
            break;
        }
        i++;
    }
    size_t hash = std::hash<std::string>()(namePrefix);
    cuckooFilter.Delete(hash);
}