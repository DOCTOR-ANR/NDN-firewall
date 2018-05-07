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

#pragma once

#include <ndn-cxx/interest.hpp>
#include <ndn-cxx/data.hpp>

#include <boost/asio.hpp>

#include <memory>
#include <string>
#include <queue>
#include <set>

#include "network/master_face.h"
#include "network/face.h"
#include "cuckoofilter/src/cuckoofilter.h"
#include "rapidjson/include/rapidjson/document.h"
#include "pit.h"

#define BITS_FOR_EACH_ITEM 32

// configurations about bits for each item and the number of total items depend on firewall design
// see "Cuckoo Filter: Practically Better Than Bloom" in proceedings of ACM CoNEXT 2014 by B. Fan, D. Andersen, and M. Kaminsky
using cuckooFilterForNdnFirewall = cuckoofilter::CuckooFilter<size_t, BITS_FOR_EACH_ITEM>;

class NdnFirewall {

    boost::asio::io_service &m_ios;

    std::string &m_mode;

    size_t &m_totalItemsInWhitelist;
    size_t &m_totalItemsInBlacklist;

    cuckooFilterForNdnFirewall &m_cuckooFilterForWhitelist;
    cuckooFilterForNdnFirewall &m_cuckooFilterForBlacklist;

    std::set<std::string> m_whitelist;
    std::set<std::string> m_blacklist;

    // firewall needs to extract name prefixes (initial pair of (number of slashes, counter) is (0, 0))
    // m_slashCounterForWhitelist and m_slashCounterForBlacklist have to be sorted based on the number of slashes before calling interestNameFilter function
    // note: this should be needed in the case of using cuckoo filter-based firewall
    std::vector<std::pair<uint16_t, uint16_t>> m_slashCounterForWhitelist;
    std::vector<std::pair<uint16_t, uint16_t>> m_slashCounterForBlacklist;

    boost::asio::ip::udp::socket m_commandSocket;
    char m_commandBuffer[65536];
    boost::asio::ip::udp::endpoint m_remoteEndpoint;

    std::shared_ptr<Face> m_egressFace;
    std::shared_ptr<MasterFace> m_ingressMasterFace;

    Pit m_pit;

public:
    NdnFirewall(boost::asio::io_service &ios, std::string &mode, size_t &totalItemsInWhitelist,
                size_t &totalItemsInBlacklist, cuckooFilterForNdnFirewall &cuckooFilterForWhitelist,
                cuckooFilterForNdnFirewall &cuckooFilterForBlacklist, const uint16_t &localPort,
                const uint16_t &localPortForCommand, const std::string &remoteAddress, const uint16_t &remotePort);

    ~NdnFirewall() = default;

    void start();

    void onIngressInterest(const std::shared_ptr<Face> &face, const ndn::Interest &interest);

    void onIngressData(const std::shared_ptr<Face> &face, const ndn::Data &data);

    void onEgressInterest(const std::shared_ptr<Face> &face, const ndn::Interest &interest);

    void onEgressData(const std::shared_ptr<Face> &face, const ndn::Data &data);

    void onMasterFaceNotification(const std::shared_ptr<MasterFace> &master_face, const std::shared_ptr<Face> &face);

    void onMasterFaceError(const std::shared_ptr<MasterFace> &master_face, const std::shared_ptr<Face> &face);

    void onFaceError(const std::shared_ptr<Face> &face);

    bool interestNameFilter(std::string uri);

    void commandRead();

    void commandReadHandler(const boost::system::error_code &err, size_t bytes_transferred);

    void commandGet(const rapidjson::Document &document);

    void getRules(const std::set<std::string> &list, const std::string &value);

    void commandPost(const rapidjson::Document &document);

    bool appendRules(std::set<std::string> &list, const std::string &namePrefix,
                     cuckooFilterForNdnFirewall &cuckooFilter,
                     std::vector<std::pair<uint16_t, uint16_t>> &slashCounter);

    void deleteRules(const std::string &namePrefix, cuckooFilterForNdnFirewall &cuckooFilter,
                     std::vector<std::pair<uint16_t, uint16_t>> &slashCounter);
};