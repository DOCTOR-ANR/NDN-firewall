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

#include <ndn-cxx/interest.hpp>

#include <memory>
#include <set>

#include "network/face.h"

class PitEntry {
private:
    static const ndn::time::milliseconds RETRANSMISSION_TIME;

    std::set<std::weak_ptr<Face>, std::owner_less<std::weak_ptr<Face>>> _faces;
    //std::set<uint32_t > _nonces;
    ndn::time::steady_clock::time_point _keep_until;
    ndn::time::steady_clock::time_point _last_update;

public:
    PitEntry(const ndn::Interest &interest, const std::shared_ptr<Face> &face);

    ~PitEntry() = default;

    const std::set<std::shared_ptr<Face>> getAndResetFaces();

    bool addFace(const ndn::Interest &interest, const std::shared_ptr<Face> &face);

    bool isValid() const;

    std::string toJSON();
};