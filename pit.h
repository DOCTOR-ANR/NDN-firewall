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
#include <ndn-cxx/data.hpp>

#include <memory>
#include <list>
#include <unordered_map>
#include <set>

#include "tree/named_tree.h"
#include "pit_entry.h"
#include "network/face.h"

class Pit {
private:
    static const ndn::time::milliseconds MINIMAL_INTEREST_LIFETIME;

    size_t _max_size;

    NamedTree<PitEntry> _tree;
    std::list<ndn::Name> _list;
    std::unordered_map<std::string, std::list<ndn::Name>::iterator> _list_index;

public:
    explicit Pit(size_t size);

    ~Pit() = default;

    size_t getSize() const;

    void setSize(size_t size);

    bool insert(const ndn::Interest &interest, const std::shared_ptr<Face> &face);

    std::set<std::shared_ptr<Face>> get(const ndn::Data &data);

    std::string toJSON() const;
};