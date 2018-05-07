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

#include "master_face.h"

#include <boost/asio.hpp>

#include <unordered_set>

#include "tcp_face.h"

class TcpMasterFace : public MasterFace, public std::enable_shared_from_this<TcpMasterFace> {
private:
    uint16_t _port;
    boost::asio::ip::tcp::socket _socket;
    boost::asio::ip::tcp::acceptor _acceptor;
    std::unordered_set<std::shared_ptr<Face>> _faces;

public:
    TcpMasterFace(boost::asio::io_service &ios, size_t max_connection, uint16_t port);

    ~TcpMasterFace() override = default;

    std::string getUnderlyingProtocol() const override;

    void listen(const NotificationCallback &notification_callback, const Face::InterestCallback &interest_callback,
                const Face::DataCallback &data_callback, const ErrorCallback &error_callback) override;

    void close() override;

    void sendToAllFaces(const std::string &message) override;

    void sendToAllFaces(const ndn::Interest &interest) override;

    void sendToAllFaces(const ndn::Data &data) override;

private:
    void accept();

    void acceptHandler(const boost::system::error_code &err);

    void onFaceError(const std::shared_ptr<Face> &face);
};