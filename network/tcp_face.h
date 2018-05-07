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

#include "face.h"

#include <boost/asio.hpp>

#include <iostream>
#include <string>
#include <deque>
#include <vector>


class TcpFace : public Face, public std::enable_shared_from_this<TcpFace> {
public:
    static const size_t BUFFER_SIZE = 1 << 14; // 8192

private:
    bool _skip_connect;

    boost::asio::ip::tcp::endpoint _endpoint;
    boost::asio::ip::tcp::socket _socket;
    boost::asio::strand _strand;
    char _buffer[BUFFER_SIZE];
    std::string _stream;
    bool _queue_in_use = false;
    std::deque<std::string> _queue;

    boost::asio::deadline_timer _timer;

public:
    // use these when creating a face yourself
    TcpFace(boost::asio::io_service &ios, std::string host, uint16_t port);

    TcpFace(boost::asio::io_service &ios, const boost::asio::ip::tcp::endpoint &endpoint);

    // specific constructor for MasterFace, not recommended to use it yourself
    explicit TcpFace(boost::asio::ip::tcp::socket &&socket);

    ~TcpFace() override = default;

    std::string getUnderlyingProtocol() const override;

    std::string getUnderlyingEndpoint() const override;

    void open(const InterestCallback &interest_callback, const DataCallback &data_callback, const ErrorCallback &error_callback) override;

    void close() override;

    void send(const std::string &message) override;

    void send(const ndn::Interest &interest) override;

    void send(const ndn::Data &data) override;

private:
    void connect();

    void connectHandler(const boost::system::error_code &err);

    void reconnect(size_t remaining_attempt);

    void reconnectHandler(const boost::system::error_code &err, size_t remaining_attempt);

    void read();

    void readHandler(const boost::system::error_code &err, size_t bytes_transferred);

    void sendImpl(const std::string &message);

    void write();

    void writeHandler(const boost::system::error_code &err, size_t bytesTransferred);

    void timerHandler(const boost::system::error_code &err);
};