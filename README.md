#NDN Firewall (ndnfirewall)
##Overview
**ndnfirewall** is a firewall for [Named Data Networking (NDN)](https://named-data.net/), which is completely decoupled from [NDN Forwarding Daemon (NFD)](http://named-data.net/doc/NFD/current/).
Currently, the firewall supports Interest packet filtering based on a name or name prefixes in the Interest with the whitelist and the blacklist.
Each of the lists installs a [cuckoo filter](https://github.com/efficient/cuckoofilter), which is a probabilistic filter such as a bloom filter.
The names and the name prefixes registered in the lists can be updated on the fly.

To perform Proof of Concept (PoC), the firewall utilizes IP network to transport NDN packets using TCP.
When a user of the firewall updates the lists, the firewall uses IP network to receive the command written by JSON format using UDP.

##Requirements
* ndn-cxx
* NFD
* Boost libraries
* cmake

##Install
Clone the repository with **--recursive** option to install submodules.  

```
$ git clone --recursive https://github.com/daishi-kondo/ndnfirewall.git
```

Build the source codes.  

```
$ cd ndnfirewall  
$ cmake . && make
```

**ndnfirewall** program should be created under the **bin** directory.

##NDN Firewall Management
The NDN firewall launch command is used once in order to activate the NDN firewall.
On the other hand, after the activation, the NDN firewall online command is available to update rules in real time.

###NDN Firewall Launch Command
The NDN firewall program is called **ndnfirewall**, and it can be run in the following way:

```
ndnfirewall [-m mode] [-w #_of_items] [-b #_of_items]
   [-lp local_port_#] [-lpc local_port_#_for_command]
   [-ra remote_address] [-rp remote_port_#] [-h help]
```

where:

* **-m** specifies the firewall default mode; accept or drop.
* **-w** configures the capacity of total items in the whitelist.
* **-b** configures the capacity of total items in the blacklist.
* **-lp** indicates the interface of the firewall (the local port number), which should be used by a consumers or NFD in order to connect to the firewall.
* **-lpc** indicates the interface of the firewall (the local port number), which should be used to insert the NDN firewall online command.
* **-ra** indicates the interface of the remote NFD (the remote IP address), which should be used by the NDN firewall in order to connect to the remote NFD.
* **-rp** indicates the interface of the remote NFD (the remote port number), which should be used by the NDN firewall in order to connect to the remote NFD.
* **-h** explains the NDN firewall usage.

As for the firewall mode, it can be changed in real time using an NDN firewall online command.
As for the other parameters, they cannot be changed after being run.

Here is the NDN firewall usage displayed by **-h**.

```
$ ./bin/ndnfirewall -h
version: 0.1.0
usage: ./bin/ndnfirewall [options...]
 -m		mode ([-m accept] or [-m drop])					# default = accept
 -w		# of items in whitelist (e.g., [-w 1000000])	# default = 1000000
 -b		# of items in blacklist (e.g., [-b 1000000])	# default = 1000000
 -lp	local port # (e.g., [-lp 6361])					# default = 6361
 -lpc	local port # for command (e.g., [-lpc 6362])	# default = 6362
 -ra	remote address (e.g., [-ra 127.0.0.1])			# default = 127.0.0.1
 -rp	remote port # (e.g., [-rp 6363])				# default = 6363
 -h		help
```

###NDN Firewall Online Command
The NDN firewall online command is written in JSON format. 
Here is one simplified example of the online command.

```
{
 "get": {
     "mode": [],
     "rules": ["white", "black"]
 },
 "post": {
     "mode": ["accept", "drop"],
     "append-accept": ["/example1", "/example2"],
     "append-drop": ["/example3", "/example4"],
     "delete-accept": ["/example1", "/example2"],
     "delete-drop": ["/example3", "/example4"]
 }
}
```

The online command has roughly two kinds of name/value pairs whose names are **get** and **post**.
The value of **get** is one object which can support two kinds of pairs whose names are **mode** and **rules**.
To get the current mode, the value of **mode** has to be an empty array, and then an NDN firewall returns either of a mode which basically accepts all packets or a mode which basically drops all packets.
The value of **rules** has to be an array including **white** or **black**, and after receiving this pair, the NDN firewall returns the rules which have been already in the whitelist or the blacklist.

The value of **post** is also one object which can support five kinds of pairs whose names are **mode**, **append-accept**, **append-drop**, **delete-accept**, and **delete-drop**.
The value of **mode** for **post** has to be an array including **accept** or **drop**, and after receiving the pair, the NDN firewall changes the current mode to the specified one.
Each value of **append-accept**, **append-drop**, **delete-accept**, and **delete-drop** also has to be an array including name prefixes, and after receiving each of the pairs, the NDN firewall appends or deletes rules which accepts or drops Interests based on name prefixes in the whitelist or the blacklist.
If the online command is syntactically wrong, the NDN firewall rejects it.

##Contributing
Contributions via GitHub pull requests are welcome!!