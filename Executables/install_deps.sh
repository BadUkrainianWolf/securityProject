#!/bin/bash

server_lib="libserver.so"
client_lib="libclient.so"

shared_lib_folder="/usr/lib"

cp "$server_lib" "$shared_lib_folder/"
cp "$client_lib" "$shared_lib_folder/"
