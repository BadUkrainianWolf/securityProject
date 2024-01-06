#!/bin/bash

release_build_folder="cmake-build-release"
executables_folder="Executables"

server_exe="secureServer/secureServer"
client_exe="secureClient/sectrans"

if [ -f "$release_build_folder/$server_exe" ]; then
    cp "$release_build_folder/$server_exe" "$executables_folder/"
    echo "$server_exe copied successfully."
else
    echo "$release_build_folder/$server_exe file does not exist."
fi


if [ -f "$release_build_folder/$client_exe" ]; then
    cp "$release_build_folder/$client_exe" "$executables_folder/"
    echo "$client_exe copied successfully."
else
    echo "$release_build_folder/$client_exe file does not exist."
fi