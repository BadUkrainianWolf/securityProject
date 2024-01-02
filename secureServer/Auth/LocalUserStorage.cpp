//
// Created by seed on 12/27/23.
//

#include "LocalUserStorage.h"
#include "files.h"
#include <iostream>

const HardcodedUserValue LocalUserStorage::HardcodedUserValues[] = {
        {"Mariia", "72B20983046F604B30B1C9C24CDC61809CC9172C7773A7A6DF52D9F2D55F80F3", "586529ED504F6AFFDEDEA283B845DA10"}
};

void LocalUserStorage::PrintUsers()
{
    using namespace CryptoPP;

    for (auto& user : Users)
    {
        HexEncoder encoder(new FileSink(std::cout));
        encoder.Put(user.salt, user.salt.size());
        encoder.MessageEnd();
        std::cout << std::endl;


        // Print the hashed password in hexadecimal format
        std::cout << "Hashed Password: ";
        encoder.Put(user.hashedPassword, user.hashedPassword.size());
        encoder.MessageEnd();
        std::cout << std::endl;
    }
}

User LocalUserStorage::GetUserData(std::string username) {
    auto found_user = std::find_if(Users.begin(), Users.end(), [&username](const auto& user){
        return user.username == username;
    });

    if (found_user == Users.end())
        return User();

    return *found_user;
}
