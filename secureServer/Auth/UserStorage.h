//
// Created by seed on 12/27/23.
//

#ifndef SECURITYPROJECT_USERSTORAGE_H
#define SECURITYPROJECT_USERSTORAGE_H

#include "cryptopp/secblock.h"
#include <string>
#include <cryptopp/hex.h>

struct User {
    std::string username;
    CryptoPP::SecByteBlock hashedPassword = CryptoPP::SecByteBlock(32);
    CryptoPP::SecByteBlock salt = CryptoPP::SecByteBlock(16);
};

struct HardcodedUserValue {
    std::string username;
    std::string hashedPassword;
    std::string salt;

public:
    User getUser() const {
        User user;

        user.username = username;

        CryptoPP::StringSource(hashedPassword, true,
                               new CryptoPP::HexDecoder(
                                       new CryptoPP::ArraySink(user.hashedPassword, user.hashedPassword.size())
                               )
        );

        CryptoPP::StringSource(salt, true,
                               new CryptoPP::HexDecoder(
                                       new CryptoPP::ArraySink(user.salt, user.salt.size())
                               )
        );

        return user;
    }
};

class UserStorage {
    static const HardcodedUserValue HardcodedUserValues[];

    std::vector<User> Users;

public:

    UserStorage()
    {
        Users.reserve(1);
        for (int i = 0; i < 1; ++i) {
            Users.push_back(HardcodedUserValues[i].getUser());
        }
    }

    void PrintUsers();
};


#endif //SECURITYPROJECT_USERSTORAGE_H
