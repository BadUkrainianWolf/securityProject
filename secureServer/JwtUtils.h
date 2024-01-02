//
// Created by seed on 12/30/23.
//

#ifndef SECURITYPROJECT_JWTUTILS_H
#define SECURITYPROJECT_JWTUTILS_H

#include <iostream>

std::string GenerateJwt(const std::string& username);

bool ValidateJwt(const std::string& jwt);


#endif //SECURITYPROJECT_JWTUTILS_H
