#pragma once
#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>

std::string getCurrentTimestamp(uint add = 0)
{
    auto now_in_time_t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now() + std::chrono::hours(24 * add));
    std::stringstream ss;
    ss << std::put_time(localtime(&now_in_time_t), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}