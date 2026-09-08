#include <atomic>
// #include <int.h>
#include <cstdint>
#include <string>
#include <map>
using namespace std;

#ifndef BLOCKLIST

#define BLOCKLIST

string get_blocked_ip_dir();
map<uint32_t, uint8_t> get_ip_blocklist();


#endif