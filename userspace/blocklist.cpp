#include <map>
#include <stdio.h>
#include <cstdint>
#include <dirent.h>  
#include <unistd.h>
#include <string.h>
#include <iostream>   
#include "blocklist.h"
#include <arpa/inet.h>
#include <netinet/in.h>
using namespace std;

#define BLOCKED_IP_FILE "/ip_blocklist/blocked_ip.txt"


string get_blocked_ip_dir(){
    char blocked_ip_dir[1024];
    getcwd(blocked_ip_dir, 1024);
    return string(blocked_ip_dir)+BLOCKED_IP_FILE;
}


map<uint32_t, uint8_t> get_ip_blocklist(){
    string dir = get_blocked_ip_dir();
    FILE *file = fopen(dir.c_str(), "r");
    uint8_t map_index=1;
    map<uint32_t, uint8_t> blocklist_map;

    if (file == NULL) {
        printf("Error!\n");
        return blocklist_map;
    }
    char line[INET_ADDRSTRLEN];

	while (fgets(line, sizeof(line), file)) {

        line[strcspn(line, "\r\n")] = '\0';

        if (line[0] == '\0')
            continue;
        
        struct in_addr ip_addr;

        if (inet_pton(AF_INET, line, &ip_addr) != 1) {
            fprintf(stderr, "Invalid IP: %s\n", line);
            continue;
        }

        blocklist_map[ip_addr.s_addr] = map_index;
    }
	fclose(file);
    for (auto it : blocklist_map){
        char str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(it.first), str, INET_ADDRSTRLEN);
    }
    
    return blocklist_map;
}

