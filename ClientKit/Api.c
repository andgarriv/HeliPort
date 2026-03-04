//
//  Api.c
//  ClientKit
//
//  Created by 钟先耀 on 2020/4/7.
//  Copyright © 2020 OpenIntelWireless. All rights reserved.
//

/*
 * This program and the accompanying materials are licensed and made available
 * under the terms and conditions of the The 3-Clause BSD License
 * which accompanies this distribution. The full text of the license may be found at
 * https://opensource.org/licenses/BSD-3-Clause
 */

#include "Api.h"
#include "mach/mach_port.h"
#include "pthread.h"
#include <ctype.h>

static pthread_mutex_t* api_mutex = NULL;

static size_t copy_truncated(char *dst, size_t dst_size, const char *src)
{
    if (dst_size == 0) {
        return 0;
    }

    memset(dst, 0, dst_size);
    if (!src) {
        return 0;
    }

    size_t len = strnlen(src, dst_size - 1);
    memcpy(dst, src, len);
    return len;
}


static bool is_enterprise_security(uint32_t security)
{
    switch (security) {
    case ITL80211_SECURITY_WPA_ENTERPRISE:
    case ITL80211_SECURITY_WPA_ENTERPRISE_MIXED:
    case ITL80211_SECURITY_WPA2_ENTERPRISE:
    case ITL80211_SECURITY_ENTERPRISE:
    case ITL80211_SECURITY_WPA3_ENTERPRISE:
        return true;
    default:
        return false;
    }
}

static int hex_to_nibble(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static bool decode_hex_pmk(const char *text, uint8_t pmk[PMK_KEY_LEN])
{
    char hex[PMK_KEY_LEN * 2 + 1];
    size_t hex_len = 0;

    if (!text || !pmk) {
        return false;
    }

    while (*text && isspace((unsigned char)*text)) {
        text++;
    }

    if ((text[0] == 'p' || text[0] == 'P') &&
        (text[1] == 'm' || text[1] == 'M') &&
        (text[2] == 'k' || text[2] == 'K') &&
        text[3] == ':') {
        text += 4;
    }

    memset(hex, 0, sizeof(hex));
    for (; *text != '\0'; text++) {
        if (*text == ':' || *text == '-' || isspace((unsigned char)*text)) {
            continue;
        }
        if (hex_to_nibble(*text) < 0 || hex_len >= sizeof(hex) - 1) {
            return false;
        }
        hex[hex_len++] = *text;
    }

    if (hex_len != PMK_KEY_LEN * 2) {
        return false;
    }

    for (size_t i = 0; i < PMK_KEY_LEN; i++) {
        int hi = hex_to_nibble(hex[i * 2]);
        int lo = hex_to_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            return false;
        }
        pmk[i] = (uint8_t)((hi << 4) | lo);
    }

    return true;
}

static bool load_current_bssid(uint8_t bssid[ETHER_ADDR_LEN])
{
    static const uint8_t zero_bssid[ETHER_ADDR_LEN] = {0};

    if (!bssid) {
        return false;
    }

    memset(bssid, 0, ETHER_ADDR_LEN);
    if (!get_network_bssid((char *)bssid)) {
        return false;
    }

    return memcmp(bssid, zero_bssid, ETHER_ADDR_LEN) != 0;
}

bool get_platform_info(platform_info_t *info) {
    memset(info, 0, sizeof(platform_info_t));

    struct ioctl_driver_info driver_info;
    if (ioctl_get(IOCTL_80211_DRIVER_INFO, &driver_info, sizeof(struct ioctl_driver_info)) != KERN_SUCCESS) {
        goto error;
    }

    strcpy(info->device_info_str, driver_info.bsd_name);
    strcpy(info->driver_info_str, driver_info.driver_version);
    strcat(info->driver_info_str, " ");
    strcat(info->driver_info_str, driver_info.fw_version);
    return true;

error:
    return false;
}

bool get_power_state(bool *enabled) {
    struct ioctl_power power;
    if (ioctl_get(IOCTL_80211_POWER, &power, sizeof(struct ioctl_power)) != KERN_SUCCESS) {
        goto error;
    }

    *enabled = power.enabled;

    return true;

error:
    return false;
}

bool get_80211_state(uint32_t *state) {
    struct ioctl_state state_struct;
    if (ioctl_get(IOCTL_80211_STATE, &state_struct, sizeof(struct ioctl_state)) != KERN_SUCCESS) {
        goto error;
    }

    *state = state_struct.state;

    return true;

error:
    return false;
}

bool get_network_ssid(char *ssid)
{
    struct ioctl_nw_id nwid;
    if (ioctl_get(IOCTL_80211_NW_ID, &nwid, sizeof(struct ioctl_nw_id)) != KERN_SUCCESS) {
        goto error;
    }
    
    memcpy(ssid, nwid.nwid, nwid.len);
    
    return true;
    
error:
    return false;
}

bool get_network_bssid(char *bssid)
{
    struct ioctl_nw_bssid nwbssid;
    if (ioctl_get(IOCTL_80211_NW_BSSID, &nwbssid, sizeof(struct ioctl_nw_bssid)) != KERN_SUCCESS) {
        goto error;
    }
    
    memcpy(bssid, nwbssid.bssid, ETHER_ADDR_LEN);
    
    return true;
    
error:
    return false;
}

bool get_network_list(network_info_list_t *list) {
    memset(list, 0, sizeof(network_info_list_t));

    struct ioctl_scan scan;
    struct ioctl_network_info network_info_ret;
    io_connect_t con;
    struct ioctl_sta_info sta_info;
    scan.version = IOCTL_VERSION;

    get_station_info(&sta_info);

    if (!open_adapter(&con)) {
        goto error;
    }
    int oid = IOCTL_80211_SCAN_RESULT;
    while (_nake_ioctl(con, &oid, true, &network_info_ret, sizeof(struct ioctl_network_info)) == kIOReturnSuccess) {
        if (list->count >= MAX_NETWORK_LIST_LENGTH) {
            break;
        }
        if (strlen((const char *)sta_info.ssid) > 0 && memcmp(sta_info.bssid, network_info_ret.bssid, ETHER_ADDR_LEN) == 0) {
            continue;
        }
        struct ioctl_network_info *info = &list->networks[list->count++];
        memcpy(info, &network_info_ret, sizeof(struct ioctl_network_info));
    }
    close_adapter(con);

    if (ioctl_set(IOCTL_80211_SCAN, &scan, sizeof(struct ioctl_scan)) != KERN_SUCCESS) {
        goto error;
    }
    return true;

error:
    return false;
}

bool connect_network(const char *ssid, const char *pwd) {
    if (associate_ssid(ssid, pwd) != KERN_SUCCESS) {
        goto error;
    }

    int timeout = 20;
    while (timeout-- > 0) {
        // Sleep first to wait for state to change
        sleep(1);
        uint32_t state;
        if (get_80211_state(&state) && state == ITL80211_S_RUN) {
            station_info_t sta_info;
            if (get_station_info(&sta_info) == KERN_SUCCESS) {
                return strncmp(ssid, (char*)sta_info.ssid, NWID_LEN) == 0;
            }
        }
    }

error:
    return false;
}

bool connect_network_with_auth(const char *ssid, uint32_t security, const char *username, const char *pwd)
{
    uint8_t pmk[PMK_KEY_LEN];
    uint8_t bssid[ETHER_ADDR_LEN];

    if (username == NULL) {
        username = "";
    }

    if (pwd == NULL) {
        pwd = "";
    }

    if (!is_enterprise_security(security)) {
        return connect_network(ssid, pwd);
    }

    /* 802.1X networks should not use password as WPA-PSK during association. */
    if (!connect_network(ssid, "")) {
        return false;
    }

    /*
     * If a supplicant already provided PMK (hex), push it to the kext and
     * trigger KEYRUN so RSN key exchange can continue.
     */
    if (!decode_hex_pmk(pwd, pmk)) {
        (void)username;
        return true;
    }

    if (!load_current_bssid(bssid)) {
        return false;
    }

    if (set_key_available(bssid, pmk, 3600) != KERN_SUCCESS) {
        return false;
    }

    if (run_key(bssid) != KERN_SUCCESS) {
        return false;
    }

    return true;
}

static bool isSupportService(const char *name)
{
    if (strcmp(name, "TestService")
        && strcmp(name, "itlwmx") && strcmp(name, "itlwm")
        ) {
        return false;
    }
    return true;
}

bool open_adapter(io_connect_t *connection_t)
{
    kern_return_t kr;
    io_iterator_t iter;
    bool found = false;
    io_service_t service;
    mach_port_name_t port;
    uint32_t type = 0;
    char nn[20];
    if (IOMasterPort(0, &port)) {
        return false;
    }
    CFMutableDictionaryRef matchingDict = IOServiceMatching("IOEthernetController");
    kr = IOServiceGetMatchingServices(port, matchingDict, &iter);
    mach_port_deallocate(mach_task_self(), port);
    if (kr != KERN_SUCCESS)
        return false;
    while ((service = IOIteratorNext(iter)) && !found) {
        CFTypeRef type_ref = IORegistryEntryCreateCFProperty(service, CFSTR("IOClass"), kCFAllocatorDefault, 0);
        if (type_ref) {
            const char *name = CFStringGetCStringPtr(type_ref, 0);
            if (!name) {
                name = nn;
                CFStringGetCString(type_ref, nn, 20, 0);
            }
            if (isSupportService(name)) {
                if (IOServiceOpen(service, mach_task_self(), type, connection_t) == KERN_SUCCESS) {
                    found = true;
                }
            }
            // Fix leak issue if there is more than one Ethernet controller
            CFRelease(type_ref);
        }
        // Fix leak issue if there is more than one Ethernet controller
        IOObjectRelease(service);
    }
    IOObjectRelease(iter);

    if (found) {
        if (!api_mutex) {
            api_mutex = malloc(sizeof(pthread_mutex_t));
            pthread_mutex_init(api_mutex, NULL);
        }
        pthread_mutex_lock(api_mutex);
    }

    return found;
}

void close_adapter(io_connect_t connection)
{
    if (connection) {
        IOServiceClose(connection);
        pthread_mutex_unlock(api_mutex);
    }
}

kern_return_t _nake_ioctl(io_connect_t con, int *ctl, bool is_get, void *data, size_t data_len)
{
    if (!is_get) {
        *ctl |= IOCTL_MASK;
    }
    kern_return_t ret;
    if (is_get) {
        ret = IOConnectCallStructMethod(con, *ctl, NULL, 0, data, &data_len);
    } else {
        ret = IOConnectCallStructMethod(con, *ctl, data, data_len, NULL, 0);
    }
    return ret;
}

kern_return_t _ioctl(int ctl, bool is_get, void *data, size_t data_len)
{
    kern_return_t ret;
    io_connect_t con;
    if (!open_adapter(&con)) {
        return KERN_FAILURE;
    }
    ret = _nake_ioctl(con, &ctl, is_get, data, data_len);
    close_adapter(con);
    return ret;
}
    
kern_return_t ioctl_set(int ctl, void *data, size_t data_len) {
    return _ioctl(ctl, false, data, data_len);
}

kern_return_t ioctl_get(int ctl, void *data, size_t data_len) {
    return _ioctl(ctl, true, data, data_len);
}

bool is_power_on(void) {
    struct ioctl_power power;
    ioctl_get(IOCTL_80211_POWER, &power, sizeof(struct ioctl_power));
    return power.enabled;
}

kern_return_t power_on(void) {
    struct ioctl_power power;
    power.enabled = 1;
    power.version = IOCTL_VERSION;
    return ioctl_set(IOCTL_80211_POWER, &power, sizeof(struct ioctl_power));
}

kern_return_t power_off(void) {
    struct ioctl_power power;
    power.enabled = 0;
    power.version = IOCTL_VERSION;
    return ioctl_set(IOCTL_80211_POWER, &power, sizeof(struct ioctl_power));
}

kern_return_t get_station_info(station_info_t *info)
{
    return ioctl_get(IOCTL_80211_STA_INFO, info, sizeof(struct ioctl_sta_info));
}

kern_return_t join_ssid(const char *ssid, const char *pwd)
{
    struct ioctl_join join = {0};
    join.version = IOCTL_VERSION;
    join.nwid.len = (unsigned int)copy_truncated(join.nwid.nwid, sizeof(join.nwid.nwid), ssid);
    join.wpa_key.len = (unsigned int)copy_truncated(join.wpa_key.key, sizeof(join.wpa_key.key), pwd);
    return ioctl_set(IOCTL_80211_JOIN, &join, sizeof(struct ioctl_join));
}

kern_return_t associate_ssid(const char *ssid, const char *pwd)
{
    struct ioctl_associate ass = {0};
    ass.nwid.len = (unsigned int)copy_truncated(ass.nwid.nwid, sizeof(ass.nwid.nwid), ssid);
    ass.wpa_key.len = (unsigned int)copy_truncated(ass.wpa_key.key, sizeof(ass.wpa_key.key), pwd);
    ass.version = IOCTL_VERSION;
    return ioctl_set(IOCTL_80211_ASSOCIATE, &ass, sizeof(struct ioctl_associate));
}

kern_return_t dis_associate_ssid(const char *ssid)
{
    struct ioctl_disassociate dis = {0};
    dis.version = IOCTL_VERSION;
    copy_truncated((char *)dis.ssid, sizeof(dis.ssid), ssid);
    return ioctl_set(IOCTL_80211_DISASSOCIATE, &dis, sizeof(struct ioctl_disassociate));
}
kern_return_t set_key_available(const uint8_t *bssid, const uint8_t *pmk, uint32_t lifetime)
{
    struct ioctl_keyavail ka = {0};

    if (pmk == NULL) {
        return kIOReturnBadArgument;
    }

    ka.version = IOCTL_VERSION;
    memcpy(ka.pmk, pmk, sizeof(ka.pmk));
    if (bssid != NULL) {
        memcpy(ka.bssid, bssid, sizeof(ka.bssid));
    }
    ka.lifetime = lifetime;

    return ioctl_set(IOCTL_80211_KEYAVAIL, &ka, sizeof(ka));
}

kern_return_t run_key(const uint8_t *bssid)
{
    struct ioctl_keyrun kr = {0};

    kr.version = IOCTL_VERSION;
    if (bssid != NULL) {
        memcpy(kr.bssid, bssid, sizeof(kr.bssid));
    }

    return ioctl_set(IOCTL_80211_KEYRUN, &kr, sizeof(kr));
}

void api_terminate(void) {
    if (api_mutex) {
        /* acquire API lock to wait for the pending API call */
        pthread_mutex_lock(api_mutex);
        pthread_mutex_unlock(api_mutex);
        pthread_mutex_destroy(api_mutex);
    }
}
