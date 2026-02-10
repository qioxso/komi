// test.cpp
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <dirent.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <thread>
#include <atomic>
#include <mutex>
#include <map>

#include "comm.h"

std::atomic<bool> g_monitor_running(false);
std::thread g_monitor_thread;

struct MemoryRegion {
    uintptr_t start;
    uintptr_t end;
    std::string perms;
    std::string name;
};

struct ScanResult {
    uintptr_t addr;
    uintptr_t value;
    int offset;
    std::string region;
};

// 获取所有子线程 TID
std::vector<int> get_all_tids(int pid) {
    std::vector<int> tids;
    std::string path = "/proc/" + std::to_string(pid) + "/task";
    DIR* dir = opendir(path.c_str());
    if (!dir) {
        tids.push_back(pid); // 至少返回主线程
        return tids;
    }
    struct dirent* ptr;
    while ((ptr = readdir(dir)) != nullptr) {
        if (ptr->d_type == DT_DIR && isdigit(ptr->d_name[0])) {
            tids.push_back(atoi(ptr->d_name));
        }
    }
    closedir(dir);
    return tids;
}

std::vector<unsigned char> hex_string_to_bytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    std::string clean_hex;
    for (char c : hex) if (c != ' ') clean_hex += c;
    for (size_t i = 0; i < clean_hex.length(); i += 2) {
        std::string byteString = clean_hex.substr(i, 2);
        try {
            char byte = (char)strtol(byteString.c_str(), NULL, 16);
            bytes.push_back(byte);
        } catch(...) {}
    }
    return bytes;
}

class ShamiTool {
private:
    int fd;
public:
    ShamiTool() {
        fd = open("/dev/shami", O_RDWR);
        if (fd < 0) { perror("[-] 驱动打开失败"); exit(-1); }
    }
    int get_fd() { return fd; }

    int get_pid_by_name(const std::string& package_name) {
        DIR* dir = opendir("/proc");
        if (!dir) return -1;
        struct dirent* ptr;
        while ((ptr = readdir(dir)) != nullptr) {
            if (ptr->d_type != DT_DIR) continue;
            int pid = atoi(ptr->d_name);
            if (pid <= 0) continue;
            std::string cmdPath = "/proc/" + std::to_string(pid) + "/cmdline";
            std::ifstream cmdline(cmdPath);
            std::string line;
            if (std::getline(cmdline, line)) {
                if (line.find(package_name) != std::string::npos) {
                    closedir(dir); return pid;
                }
            }
        }
        closedir(dir); return -1;
    }

    // 用于扫描的内存区域 (只读写)
    std::vector<MemoryRegion> get_rw_regions(int pid) {
        std::vector<MemoryRegion> regions;
        std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
        std::string line;
        while (std::getline(maps, line)) {
            MemoryRegion region;
            size_t dash = line.find('-');
            size_t space = line.find(' ');
            try {
                region.start = std::stoull(line.substr(0, dash), nullptr, 16);
                region.end = std::stoull(line.substr(dash + 1, space - dash - 1), nullptr, 16);
                size_t perm_start = space + 1;
                size_t perm_end = line.find(' ', perm_start);
                region.perms = line.substr(perm_start, perm_end - perm_start);
                size_t path_start = line.find_last_of(' ');
                if (path_start != std::string::npos) {
                   region.name = line.substr(path_start + 1);
                   region.name.erase(0, region.name.find_first_not_of(" \t\n\r"));
                }
                if (region.perms.find("rw") != std::string::npos && region.name != "[vvar]") {
                    regions.push_back(region);
                }
            } catch (...) { continue; }
        }
        return regions;
    }

    // 修复：Maps 搜索 (不过滤权限)
    void search_maps(int pid, const std::string& keyword) {
        std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
        if (!maps.is_open()) {
            std::cout << "[-] 无法打开 maps" << std::endl;
            return;
        }
        std::string line;
        std::cout << "\n[Maps 搜索: " << keyword << "]" << std::endl;
        bool found = false;
        while (std::getline(maps, line)) {
            if (keyword.empty() || line.find(keyword) != std::string::npos) {
                std::cout << line << std::endl;
                found = true;
            }
        }
        if (!found) std::cout << "[-] 未找到" << std::endl;
    }

    std::pair<uintptr_t, size_t> get_module_range(int pid, const std::string& module_name) {
        std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
        std::string line;
        uintptr_t min_addr = -1;
        uintptr_t max_addr = 0;
        bool found = false;
        while (std::getline(maps, line)) {
            if (line.find(module_name) != std::string::npos) {
                found = true;
                size_t dash = line.find('-');
                size_t space = line.find(' ');
                try {
                    uintptr_t start = std::stoull(line.substr(0, dash), nullptr, 16);
                    uintptr_t end = std::stoull(line.substr(dash + 1, space - dash - 1), nullptr, 16);
                    if (start < min_addr) min_addr = start;
                    if (end > max_addr) max_addr = end;
                } catch (...) {}
            }
        }
        if (!found) return {0, 0};
        return {min_addr, max_addr - min_addr};
    }

    bool read_mem(int pid, uintptr_t addr, void* buffer, size_t size) {
        COPY_MEMORY cm = {pid, addr, buffer, size};
        return ioctl(fd, OP_READ_MEM, &cm) == 0;
    }

    bool write_mem(int pid, uintptr_t addr, void* buffer, size_t size) {
        COPY_MEMORY cm = {pid, addr, buffer, size};
        return ioctl(fd, OP_WRITE_MEM, &cm) == 0;
    }

    bool add_uprobe_advanced(const UPROBE_CONFIG& uc) {
        if (ioctl(fd, OP_ADD_UPROBE, &uc) == 0) {
            std::cout << "[+] Uprobe 设置成功!" << std::endl; return true;
        }
        perror("[-] Uprobe 设置失败"); return false;
    }

    bool del_uprobe(int pid, uintptr_t addr) {
        UPROBE_CONFIG uc = {0}; uc.pid = pid; uc.addr = addr;
        return ioctl(fd, OP_DEL_UPROBE, &uc) == 0;
    }

    // 修复：硬件断点 (遍历所有线程)
    bool add_watchpoint(int pid, uintptr_t addr, int type) {
        std::vector<int> tids = get_all_tids(pid);
        int success_count = 0;
        std::cout << "[*] 正在对 " << tids.size() << " 个线程设置断点..." << std::endl;
        
        for (int tid : tids) {
            WATCHPOINT_CONFIG wc;
            wc.pid = tid; wc.addr = addr; wc.type = type; wc.len = 4;
            if (ioctl(fd, OP_ADD_WATCHPOINT, &wc) == 0) success_count++;
        }
        
        if (success_count > 0) {
            std::cout << "[+] 成功在 " << success_count << " 个线程上激活断点。" << std::endl;
            return true;
        }
        perror("[-] 设置失败"); 
        return false;
    }

    bool del_watchpoint(int pid, uintptr_t addr) {
        std::vector<int> tids = get_all_tids(pid);
        int del_count = 0;
        for (int tid : tids) {
            WATCHPOINT_CONFIG wc; wc.pid = tid; wc.addr = addr;
            if (ioctl(fd, OP_DEL_WATCHPOINT, &wc) == 0) del_count++;
        }
        std::cout << "[+] 从 " << del_count << " 个线程移除了断点。" << std::endl;
        return true;
    }

    void save_chains_formatted(int pid, 
                             const std::vector<std::vector<ScanResult>>& history, 
                             uintptr_t final_target, 
                             const std::string& filename,
                             uintptr_t module_base = 0,
                             std::string module_name = "") {
        std::ofstream file(filename);
        if (!file.is_open()) return;

        file << "=== Shami Pointer Chain Report ===\n";
        file << "Final Target: " << std::hex << final_target << "\n";
        file << "Scan Depth: " << std::dec << history.size() << "\n";

        float final_float_val = 0.0f; int final_int_val = 0;
        read_mem(pid, final_target, &final_float_val, sizeof(float));
        read_mem(pid, final_target, &final_int_val, sizeof(int));
        file << "Value: " << std::fixed << std::setprecision(6) << final_float_val 
             << " (Int: " << std::dec << final_int_val << ")\n\n";

        std::vector<std::map<uintptr_t, ScanResult>> lookup_maps(history.size());
        for(size_t i=0; i<history.size(); i++) {
            for(const auto& item : history[i]) lookup_maps[i][item.addr] = item;
        }

        auto write_chain = [&](const ScanResult& top_node, bool is_static) {
            ScanResult current = top_node;
            std::vector<int> offsets; offsets.push_back(current.offset);
            bool broken = false;
            for (int k = (int)history.size() - 2; k >= 0; k--) {
                uintptr_t looking_for = current.value;
                if (lookup_maps[k].count(looking_for)) {
                    current = lookup_maps[k][looking_for];
                    offsets.push_back(current.offset);
                } else { broken = true; break; }
            }

            if (!broken) {
                std::string region = top_node.region.empty() ? "anon" : top_node.region;
                size_t slash = region.find_last_of('/');
                if (slash != std::string::npos) region = region.substr(slash + 1);
                
                std::string seg = "";
                if (region.find(".so") != std::string::npos) seg = (region.find("bss") != std::string::npos) ? "[bss]" : "[data]";
                
                file << region << seg << " + ";
                if (module_base > 0 && top_node.addr >= module_base && top_node.region.find(module_name) != std::string::npos) {
                    file << "0x" << std::hex << (top_node.addr - module_base);
                } else {
                    file << "0x" << std::hex << (is_static ? (top_node.addr & 0xFFFFFF) : top_node.addr);
                }

                for (int off : offsets) file << " -> 0x" << std::hex << off;
                file << " = " << std::dec << std::fixed << std::setprecision(6) << final_float_val << "\n";
                return true;
            }
            return false;
        };

        file << "--- [Section 1] Static Chains ---\n";
        for (const auto& node : history.back()) {
            bool is_static = (node.region.find(".so") != std::string::npos) || (node.region.find("/data/") != std::string::npos);
            if (is_static) write_chain(node, true);
        }

        file << "\n--- [Section 2] Dynamic/Heap Chains ---\n";
        for (const auto& node : history.back()) {
            bool is_static = (node.region.find(".so") != std::string::npos) || (node.region.find("/data/") != std::string::npos);
            if (!is_static) write_chain(node, false);
        }
        file.close();
        std::cout << "[+] Report saved: " << filename << std::endl;
    }

    void scan_pointers_multilevel(int pid, uintptr_t initial_target, int max_offset, int max_depth, const std::string& filename) {
        auto regions = get_rw_regions(pid);
        uintptr_t mod_base = 0; std::string mod_name = "";
        auto il2cpp = get_module_range(pid, "libil2cpp.so");
        if (il2cpp.second > 0) { mod_base = il2cpp.first; mod_name = "libil2cpp.so"; }

        std::vector<std::vector<ScanResult>> history;
        std::vector<uintptr_t> next_targets;
        next_targets.push_back(initial_target);

        for (int level = 1; level <= max_depth; ++level) {
            std::cout << "\n[*] Scanning Level " << level << "..." << std::flush;
            std::sort(next_targets.begin(), next_targets.end());
            next_targets.erase(std::unique(next_targets.begin(), next_targets.end()), next_targets.end());
            if (next_targets.empty()) break;

            std::vector<ScanResult> current_level;
            const size_t CHUNK = 64 * 1024;
            std::vector<unsigned char> buf(CHUNK);

            int cnt = 0;
            for (const auto& region : regions) {
                for (uintptr_t curr = region.start; curr < region.end; curr += CHUNK) {
                    size_t read_size = std::min(CHUNK, (size_t)(region.end - curr));
                    if (!read_mem(pid, curr, buf.data(), read_size)) continue;
                    for (size_t i = 0; i <= read_size - 8; i += 4) {
                        uint64_t val = *reinterpret_cast<uint64_t*>(&buf[i]);
                        auto it = std::lower_bound(next_targets.begin(), next_targets.end(), val);
                        if (it != next_targets.end()) {
                            uintptr_t target = *it;
                            if (target <= val + max_offset) {
                                ScanResult res; res.addr = curr + i; res.value = val;
                                res.offset = (int)(target - val); res.region = region.name;
                                current_level.push_back(res);
                            }
                        }
                    }
                }
                if (++cnt % 100 == 0) std::cout << "." << std::flush;
            }
            std::cout << " Found: " << current_level.size() << std::endl;
            if (current_level.empty()) break;
            history.push_back(current_level);
            
            next_targets.clear();
            for (const auto& res : current_level) next_targets.push_back(res.addr);
            if (current_level.size() > 500000) break;
        }
        save_chains_formatted(pid, history, initial_target, filename, mod_base, mod_name);
    }
};

void log_monitor_thread(int fd) {
    LOG_BUFFER lb; char buffer[4096];
    std::cout << "\n[Monitor] Log thread started..." << std::endl;
    while (g_monitor_running) {
        lb.buffer = buffer; lb.size = sizeof(buffer) - 1; lb.read_bytes = 0;
        int ret = ioctl(fd, OP_GET_LOG, &lb);
        if (ret == 0 && lb.read_bytes > 0) {
            buffer[lb.read_bytes] = '\0';
            std::cout << "\033[1;32m" << buffer << "\033[0m" << std::flush;
        } else std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void perform_dump(ShamiTool& tool, int pid, uintptr_t start_addr, size_t len, std::string filename) {
    std::ofstream outfile(filename, std::ios::binary);
    std::vector<char> buffer(4096);
    size_t total_read = 0;
    std::cout << "[*] Dumping..." << std::endl;
    while (total_read < len) {
        size_t current_read = std::min((size_t)4096, len - total_read);
        if (tool.read_mem(pid, start_addr + total_read, buffer.data(), current_read)) 
            outfile.write(buffer.data(), current_read);
        else {
            std::vector<char> zeros(current_read, 0);
            outfile.write(zeros.data(), current_read);
        }
        total_read += current_read;
    }
    outfile.close(); std::cout << "[+] Dump Done: " << filename << std::endl;
}

void wizard_add_uprobe(ShamiTool& tool, int pid) {
    UPROBE_CONFIG uc = {0}; uc.pid = pid;
    std::cout << "Addr (HEX): "; std::cin >> std::hex >> uc.addr;
    char choice; uc.flags = 0;
    std::cout << "Enable dmesg? (y/n): "; std::cin >> choice;
    if (choice == 'y') uc.flags |= FLAG_ENABLE_PRINTK;
    std::cout << "Enable Monitor? (y/n): "; std::cin >> choice;
    if (choice == 'y') uc.flags |= FLAG_ENABLE_LOG;
    std::cout << "Modify Regs? (y/n): "; std::cin >> choice;
    if (choice == 'y') {
        uc.flags |= FLAG_MODIFY_REG;
        int count = 0; std::cout << "Count (Max 8): "; std::cin >> std::dec >> count;
        if (count > MAX_REG_MODS) count = MAX_REG_MODS;
        uc.mod_count = count;
        for (int i = 0; i < count; i++) {
            std::cout << "Idx (0-30,31=SP,32=PC): "; std::cin >> std::dec >> uc.mods[i].reg_index;
            std::cout << "Val (HEX): "; std::cin >> std::hex >> uc.mods[i].value;
        }
    }
    tool.add_uprobe_advanced(uc);
}

void show_menu() {
    std::cout << "\n========= Shami Pro Ultimate V4 =========" << std::endl;
    std::cout << "1. Get PID\n2. Search Maps\n3. Read Mem\n4. Write Mem\n5. Dump Mem\n";
    std::cout << "-------------------------------------------\n";
    std::cout << "6. [+] Add Uprobe (Hook)\n7. [-] Del Uprobe\n8. [Monitor] Toggle Logs\n";
    std::cout << "-------------------------------------------\n";
    std::cout << "9. [Scan] Smart Pointer Scan\n";
    std::cout << "10.[HWBP] Add Hardware Watchpoint (Multi-Thread)\n11.[HWBP] Del Hardware Watchpoint\n";
    std::cout << "0. Exit\nSelect: ";
}

int main() {
    ShamiTool tool;
    int pid = -1; int choice; std::string input_str;

    while (true) {
        show_menu(); std::cin >> std::dec >> choice;
        if (std::cin.fail()) { std::cin.clear(); std::cin.ignore(); continue; }
        if (choice == 0) break;

        switch (choice) {
            case 1: std::cout << "Package: "; std::cin >> input_str; 
                    pid = tool.get_pid_by_name(input_str); 
                    std::cout << (pid!=-1 ? "PID: "+std::to_string(pid) : "Not found") << std::endl; break;
            case 2: if(pid==-1)break; std::cout << "Keyword: "; std::cin.ignore(); std::getline(std::cin, input_str); 
                    tool.search_maps(pid, input_str); break;
            case 3: if(pid==-1)break; uintptr_t a; size_t l; std::cout<<"Addr: ";std::cin>>std::hex>>a; std::cout<<"Len: ";std::cin>>std::dec>>l;
                    { std::vector<unsigned char> b(l); if(tool.read_mem(pid,a,b.data(),l)){ for(auto x:b)std::cout<<std::hex<<std::setw(2)<<(int)x<<" "; std::cout<<std::endl;} } break;
            case 4: if(pid==-1)break; { uintptr_t a; std::cout<<"Addr: ";std::cin>>std::hex>>a; std::cout<<"Hex: ";std::cin.ignore();std::getline(std::cin,input_str);
                    auto b=hex_string_to_bytes(input_str); tool.write_mem(pid,a,b.data(),b.size()); } break;
            case 5: if(pid==-1)break; { uintptr_t s; size_t ln; std::cout<<"Start(HEX): ";std::cin>>std::hex>>s; std::cout<<"Len(DEC): ";std::cin>>std::dec>>ln;
                    perform_dump(tool, pid, s, ln, "dump.bin"); } break;
            case 6: if(pid!=-1) wizard_add_uprobe(tool, pid); break;
            case 7: if(pid!=-1){ uintptr_t a; std::cout<<"Addr: ";std::cin>>std::hex>>a; tool.del_uprobe(pid,a); } break;
            case 8: if(!g_monitor_running){ g_monitor_running=true; g_monitor_thread=std::thread(log_monitor_thread,tool.get_fd()); g_monitor_thread.detach(); }
                    else g_monitor_running=false; break;
            case 9: if(pid!=-1){ uintptr_t t; int o,d; std::string f; std::cout<<"Target(HEX): ";std::cin>>std::hex>>t; 
                    std::cout<<"Offset(DEC): ";std::cin>>std::dec>>o; std::cout<<"Depth(DEC): ";std::cin>>std::dec>>d; 
                    std::cout<<"File: ";std::cin>>f; tool.scan_pointers_multilevel(pid,t,o,d,f); } break;
            case 10: if(pid!=-1){ uintptr_t a; int t; std::cout<<"Addr(HEX): ";std::cin>>std::hex>>a; std::cout<<"Type(1=W,2=R,3=RW): ";std::cin>>std::dec>>t; 
                     tool.add_watchpoint(pid,a,t); } break;
            case 11: if(pid!=-1){ uintptr_t a; std::cout<<"Addr(HEX): ";std::cin>>std::hex>>a; tool.del_watchpoint(pid,a); } break;
        }
    }
    g_monitor_running = false;
    return 0;
}
