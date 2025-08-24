// dnsproxy.c - DNS proxy with domain-based route injection

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <signal.h>
#include <syslog.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <net/if.h>
#include <sys/uio.h>
#include <event2/event.h>
#include <sys/queue.h>

#ifdef __linux__
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#elif defined(__FreeBSD__)
#include <net/route.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <net/if_types.h>
#else
#error "Unsupported platform"
#endif

// Constants
#define MAX_CACHED_IPS 65536
#define MAX_BLOCKLIST_FILES 10
#define MAX_GATEWAYS 10
#define MAX_DOMAIN_PARTS 32
#define MAX_DOMAIN_LENGTH 256
#define MAX_LABEL_LENGTH 64  // RFC 1035: максимальная длина метки 63 байта + 1 для нулевого символа
#define INITIAL_HASH_SIZE 16
#define LOAD_FACTOR_THRESHOLD 0.75
#define INITIAL_IP_CACHE_SIZE 1024

// Basic structure definitions first
struct domain_node;  // Forward declaration
struct hash_table;   // Forward declaration
struct hash_entry;   // Forward declaration
struct cached_ip;    // Forward declaration
struct ip_cache;     // Forward declaration

// Complete structure definitions
struct domain_node {
    struct hash_table *children;
    int exact;
    int wildcard;
};

struct hash_table {
    struct hash_entry **buckets;
    size_t size;
    size_t count;
};

struct hash_entry {
    uint32_t hash;     // Hash for quick comparison
    uint32_t offset;   // Offset in string pool
    struct domain_node *node;
    struct hash_entry *next;
};

struct cached_ip {
    uint32_t subnet;
    time_t expiry;
    struct cached_ip *next;
};

struct ip_cache {
    struct cached_ip **buckets;
    size_t size;
    size_t count;
};

// Forward declarations of hash functions
uint32_t hash_string_fnv(const char *str);
size_t hash_to_index(uint32_t hash, size_t size);

// Forward declarations of domain functions
int split_domain(char *domain, char parts[MAX_DOMAIN_PARTS][MAX_LABEL_LENGTH], int *count);
void free_domain_node(struct domain_node *node);

// String pool related structures and functions
struct string_index_entry {
    uint32_t hash;
    uint32_t offset;
    struct string_index_entry *next;
};

struct string_pool {
    char *data;
    size_t size;
    size_t capacity;
    struct string_index_entry **index;
    size_t index_size;
    size_t unique_strings;
};

// Forward declarations of string pool functions
struct string_pool *create_string_pool(size_t initial_capacity);
uint32_t pool_add_string(struct string_pool *pool, const char *str);
const char *pool_get_string(struct string_pool *pool, uint32_t offset);
void free_string_pool(struct string_pool *pool);

// Global variables
struct ip_cache *ip_cache = NULL;
struct string_pool *global_string_pool = NULL;

// Configuration structure
struct gateway_config {
    char gateway[64];
    char blocked_domains_file[MAX_BLOCKLIST_FILES][256];
    int blocked_domains_file_count;
    struct domain_node *domain_root;
};

struct config {
    char listen_address[64];
    int listen_port;
    char upstream_dns[64];
    int route_expire;
    int log_level;
    struct gateway_config gateways[MAX_GATEWAYS];
    int gateway_count;
} cfg;

struct event_base *evbase;
struct event *dns_event;
int sockfd;

// Hash function implementations
uint32_t hash_string_fnv(const char *str) {
    uint32_t hash = 2166136261u;
    while (*str) {
        hash ^= (uint8_t)tolower(*str);
        hash *= 16777619u;
        str++;
    }
    return hash;
}

size_t hash_to_index(uint32_t hash, size_t size) {
    return hash % size;
}

// Создание пула строк
struct string_pool *create_string_pool(size_t initial_capacity) {
    struct string_pool *pool = malloc(sizeof(struct string_pool));
    if (!pool) return NULL;

    pool->data = malloc(initial_capacity);
    if (!pool->data) {
        free(pool);
        return NULL;
    }

    // Инициализируем индекс с тем же размером что и хэш-таблицы доменов
    pool->index_size = INITIAL_HASH_SIZE;
    pool->index = calloc(pool->index_size, sizeof(struct string_index_entry *));
    if (!pool->index) {
        free(pool->data);
        free(pool);
        return NULL;
    }

    pool->size = 0;
    pool->capacity = initial_capacity;
    pool->unique_strings = 0;
    return pool;
}

// Поиск строки в индексе
static uint32_t find_string_offset(struct string_pool *pool, const char *str, uint32_t hash) {
    size_t index = hash_to_index(hash, pool->index_size);
    struct string_index_entry *entry = pool->index[index];
    
    while (entry) {
        if (entry->hash == hash && strcasecmp(pool->data + entry->offset, str) == 0) {
            return entry->offset;
        }
        entry = entry->next;
    }
    
    return -1;
}

// Добавление записи в индекс
static void add_to_index(struct string_pool *pool, uint32_t offset, uint32_t hash) {
    // Проверяем необходимость ресайза
    if ((float)pool->unique_strings / pool->index_size > LOAD_FACTOR_THRESHOLD) {
        size_t new_size = pool->index_size * 2;
        struct string_index_entry **new_index = calloc(new_size, sizeof(struct string_index_entry *));
        if (!new_index) return;  // В случае ошибки продолжаем со старым размером

        // Перехэшируем все записи
        for (size_t i = 0; i < pool->index_size; i++) {
            struct string_index_entry *entry = pool->index[i];
            while (entry) {
                struct string_index_entry *next = entry->next;
                size_t new_idx = hash_to_index(entry->hash, new_size);
                entry->next = new_index[new_idx];
                new_index[new_idx] = entry;
                entry = next;
            }
        }

        free(pool->index);
        pool->index = new_index;
        pool->index_size = new_size;
    }

    // Добавляем новую запись
    struct string_index_entry *entry = malloc(sizeof(struct string_index_entry));
    if (!entry) return;

    entry->hash = hash;
    entry->offset = offset;
    size_t index = hash_to_index(hash, pool->index_size);
    entry->next = pool->index[index];
    pool->index[index] = entry;
    pool->unique_strings++;
}

// Обновленная функция добавления строки
uint32_t pool_add_string(struct string_pool *pool, const char *str) {
    size_t len = strlen(str) + 1;
    uint32_t hash = hash_string_fnv(str);
    
    // Ищем строку в индексе
    uint32_t existing_offset = find_string_offset(pool, str, hash);
    if (existing_offset != -1) {
        return existing_offset;
    }
    
    // Расширяем пул если нужно
    if (pool->size + len > pool->capacity) {
        size_t new_capacity = pool->capacity * 2;
        char *new_data = realloc(pool->data, new_capacity);
        if (!new_data) return -1;
        
        pool->data = new_data;
        pool->capacity = new_capacity;
    }
    
    // Добавляем строку
    uint32_t result = pool->size;
    memcpy(pool->data + pool->size, str, len);
    pool->size += len;
    
    // Добавляем в индекс
    add_to_index(pool, result, hash);
    
    return result;
}

// Получение строки из пула
const char *pool_get_string(struct string_pool *pool, uint32_t offset) {
    if (offset >= pool->size) return NULL;
    return pool->data + offset;
}

void free_string_pool(struct string_pool *pool) {
    if (!pool) return;
    
    // Освобождаем все записи в индексе
    for (size_t i = 0; i < pool->index_size; i++) {
        struct string_index_entry *entry = pool->index[i];
        while (entry) {
            struct string_index_entry *next = entry->next;
            free(entry);
            entry = next;
        }
    }
    
    free(pool->data);
    free(pool->index);
    free(pool);
}

struct hash_entry *find_entry(struct hash_table *ht, const char *label, uint32_t hash) {
    if (!ht) return NULL;
    
    size_t index = hash_to_index(hash, ht->size);
    struct hash_entry *entry = ht->buckets[index];
    
    while (entry) {
        const char *entry_label = pool_get_string(global_string_pool, entry->offset);
        if (entry->hash == hash && strcasecmp(entry_label, label) == 0) {
            return entry;
        }
        entry = entry->next;
    }
    
    return NULL;
}

void resize_hash_table(struct hash_table *ht) {
    size_t new_size = ht->size * 2;
    struct hash_entry **new_buckets = calloc(new_size, sizeof(struct hash_entry *));
    if (!new_buckets) return;
    
    for (size_t i = 0; i < ht->size; i++) {
        struct hash_entry *entry = ht->buckets[i];
        while (entry) {
            struct hash_entry *next = entry->next;
            size_t new_index = hash_to_index(entry->hash, new_size);
            entry->next = new_buckets[new_index];
            new_buckets[new_index] = entry;
            entry = next;
        }
    }
    
    free(ht->buckets);
    ht->buckets = new_buckets;
    ht->size = new_size;
}

struct domain_node *create_node() {
    struct domain_node *node = malloc(sizeof(struct domain_node));
    if (!node) return NULL;
    
    node->children = malloc(sizeof(struct hash_table));
    if (!node->children) {
        free(node);
        return NULL;
    }
    
    node->children->buckets = calloc(INITIAL_HASH_SIZE, sizeof(struct hash_entry *));
    if (!node->children->buckets) {
        free(node->children);
        free(node);
        return NULL;
    }
    
    node->children->size = INITIAL_HASH_SIZE;
    node->children->count = 0;
    node->exact = 0;
    node->wildcard = 0;
    
    return node;
}

void add_domain_to_tree(struct domain_node **root, const char *domain, int wildcard) {
    char parts[MAX_DOMAIN_PARTS][MAX_LABEL_LENGTH];
    int count;
    
    if (!global_string_pool) {
        // Начинаем с 1MB вместо 16MB
        global_string_pool = create_string_pool(1024 * 1024);
        if (!global_string_pool) {
            syslog(LOG_ERR, "Failed to allocate string pool");
            return;
        }
    }
    
    if (!*root) {
        *root = create_node();
        if (!*root) return;
    }
    
    // Проверяем длину домена
    size_t domain_len = strlen(domain);
    if (domain_len >= MAX_DOMAIN_LENGTH) {
        syslog(LOG_WARNING, "Domain too long (%zu bytes): %s", domain_len, domain);
        return;
    }
    
    char domain_copy[MAX_DOMAIN_LENGTH];
    strncpy(domain_copy, domain, MAX_DOMAIN_LENGTH - 1);
    domain_copy[MAX_DOMAIN_LENGTH - 1] = '\0';
    
    if (!split_domain(domain_copy, parts, &count)) {
        syslog(LOG_WARNING, "Failed to split domain: %s", domain);
        return;
    }
    
    struct domain_node *current = *root;
    for (int i = 0; i < count; i++) {
        uint32_t hash = hash_string_fnv(parts[i]);
        struct hash_entry *entry = find_entry(current->children, parts[i], hash);
        
        if (!entry) {
            if ((float)current->children->count / current->children->size > LOAD_FACTOR_THRESHOLD) {
                resize_hash_table(current->children);
            }
            
            entry = malloc(sizeof(struct hash_entry));
            if (!entry) {
                syslog(LOG_ERR, "Failed to allocate hash entry for domain: %s", domain);
                return;
            }
            
            entry->hash = hash;
            entry->offset = pool_add_string(global_string_pool, parts[i]);
            if (entry->offset == -1) {
                syslog(LOG_ERR, "Failed to add string to pool for domain: %s", domain);
                free(entry);
                return;
            }
            
            entry->node = create_node();
            if (!entry->node) {
                syslog(LOG_ERR, "Failed to create node for domain: %s", domain);
                free(entry);
                return;
            }
            
            size_t index = hash_to_index(hash, current->children->size);
            entry->next = current->children->buckets[index];
            current->children->buckets[index] = entry;
            current->children->count++;
        }
        
        current = entry->node;
    }
    
    if (wildcard)
        current->wildcard = 1;
    else
        current->exact = 1;
}

// Проверяет, содержится ли домен в дереве
int domain_in_tree(struct domain_node *root, const char *domain) {
    char parts[MAX_DOMAIN_PARTS][MAX_LABEL_LENGTH];
    int count;
    
    if (!root) return 0;
    
    // Проверяем длину домена
    size_t domain_len = strlen(domain);
    if (domain_len >= MAX_DOMAIN_LENGTH) {
        syslog(LOG_WARNING, "Domain too long (%zu bytes): %s", domain_len, domain);
        return 0;
    }
    
    // Разбиваем домен на части
    char domain_copy[MAX_DOMAIN_LENGTH];
    strncpy(domain_copy, domain, MAX_DOMAIN_LENGTH - 1);
    domain_copy[MAX_DOMAIN_LENGTH - 1] = '\0';
    
    if (!split_domain(domain_copy, parts, &count)) {
        return 0;
    }
    
    // Ищем в дереве, начиная с конца (TLD)
    struct domain_node *current = root;
    for (int i = 0; i < count && current; i++) {
        if (current->wildcard) return 1;  // Нашли родительский домен
        
        struct hash_entry *entry = find_entry(current->children, parts[i], hash_string_fnv(parts[i]));
        current = entry ? entry->node : NULL;
    }

    return current && (current->exact || current->wildcard);
}

// Разбивает домен на части в обратном порядке
int split_domain(char *domain, char parts[MAX_DOMAIN_PARTS][MAX_LABEL_LENGTH], int *count) {
    *count = 0;
    char *saveptr;
    
    // Пропускаем начальную точку если есть
    if (domain[0] == '.') domain++;
    
    // Копируем домен, так как strtok_r модифицирует строку
    char temp[MAX_DOMAIN_LENGTH];
    strncpy(temp, domain, MAX_DOMAIN_LENGTH - 1);
    temp[MAX_DOMAIN_LENGTH - 1] = '\0';
    
    // Разбиваем на части
    char *part = strtok_r(temp, ".", &saveptr);
    while (part && *count < MAX_DOMAIN_PARTS) {
        size_t len = strlen(part);
        if (len >= MAX_LABEL_LENGTH) {
            syslog(LOG_WARNING, "Domain label too long: %s", part);
            return 0;
        }
        strncpy(parts[*count], part, MAX_LABEL_LENGTH - 1);
        parts[*count][MAX_LABEL_LENGTH - 1] = '\0';
        (*count)++;
        part = strtok_r(NULL, ".", &saveptr);
    }
    
    // Разворачиваем массив частей
    for (int i = 0; i < *count / 2; i++) {
        char temp[MAX_LABEL_LENGTH];
        strncpy(temp, parts[i], MAX_LABEL_LENGTH);
        strncpy(parts[i], parts[*count - 1 - i], MAX_LABEL_LENGTH);
        strncpy(parts[*count - 1 - i], temp, MAX_LABEL_LENGTH);
    }
    
    return *count > 0;
}

void trim(char *s) {
    char *p = s, *q;
    while (isspace((unsigned char)*p)) p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    q = s + strlen(s) - 1;
    while (q >= s && isspace((unsigned char)*q)) *q-- = '\0';
}

void load_config() {
    FILE *f = fopen("/usr/local/etc/dnsproxy.conf", "r");
    if (!f) {
        syslog(LOG_ERR, "Unable to open config file");
        exit(1);
    }

    cfg.gateway_count = 0;
    cfg.log_level = LOG_INFO;
    struct gateway_config *current_gw = NULL;
    
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        char *k = line, *v = eq + 1;
        trim(k); trim(v);
        if (!strcmp(k, "listen_address")) {
            strncpy(cfg.listen_address, v, sizeof(cfg.listen_address));
        } else if (!strcmp(k, "listen_port")) {
            cfg.listen_port = atoi(v);
        } else if (!strcmp(k, "upstream_dns")) {
            strncpy(cfg.upstream_dns, v, sizeof(cfg.upstream_dns));
        } else if (!strcmp(k, "route_expire")) {
            cfg.route_expire = atoi(v);
        } else if (!strcmp(k, "log_level")) {
            cfg.log_level = atoi(v);
        } else if (!strcmp(k, "gateway")) {
            if (cfg.gateway_count < MAX_GATEWAYS) {
                current_gw = &cfg.gateways[cfg.gateway_count++];
                strncpy(current_gw->gateway, v, sizeof(current_gw->gateway));
                current_gw->blocked_domains_file_count = 0;
                current_gw->domain_root = NULL;
            } else {
                syslog(LOG_WARNING, "Maximum number of gateways (%d) exceeded, ignoring %s",
                       MAX_GATEWAYS, v);
                current_gw = NULL;
            }
        } else if (!strcmp(k, "blocked_domains_file")) {
            if (!current_gw) {
                syslog(LOG_WARNING, "blocked_domains_file specified before any gateway, ignoring %s", v);
            } else if (current_gw->blocked_domains_file_count < MAX_BLOCKLIST_FILES) {
                strncpy(current_gw->blocked_domains_file[current_gw->blocked_domains_file_count], v, 255);
                current_gw->blocked_domains_file_count++;
            } else {
                syslog(LOG_WARNING,
                       "Maximum number of blocklist files (%d) exceeded for gateway %s, ignoring %s",
                       MAX_BLOCKLIST_FILES, current_gw->gateway, v);
            }
        }
    }
    fclose(f);

    if (cfg.gateway_count == 0) {
        syslog(LOG_WARNING, "No gateways specified in config");
    } else {
        for (int i = 0; i < cfg.gateway_count; i++) {
            if (cfg.gateways[i].blocked_domains_file_count == 0) {
                syslog(LOG_WARNING, "Gateway %s has no blocklist files", cfg.gateways[i].gateway);
            }
        }
    }

    setlogmask(LOG_UPTO(cfg.log_level));
}

void free_blocklist() {
    for (int i = 0; i < cfg.gateway_count; i++) {
        if (cfg.gateways[i].domain_root) {
            free_domain_node(cfg.gateways[i].domain_root);
            cfg.gateways[i].domain_root = NULL;
        }
    }
    if (global_string_pool) {
        free_string_pool(global_string_pool);
        global_string_pool = NULL;
    }
}

void load_blocklist() {
    syslog(LOG_INFO, "Loading blocklist");

    int total_domains = 0;
    struct timeval start_time, current_time, last_progress_time;
    gettimeofday(&start_time, NULL);
    gettimeofday(&last_progress_time, NULL);

    for (int gw = 0; gw < cfg.gateway_count; gw++) {
        for (int file_idx = 0; file_idx < cfg.gateways[gw].blocked_domains_file_count; file_idx++) {
            FILE *f = fopen(cfg.gateways[gw].blocked_domains_file[file_idx], "r");
            if (!f) {
                syslog(LOG_ERR, "Unable to open blocklist file: %s", cfg.gateways[gw].blocked_domains_file[file_idx]);
                continue;
            }

            char line[MAX_DOMAIN_LENGTH];
            int file_domains = 0;
            while (fgets(line, sizeof(line), f)) {
                trim(line);
                if (!*line) continue;
                int wildcard = (line[0] == '.');
                add_domain_to_tree(&cfg.gateways[gw].domain_root, line, wildcard);
                file_domains++;
                total_domains++;

                if (total_domains % 10000 == 0) {
                    gettimeofday(&current_time, NULL);
                    double elapsed = (current_time.tv_sec - start_time.tv_sec) +
                                     (current_time.tv_usec - start_time.tv_usec) / 1000000.0;
                    double time_since_last = (current_time.tv_sec - last_progress_time.tv_sec) +
                                            (current_time.tv_usec - last_progress_time.tv_usec) / 1000000.0;

                    if (time_since_last >= 30.0) {
                        syslog(LOG_INFO, "Loading domains progress: %d domains in %.1f seconds",
                               total_domains, elapsed);
                        last_progress_time = current_time;
                    }
                }
            }
            fclose(f);
            syslog(LOG_INFO, "Loaded %d domains from %s for gateway %s", file_domains,
                   cfg.gateways[gw].blocked_domains_file[file_idx], cfg.gateways[gw].gateway);
        }
    }

    gettimeofday(&current_time, NULL);
    double total_time = (current_time.tv_sec - start_time.tv_sec) +
                        (current_time.tv_usec - start_time.tv_usec) / 1000000.0;
    syslog(LOG_INFO, "Loaded %d blocked domains total in %.1f seconds", total_domains, total_time);
    
    // Логируем информацию о памяти после загрузки
    if (global_string_pool) {
        syslog(LOG_INFO, "String pool: %zu unique strings, %zu bytes used, %zu bytes allocated",
               global_string_pool->unique_strings,
               global_string_pool->size,
               global_string_pool->capacity);
    }
    if (ip_cache) {
        syslog(LOG_INFO, "IP cache: %zu entries, %zu buckets",
               ip_cache->count,
               ip_cache->size);
    }
}

// Проверяет домен во всех деревьях и возвращает соответствующий шлюз
int domain_matches(const char *query, struct gateway_config **match_gw) {
    for (int i = 0; i < cfg.gateway_count; i++) {
        if (domain_in_tree(cfg.gateways[i].domain_root, query)) {
            if (match_gw) *match_gw = &cfg.gateways[i];
            return 1;
        }
    }
    return 0;
}

// Обработчик SIGHUP
void sighup_handler(evutil_socket_t fd, short what, void *arg) {
    syslog(LOG_INFO, "Reloading configuration and blocklist");
    free_blocklist();
    load_config();
    load_blocklist();
}

// Функция для получения подсети /24 из IP
uint32_t get_subnet_24(uint32_t ip) {
    // Преобразуем из сетевого порядка в хостовый, применяем маску и возвращаем в сетевом порядке
    return htonl((ntohl(ip)) & 0xFFFFFF00);
}

// Создание кэша IP
struct ip_cache *create_ip_cache(size_t size) {
    struct ip_cache *cache = malloc(sizeof(struct ip_cache));
    if (!cache) {
        syslog(LOG_ERR, "Failed to allocate IP cache");
        return NULL;
    }
    
    cache->buckets = calloc(size, sizeof(struct cached_ip *));
    if (!cache->buckets) {
        syslog(LOG_ERR, "Failed to allocate IP cache buckets");
        free(cache);
        return NULL;
    }
    
    cache->size = size;
    cache->count = 0;
    return cache;
}

// Хэш-функция для IP подсети
size_t hash_subnet(uint32_t subnet, size_t size) {
    return (size_t)subnet % size;
}

// Поиск подсети в кэше
struct cached_ip *find_subnet(struct ip_cache *cache, uint32_t subnet) {
    if (!cache) return NULL;
    
    size_t index = hash_subnet(subnet, cache->size);
    struct cached_ip *entry = cache->buckets[index];
    
    while (entry) {
        if (entry->subnet == subnet) return entry;
        entry = entry->next;
    }
    
    return NULL;
}

// Ресайз кэша IP
void resize_ip_cache(struct ip_cache *cache) {
    size_t new_size = cache->size * 2;
    struct cached_ip **new_buckets = calloc(new_size, sizeof(struct cached_ip *));
    if (!new_buckets) {
        syslog(LOG_ERR, "Failed to resize IP cache");
        return;
    }
    
    for (size_t i = 0; i < cache->size; i++) {
        struct cached_ip *entry = cache->buckets[i];
        while (entry) {
            struct cached_ip *next = entry->next;
            size_t new_index = hash_subnet(entry->subnet, new_size);
            entry->next = new_buckets[new_index];
            new_buckets[new_index] = entry;
            entry = next;
        }
    }
    
    free(cache->buckets);
    cache->buckets = new_buckets;
    cache->size = new_size;
}

void add_ip_cache_with_expire(uint32_t subnet, time_t expire) {
    // Создаем кэш если его нет
    if (!ip_cache) {
        ip_cache = create_ip_cache(INITIAL_IP_CACHE_SIZE);
        if (!ip_cache) return;
    }
    // Ищем существующую запись
    struct cached_ip *entry = find_subnet(ip_cache, subnet);
    if (entry) {
        entry->expiry = expire;
        return;
    }
    // Проверяем необходимость ресайза
    if ((float)ip_cache->count / ip_cache->size > LOAD_FACTOR_THRESHOLD) {
        resize_ip_cache(ip_cache);
    }
    entry = malloc(sizeof(struct cached_ip));
    if (!entry) {
        syslog(LOG_ERR, "Failed to allocate IP cache entry");
        return;
    }
    entry->subnet = subnet;
    entry->expiry = expire;
    size_t index = hash_subnet(subnet, ip_cache->size);
    entry->next = ip_cache->buckets[index];
    ip_cache->buckets[index] = entry;
    ip_cache->count++;
}

// Сжатие хэш-таблицы при малом количестве элементов
void shrink_hash_table(struct hash_table *ht) {
    if (!ht || ht->size <= INITIAL_HASH_SIZE) return;
    
    // Если элементов меньше 25% от размера таблицы, уменьшаем размер
    if ((float)ht->count / ht->size < 0.25) {
        size_t new_size = ht->size / 2;
        struct hash_entry **new_buckets = calloc(new_size, sizeof(struct hash_entry *));
        if (!new_buckets) return;
        
        for (size_t i = 0; i < ht->size; i++) {
            struct hash_entry *entry = ht->buckets[i];
            while (entry) {
                struct hash_entry *next = entry->next;
                size_t new_index = hash_to_index(entry->hash, new_size);
                entry->next = new_buckets[new_index];
                new_buckets[new_index] = entry;
                entry = next;
            }
        }
        
        free(ht->buckets);
        ht->buckets = new_buckets;
        ht->size = new_size;
    }
}

// Сжатие кэша IP при малом количестве элементов
void shrink_ip_cache(struct ip_cache *cache) {
    if (!cache || cache->size <= INITIAL_IP_CACHE_SIZE) return;

    // Если элементов меньше 25% от размера таблицы, уменьшаем размер
    if ((float)cache->count / cache->size < 0.25) {
        size_t new_size = cache->size / 2;
        struct cached_ip **new_buckets = calloc(new_size, sizeof(struct cached_ip *));
        if (!new_buckets) return;

        for (size_t i = 0; i < cache->size; i++) {
            struct cached_ip *entry = cache->buckets[i];
            while (entry) {
                struct cached_ip *next = entry->next;
                size_t new_index = hash_subnet(entry->subnet, new_size);
                entry->next = new_buckets[new_index];
                new_buckets[new_index] = entry;
                entry = next;
            }
        }

        free(cache->buckets);
        cache->buckets = new_buckets;
        cache->size = new_size;
    }
}

void free_domain_node(struct domain_node *node) {
    if (!node) return;
    
    if (node->children) {
        for (size_t i = 0; i < node->children->size; i++) {
            struct hash_entry *entry = node->children->buckets[i];
            while (entry) {
                struct hash_entry *next = entry->next;
                free_domain_node(entry->node);
                free(entry);
                entry = next;
            }
        }
        free(node->children->buckets);
        free(node->children);
    }
    
    free(node);
}

// Добавляем сжатие хэш-таблицы в cleanup_ip_cache
void cleanup_ip_cache() {
    if (!ip_cache) return;
    
    time_t now = time(NULL);
    size_t removed = 0;
    
    for (size_t i = 0; i < ip_cache->size; i++) {
        struct cached_ip **pp = &ip_cache->buckets[i];
        struct cached_ip *entry = *pp;
        
        while (entry) {
            if (entry->expiry <= now) {
                *pp = entry->next;
                free(entry);
                ip_cache->count--;
                removed++;
            } else {
                pp = &entry->next;
            }
            entry = *pp;
        }
    }
    
    if (removed > 0) {
        syslog(LOG_INFO, "Cleaned up %zu expired IP cache entries", removed);
        // Сжимаем кэш IP после удаления элементов
        shrink_ip_cache(ip_cache);
    }
}

int is_ip_cached(uint32_t subnet) {
    if (!ip_cache) return 0;
    
    time_t now = time(NULL);
    struct cached_ip *entry = find_subnet(ip_cache, subnet);
    
    return entry && entry->expiry > now;
}

void free_ip_cache() {
    if (!ip_cache) return;
    
    for (size_t i = 0; i < ip_cache->size; i++) {
        struct cached_ip *entry = ip_cache->buckets[i];
        while (entry) {
            struct cached_ip *next = entry->next;
            free(entry);
            entry = next;
        }
    }
    
    free(ip_cache->buckets);
    free(ip_cache);
    ip_cache = NULL;
}

#if defined(__linux__)

static void parse_rtattr(struct rtattr **tb, int max, struct rtattr *rta, int len) {
    while (RTA_OK(rta, len)) {
        if (rta->rta_type <= max)
            tb[rta->rta_type] = rta;
        rta = RTA_NEXT(rta, len);
    }
}

static int addattr_l(struct nlmsghdr *n, size_t maxlen, int type, const void *data, size_t alen) {
    size_t len = RTA_LENGTH(alen);
    size_t newlen = NLMSG_ALIGN(n->nlmsg_len) + len;
    if (newlen > maxlen)
        return -1;
    struct rtattr *rta = (struct rtattr *)(((char *)n) + NLMSG_ALIGN(n->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len = len;
    if (alen)
        memcpy(RTA_DATA(rta), data, alen);
    n->nlmsg_len = newlen;
    return 0;
}

int add_route_via_pfroute(uint32_t ip, const char *domain, const char *gateway) {
    uint32_t subnet = get_subnet_24(ip);
    if (is_ip_cached(subnet))
        return 0;

    int rtsock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (rtsock < 0) {
        syslog(LOG_ERR, "NETLINK socket failed: %s", strerror(errno));
        return -1;
    }

    struct sockaddr_nl nladdr = { .nl_family = AF_NETLINK };
    int result = 0;

    // Check existing route
    struct { struct nlmsghdr nh; struct rtmsg rt; char buf[256]; } req;
    memset(&req, 0, sizeof(req));
    req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nh.nlmsg_type = RTM_GETROUTE;
    req.nh.nlmsg_flags = NLM_F_REQUEST;
    req.rt.rtm_family = AF_INET;
    req.rt.rtm_dst_len = 24;
    addattr_l(&req.nh, sizeof(req), RTA_DST, &subnet, sizeof(subnet));
    if (sendto(rtsock, &req, req.nh.nlmsg_len, 0, (struct sockaddr *)&nladdr, sizeof(nladdr)) >= 0) {
        char buf[4096];
        int len = recv(rtsock, buf, sizeof(buf), 0);
        if (len > 0) {
            struct nlmsghdr *nh;
            for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
                if (nh->nlmsg_type == RTM_NEWROUTE) {
                    struct rtmsg *rtm = NLMSG_DATA(nh);
                    struct rtattr *tb[RTA_MAX + 1];
                    memset(tb, 0, sizeof(tb));
                    parse_rtattr(tb, RTA_MAX, RTM_RTA(rtm), RTM_PAYLOAD(nh));
                    if (tb[RTA_GATEWAY]) {
                        uint32_t gw = *(uint32_t *)RTA_DATA(tb[RTA_GATEWAY]);
                        char gwbuf[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &gw, gwbuf, sizeof(gwbuf));
                        struct in_addr addr; addr.s_addr = subnet;
                        if (strcmp(gwbuf, gateway) == 0) {
                            time_t now = time(NULL);
                            time_t expire = now + cfg.route_expire;
                            if (tb[RTA_METRICS]) {
                                struct rtattr *mt[RTAX_MAX + 1];
                                memset(mt, 0, sizeof(mt));
                                parse_rtattr(mt, RTAX_MAX, RTA_DATA(tb[RTA_METRICS]), RTA_PAYLOAD(tb[RTA_METRICS]));
                                if (mt[RTAX_EXPIRES])
                                    expire = now + *(uint32_t *)RTA_DATA(mt[RTAX_EXPIRES]);
                            }
                            add_ip_cache_with_expire(subnet, expire);
                            close(rtsock);
                            return 0;
                        }
                        if (rtm->rtm_protocol == RTPROT_STATIC) {
                            syslog(LOG_WARNING,
                                   "Route for %s/24 (domain: %s) exists via different gateway: %s",
                                   inet_ntoa(addr), domain, gwbuf);
                            close(rtsock);
                            return -1;
                        }
                    }
                }
            }
        }
    }

    // Add new route
    struct { struct nlmsghdr nh; struct rtmsg rt; char buf[256]; } add;
    memset(&add, 0, sizeof(add));
    add.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    add.nh.nlmsg_type = RTM_NEWROUTE;
    add.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
    add.rt.rtm_family = AF_INET;
    add.rt.rtm_table = RT_TABLE_MAIN;
    add.rt.rtm_protocol = RTPROT_STATIC;
    add.rt.rtm_scope = RT_SCOPE_UNIVERSE;
    add.rt.rtm_type = RTN_UNICAST;
    add.rt.rtm_dst_len = 24;
    addattr_l(&add.nh, sizeof(add), RTA_DST, &subnet, sizeof(subnet));
    struct in_addr gwaddr; inet_pton(AF_INET, gateway, &gwaddr);
    addattr_l(&add.nh, sizeof(add), RTA_GATEWAY, &gwaddr, sizeof(gwaddr));

    // Set expiration
    struct rtattr *metrics = (struct rtattr *)(((char *)&add) + NLMSG_ALIGN(add.nh.nlmsg_len));
    metrics->rta_type = RTA_METRICS;
    metrics->rta_len = RTA_LENGTH(0);
    struct rtattr *mt = (struct rtattr *)((char *)metrics + RTA_LENGTH(0));
    uint32_t expire = cfg.route_expire;
    mt->rta_type = RTAX_EXPIRES;
    mt->rta_len = RTA_LENGTH(sizeof(expire));
    memcpy(RTA_DATA(mt), &expire, sizeof(expire));
    metrics->rta_len = RTA_LENGTH(RTA_LENGTH(sizeof(expire)));
    add.nh.nlmsg_len = NLMSG_ALIGN(add.nh.nlmsg_len) + metrics->rta_len;

    if (sendto(rtsock, &add, add.nh.nlmsg_len, 0, (struct sockaddr *)&nladdr, sizeof(nladdr)) < 0) {
        struct in_addr addr; addr.s_addr = subnet;
        syslog(LOG_WARNING, "Failed to add route for %s/24 (domain: %s): %s",
               inet_ntoa(addr), domain, strerror(errno));
        result = -1;
    } else {
        struct in_addr addr; addr.s_addr = subnet;
        syslog(LOG_INFO, "Route added for %s/24 (domain: %s) via %s",
               inet_ntoa(addr), domain, gateway);
        add_ip_cache_with_expire(subnet, time(NULL) + cfg.route_expire);
    }

    close(rtsock);
    return result;
}

#elif defined(__FreeBSD__)

int add_route_via_pfroute(uint32_t ip, const char *domain, const char *gateway) {
    uint32_t subnet = get_subnet_24(ip);
    int result = 0;

    // Проверяем кэш перед любыми операциями с сокетом
    if (is_ip_cached(subnet)) {
        return 0;
    }

    int rtsock = socket(PF_ROUTE, SOCK_RAW, 0);
    if (rtsock < 0) {
        syslog(LOG_ERR, "PF_ROUTE socket failed: %s", strerror(errno));
        return -1;
    }

    // Используем текущее время в микросекундах для уникального seq
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint32_t seq = (tv.tv_sec * 1000000 + tv.tv_usec) & 0x7FFFFFFF;

    // Подготовка запроса RTM_GET
    char buf[512];
    struct rt_msghdr *rtm = (struct rt_msghdr *)buf;
    struct sockaddr_in *dst = (struct sockaddr_in *)(rtm + 1);

    memset(buf, 0, sizeof(buf));
    rtm->rtm_msglen = sizeof(struct rt_msghdr) + sizeof(struct sockaddr_in);
    rtm->rtm_version = RTM_VERSION;
    rtm->rtm_type = RTM_GET;
    rtm->rtm_addrs = RTA_DST | RTA_NETMASK;
    rtm->rtm_pid = getpid();
    rtm->rtm_seq = seq;

    dst->sin_len = sizeof(struct sockaddr_in);
    dst->sin_family = AF_INET;
    dst->sin_addr.s_addr = subnet;

    // Добавляем маску подсети в запрос
    struct sockaddr_in *netmask = (struct sockaddr_in *)(dst + 1);
    netmask->sin_len = sizeof(struct sockaddr_in);
    netmask->sin_family = AF_INET;
    netmask->sin_addr.s_addr = htonl(0xFFFFFF00);  // Маска /24

    rtm->rtm_msglen += sizeof(struct sockaddr_in);

    if (write(rtsock, buf, rtm->rtm_msglen) < 0) {
        struct in_addr addr;
        addr.s_addr = subnet;
        syslog(LOG_DEBUG, "No route found for %s/24 (domain: %s), will add", inet_ntoa(addr), domain);
        goto add_route;  // Маршрут не найден, добавляем
    }

    ssize_t n;
    do {
        n = read(rtsock, buf, sizeof(buf));
    } while (n > 0 && rtm->rtm_seq != seq);  // Пропускаем сообщения не для нас

    if (n > 0) {
        if (rtm->rtm_errno) {
            goto add_route;  // Маршрут не найден, добавляем
        }

        // Проверяем флаги маршрута
        if (!(rtm->rtm_flags & RTF_GATEWAY)) {
            goto add_route;  // Нет шлюза, добавляем свой маршрут
        }

        // Проверяем шлюз
        struct sockaddr *sa = (struct sockaddr *)(rtm + 1);
        struct sockaddr_in *gw = NULL;
        int addrs = rtm->rtm_addrs;

        for (int i = 0; i < RTAX_MAX; i++) {
            if (addrs & (1 << i)) {
                if (i == RTAX_GATEWAY && sa->sa_family == AF_INET) {
                    gw = (struct sockaddr_in *)sa;
                    break;
                }
                sa = (struct sockaddr *)((char *)sa + sa->sa_len);
            }
        }

        if (gw != NULL) {
            char gwbuf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &gw->sin_addr, gwbuf, sizeof(gwbuf));

            struct in_addr addr;
            addr.s_addr = subnet;

            if (strcmp(gwbuf, gateway) == 0) {
                // Маршрут уже существует через наш шлюз
                syslog(LOG_DEBUG, "Route for %s/24 (domain: %s) already exists via our gateway",
                       inet_ntoa(addr), domain);
                time_t now = time(NULL);
                time_t expire = now + cfg.route_expire; // Use configured expiration time
                if (rtm->rtm_rmx.rmx_expire > 0) {
                    expire = rtm->rtm_rmx.rmx_expire;
                }
                add_ip_cache_with_expire(subnet, expire);
                close(rtsock);
                return 0;
            }

            if (rtm->rtm_flags & RTF_STATIC) {
                // Существует статический маршрут через другой шлюз
                syslog(LOG_WARNING, "Route for %s/24 (domain: %s) exists via different gateway: %s",
                       inet_ntoa(addr), domain, gwbuf);
                close(rtsock);
                return -1;
            }
        }
    }

add_route:
    ;  // Пустой оператор после метки

    // Добавление маршрута для подсети /24
    struct {
        struct rt_msghdr hdr;
        struct sockaddr_in dst;
        struct sockaddr_in gw;
        struct sockaddr_in netmask;
    } msg;

    memset(&msg, 0, sizeof(msg));
    msg.hdr.rtm_msglen = sizeof(msg);
    msg.hdr.rtm_version = RTM_VERSION;
    msg.hdr.rtm_type = RTM_ADD;
    msg.hdr.rtm_flags = RTF_UP | RTF_GATEWAY | RTF_STATIC;  // Убрали RTF_PROTO1
    msg.hdr.rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
    msg.hdr.rtm_pid = getpid();
    msg.hdr.rtm_seq = seq + 1;  // Увеличиваем seq для нового сообщения
    msg.hdr.rtm_inits = RTV_EXPIRE;
    msg.hdr.rtm_rmx.rmx_expire = time(NULL) + cfg.route_expire;

    msg.dst.sin_len = sizeof(struct sockaddr_in);
    msg.dst.sin_family = AF_INET;
    msg.dst.sin_addr.s_addr = subnet;

    msg.gw.sin_len = sizeof(struct sockaddr_in);
    msg.gw.sin_family = AF_INET;
    inet_pton(AF_INET, gateway, &msg.gw.sin_addr);

    msg.netmask.sin_len = sizeof(struct sockaddr_in);
    msg.netmask.sin_family = AF_INET;
    msg.netmask.sin_addr.s_addr = htonl(0xFFFFFF00);

    struct in_addr addr;
    addr.s_addr = subnet;

    if (write(rtsock, &msg, sizeof(msg)) < 0) {
        syslog(LOG_WARNING, "Failed to add route for %s/24 (domain: %s): %s",
               inet_ntoa(addr), domain, strerror(errno));
        result = -1;
    } else {
        // Ждем подтверждения добавления маршрута
        ssize_t n;
        do {
            n = read(rtsock, buf, sizeof(buf));
            rtm = (struct rt_msghdr *)buf;
        } while (n > 0 && rtm->rtm_seq != msg.hdr.rtm_seq);  // Ждем наше сообщение

        if (n > 0 && rtm->rtm_errno == 0) {
            syslog(LOG_INFO, "Route added for %s/24 (domain: %s) via %s",
                   inet_ntoa(addr), domain, gateway);
            time_t expire = time(NULL) + cfg.route_expire;
            if (rtm->rtm_rmx.rmx_expire > 0) {
                expire = rtm->rtm_rmx.rmx_expire;
            }
            add_ip_cache_with_expire(subnet, expire);
        } else {
            syslog(LOG_WARNING, "Route add confirmation failed for %s/24 (domain: %s): %s",
                   inet_ntoa(addr), domain, rtm->rtm_errno ? strerror(rtm->rtm_errno) : "No response");
            result = -1;
        }
    }

    close(rtsock);
    return result;
}

#endif /* __linux__ / __FreeBSD__ */


int parse_dns_query(char *packet, ssize_t len, char *qname) {
    if (len < 12) return 0;
    int pos = 12;
    int i = 0;
    while (pos < len && packet[pos] != 0 && i < 255) {
        int label_len = packet[pos++];
        if (label_len + pos > len) return 0;
        for (int j = 0; j < label_len && i < 255; j++) {
            qname[i++] = packet[pos++];
        }
        qname[i++] = '.';
    }
    if (i > 0) qname[i - 1] = '\0';
    return 1;
}

static int skip_name(char *packet, ssize_t len, int pos) {
    while (pos < len) {
        unsigned char c = (unsigned char)packet[pos];
        if (c == 0) {
            return pos + 1;
        }
        if ((c & 0xC0) == 0xC0) {
            if (pos + 1 < len) {
                return pos + 2;
            }
            return len;
        }
        pos += c + 1;
    }
    return len;
}

int extract_ips_from_response(char *packet, ssize_t len, uint32_t *ips, int max_ips) {
    if (len < 12) return 0;
    int qdcount = ntohs(*(uint16_t*)(packet + 4));
    int ancount = ntohs(*(uint16_t*)(packet + 6));
    int nscount = ntohs(*(uint16_t*)(packet + 8));
    int arcount = ntohs(*(uint16_t*)(packet + 10));
    int pos = 12;

    for (int i = 0; i < qdcount; i++) {
        pos = skip_name(packet, len, pos);
        pos += 4;
    }

    int found = 0;
    for (int i = 0; i < ancount && found < max_ips; i++) {
        pos = skip_name(packet, len, pos);
        if (pos + 10 > len) break;
        uint16_t type = ntohs(*(uint16_t*)(packet + pos));
        uint16_t rdlen = ntohs(*(uint16_t*)(packet + pos + 8));
        if (type == 1 && rdlen == 4 && pos + 14 <= len) {
            memcpy(&ips[found], packet + pos + 10, 4);
            found++;
        }
        pos += 10 + rdlen;
    }

    for (int i = 0; i < nscount; i++) {
        pos = skip_name(packet, len, pos);
        if (pos + 10 > len) break;
        uint16_t rdlen = ntohs(*(uint16_t*)(packet + pos + 8));
        pos += 10 + rdlen;
    }

    for (int i = 0; i < arcount && found < max_ips; i++) {
        pos = skip_name(packet, len, pos);
        if (pos + 10 > len) break;
        uint16_t type = ntohs(*(uint16_t*)(packet + pos));
        uint16_t rdlen = ntohs(*(uint16_t*)(packet + pos + 8));
        if (type == 1 && rdlen == 4 && pos + 14 <= len) {
            memcpy(&ips[found], packet + pos + 10, 4);
            found++;
        }
        pos += 10 + rdlen;
    }

    return found;
}

void dns_read_cb(evutil_socket_t fd, short events, void *arg) {
    char buf[512];
    struct sockaddr_in cli;
    socklen_t slen = sizeof(cli);
    int up = -1;

    ssize_t len = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&cli, &slen);
    if (len <= 0)
        goto out;

    char qname[256] = {0};
    parse_dns_query(buf, len, qname);

    struct gateway_config *gw = NULL;
    int match = domain_matches(qname, &gw);
    syslog(LOG_DEBUG, "Query %s match=%d", qname, match);

    // Проксируем всегда
    up = socket(AF_INET, SOCK_DGRAM, 0);
    if (up < 0)
        goto out;

    struct sockaddr_in upstream;
    upstream.sin_family = AF_INET;
    upstream.sin_port = htons(53);
    inet_pton(AF_INET, cfg.upstream_dns, &upstream.sin_addr);

    sendto(up, buf, len, 0, (struct sockaddr *)&upstream, sizeof(upstream));
    struct timeval tv = {5, 0};  // Increased timeout to 5 seconds
    setsockopt(up, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ssize_t rlen = recv(up, buf, sizeof(buf), 0);

    if (rlen > 0) {
        sendto(fd, buf, rlen, 0, (struct sockaddr *)&cli, slen);

        // Если домен в блоклисте, обработаем IP
        if (match) {
            uint32_t ips[10];
            int n = extract_ips_from_response(buf, rlen, ips, 10);
            syslog(LOG_DEBUG, "Extracted %d IPs for %s", n, qname);
            if (n <= 0) {
                syslog(LOG_DEBUG, "No IP addresses for %s, skipping route", qname);
            } else {
                // Группируем IP по подсетям для оптимизации
                uint32_t subnets[10];
                int unique_subnets = 0;

                for (int i = 0; i < n; ++i) {
                    uint32_t subnet = get_subnet_24(ips[i]);

                    // Проверяем, не обработали ли мы уже эту подсеть
                    int found = 0;
                    for (int j = 0; j < unique_subnets; j++) {
                        if (subnets[j] == subnet) {
                            found = 1;
                            break;
                        }
                    }

                    if (!found) {
                        subnets[unique_subnets++] = subnet;
                    }
                }

                // Обрабатываем уникальные подсети
                for (int i = 0; i < unique_subnets; ++i) {
                    struct in_addr addr;
                    addr.s_addr = subnets[i];
                    if (is_ip_cached(subnets[i])) {
                        syslog(LOG_DEBUG, "Subnet %s for %s cached, skipping route", inet_ntoa(addr), qname);
                        continue;
                    }
                    // Используем любой IP из этой подсети
                    for (int j = 0; j < n; ++j) {
                        if (get_subnet_24(ips[j]) == subnets[i]) {
                            if (add_route_via_pfroute(ips[j], qname, gw->gateway) != 0) {
                                syslog(LOG_DEBUG, "Failed to add route for %s via %s", qname, gw->gateway);
                            }
                            break;
                        }
                    }
                }
            }
        }
    }

out:
    if (up >= 0)
        close(up);
    cleanup_ip_cache();
}

int main() {
    openlog("dnsproxy", LOG_PID|LOG_NDELAY, LOG_DAEMON);
    load_config();
    load_blocklist();
    
    evbase = event_base_new();

    struct sigaction sa = {0};
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);

    struct event *sighup_ev = evsignal_new(evbase, SIGHUP, sighup_handler, NULL);
    event_add(sighup_ev, NULL);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    int reuse = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(cfg.listen_port);
    inet_pton(AF_INET, cfg.listen_address, &addr.sin_addr);
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        syslog(LOG_ERR, "Failed to bind: %s", strerror(errno));
        exit(1);
    }
    dns_event = event_new(evbase, sockfd, EV_READ|EV_PERSIST, dns_read_cb, NULL);
    event_add(dns_event, NULL);

    syslog(LOG_INFO, "dnsproxy started on %s:%d", cfg.listen_address, cfg.listen_port);
    event_base_dispatch(evbase);
    return 0;
}
