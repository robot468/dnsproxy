# dnsproxy

Работает под FreeBSD и Linux

Dns proxy for domain based routing

Простой DNS-прокси с возможностью добавлять маршруты через разные шлюзы для
разных доменных списков. Формат `dnsproxy.conf` теперь поддерживает несколько
блоков:

```
listen_address = 127.0.0.1
listen_port = 5300
upstream_dns = 8.8.8.8
route_expire = 86400

gateway = 10.0.0.1
blocked_domains_file = /usr/local/etc/blocklist1.txt
blocked_domains_file = /usr/local/etc/blocklist2.txt

gateway = 10.0.0.2
blocked_domains_file = /usr/local/etc/blocklist_other.txt
```

Если домен в списке начинается с точки, блокируются также поддомены. Без точки
соответствие только точное.

При обработке ответов извлекаются IP-адреса как из answer-, так и из
additional-секций DNS.

## Тесты

Собрать и запустить встроенные тесты можно так:

```
./configure
make test
```

## remove_temp_routes.sh

Скрипт `remove_temp_routes.sh` удаляет временные маршруты, у которых задано
время истечения (expires). Использует `netstat` и `route` из базовой системы
FreeBSD, требуются привилегии root.

