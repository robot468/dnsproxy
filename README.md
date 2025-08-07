# dnsproxy

Поддерживаются FreeBSD и Linux. Перед сборкой убедитесь, что установлены заголовки
и библиотеки [libevent](https://libevent.org/) (например, пакет `libevent-dev` в
Debian/Ubuntu). Затем запустите `./configure`, который сгенерирует подходящий
Makefile.

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

## remove_temp_routes.sh

Скрипт `remove_temp_routes.sh` удаляет временные маршруты, у которых задано
время истечения (expires). На Linux используется утилита `ip`, на FreeBSD —
`netstat` и `route`. Для выполнения требуются привилегии root.

