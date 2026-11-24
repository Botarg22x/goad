# Локальный стенд Bitrix

Для тестирования используется [официальное окружение Bitrix
`env-docker`](https://github.com/bitrix-tools/env-docker), а не копия продукта
в репозитории GOAD. Папка `bitrix/env-docker/` исключена из Git: там будут
локальные секреты и скачанный сайт. Окружение предназначено для разработки,
не для продакшена.

Из корня GOAD скачайте окружение один раз:

```bash
cd bitrix
git clone https://github.com/bitrix-tools/env-docker.git env-docker
cd env-docker
```

Перед первым запуском откройте `.env_mysql`, `.env_postgresql` и `.env_push`.
Замените соответственно `CHANGE_MYSQL_ROOT_PASSWORD_HERE`,
`CHANGE_POSTGRESQL_POSTGRES_PASSWORD_HERE` и `CHANGE_SECURITY_KEY_HERE` на
собственные случайные значения. Они останутся только в игнорируемой папке.
Подробности приведены в [инструкции окружения](https://github.com/bitrix-tools/env-docker#readme).

Для локального стенда ограничьте доступ с других компьютеров: в
`docker-compose.yml`, в сервисе `nginx`, замените строки `8588:80` и
`8589:443` на такой блок:

```yaml
ports:
  - "127.0.0.1:8588:80"
  - "127.0.0.1:8589:443"
```

Затем запустите контейнеры из папки `bitrix/env-docker`:

```bash
sudo docker compose config --quiet
sudo docker compose up -d
sudo docker compose ps
```

Установочный скрипт скачивается в контейнер PHP по [инструкции
Bitrix](https://dev.1c-bitrix.ru/learning/course/index.php?COURSE_ID=34&LESSON_ID=33158&LESSON_PATH=33134.33158):

```bash
sudo docker compose exec --user=bitrix php sh -c 'cd /opt/www && wget https://www.1c-bitrix.ru/download/scripts/bitrixsetup.php'
```

Откройте `http://127.0.0.1:8588/bitrixsetup.php` и завершите установку
демоверсии в браузере. После установки удалите установочный скрипт из
контейнера:

```bash
sudo docker compose exec --user=bitrix php sh -c 'rm -f /opt/www/bitrixsetup.php'
```

Адрес сайта: `http://127.0.0.1:8588/`; административный вход обычно находится
по адресу `http://127.0.0.1:8588/bitrix/admin/`. Для теста GOAD используйте
только учётную запись, которую создали в этом стенде.

Остановить стенд без удаления томов:

```bash
sudo docker compose down
```

Не используйте `down -v`, если хотите сохранить установленный сайт и БД.
