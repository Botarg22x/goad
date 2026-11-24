# Локальный стенд GitLab CE

Compose-файл хранится рядом с остальным проектом. Стенд предназначен для Kali
Linux и доступен только на этом компьютере по `http://gitlab.test:8082`.

Перед запуском проверьте свободное место в Docker: облегчённому GitLab нужно
как минимум 20 ГБ доступного хранилища. Если места меньше, сначала освободите
его или перенесите Docker на другой Linux-раздел. Не размещайте рабочие данные
GitLab на NTFS-разделе проекта.

```bash
df -h /var/lib/docker
```

Добавьте строку `127.0.0.1 gitlab.test` в `/etc/hosts`, затем выполните из
папки `gitlab`:

```bash
sudo docker compose config --quiet
sudo docker compose up -d
sudo docker compose ps
```

Первый запуск может занять несколько минут. Состояние видно в журнале:

```bash
sudo docker compose logs -f gitlab
```

После изменения `compose.yaml` пересоздайте контейнер без удаления томов:

```bash
sudo docker compose up -d --force-recreate gitlab
sudo docker compose ps
```

Откройте `http://gitlab.test:8082/users/sign_in`. Логин администратора —
`root`. Начальный пароль покажет команда (не публикуйте его в отчётах):

```bash
sudo docker compose exec gitlab cat /etc/gitlab/initial_root_password
```

Данные находятся в именованных томах Docker: `docker compose down` их не
удаляет, но при переносе одной папки проекта на другой компьютер они сами не
переедут. Для резервного копирования GitLab нужен архив приложения **и** файл
`/etc/gitlab/gitlab-secrets.json`; восстановление делайте на той же версии CE.

Остановить стенд без удаления данных:

```bash
sudo docker compose down
```
