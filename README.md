# GOAD

GOAD объединяет четыре самостоятельных CLI-модуля: генерацию парольных
кандидатов (`passgen`), сбор ФИО и e-mail (`logingen`), поиск страниц входа
(`pointfinder`) и проверку входа (`authchecker`). Общая команда `goad` запускает
те же модули; `goad run` — дополнительный способ объединить этапы.

Используйте проект только для систем, на проверку которых у вас есть разрешение.

## Установка на Linux

Нужен Python 3.11+. Из корня проекта:

```bash
python3 install_workspace.py --venv .venv-linux
source .venv-linux/bin/activate
goad doctor
```

Установщик ставит Python-пакеты в редактируемом режиме. Для активного обхода
дополнительно нужен [Katana](https://github.com/projectdiscovery/katana) в `PATH`;
Nmap и Subfinder нужны только при явном выборе этих инструментов. Локальные
копии исполняемых файлов и браузерные профили в репозиторий не входят.

После активации окружения доступны `goad`, `passgen`, `logingen`, `pointfinder`
и `authchecker`. Проверка параметров установки без изменений:
`python3 install_workspace.py --venv .venv-linux --dry-run`.

## Основной порядок работы

```bash
goad passwords -p 'Admin?d?d' -o passwords.txt --plan
goad logins --domain example.ru --company 'Пример'
goad discover -u https://example.ru --links-output auth-links.txt
goad check -u auth-links.txt -l admin -p passwords.txt --slow
```

`logins` без `-u` использует внешние источники; с `-u` активно обходит сайт.
`discover` по умолчанию запускает Katana и проверку типовых путей. `check`
получает готовые страницы входа или отчёт PointFinder и не обходит сайт заново.
Если нужна только проверка одной известной страницы, передайте её в `check -u`.

Дополнительный запуск нескольких этапов:

```bash
goad run -u https://example.ru --collect-logins --collect-points --slow
```

Пароль здесь не указан, поэтому попыток входа не будет. Подробности и точные
параметры каждого модуля: `goad -h`, `goad passwords -h`, `goad logins -h`,
`goad discover -h`, `goad check -h`, `goad run -h`.

## Результаты и безопасность

Типовые папки результатов, журналы авторизации и профили браузера исключены
из Git. Если задать результату произвольное имя вне этих папок, проверьте
его перед `git add`: в URL и журналах могут оказаться токены, а в консольном
выводе проверки — найденные пароли. Для демонстрации используйте собственный
стенд и тестовые учётные данные.

Шаблоны распознавания продуктов находятся в
[`discovery_module_3/src/authpoints/data/login_templates/`](discovery_module_3/src/authpoints/data/login_templates/).
После изменения шаблона повторите поиск точек, чтобы обновить отчёт.

## Стенды для демонстрации

Для проверки на настоящих продуктах есть локальные стенды
[GitLab](gitlab/README.md), [WordPress](wordpress/README.md) и инструкция для
[Bitrix](bitrix/README.md). Они работают в Docker и не требуются для установки
самой GOAD. Тестовые учётные данные и содержимое контейнеров в GitHub не
публикуйте. При остановке через `docker compose down` данные в именованных
томах сохраняются.

## Публикация

Пошаговая инструкция по первой загрузке проекта на GitHub — в
[PUBLISHING.md](PUBLISHING.md). Сначала проверьте список файлов для коммита;
сам по себе `.gitignore` не гарантирует, что случайно добавленный секрет не
попадёт в публичный репозиторий.
