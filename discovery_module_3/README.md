# PointFinder

`PointFinder` — третий модуль дипломного проекта: он обнаруживает точки
авторизации, но не пытается авторизоваться.

Модуль умеет:

- запускать service/version scan Nmap и читать его XML;
- по явному флагу выполнять отдельный UDP-проход Nmap;
- строить web seed URL из найденных HTTP/HTTPS-сервисов;
- пассивно находить поддомены через Subfinder и передавать их web-этапам;
- запускать Katana в ограниченном scope и читать JSONL;
- автоматически извлекать URL из JavaScript и точечно отрисовывать в Chromium
  стартовые страницы и кандидаты на JS-авторизацию;
- проверять явно переданные URL только методом `GET`;
- находить HTML-формы входа, HTTP Basic/Digest/Negotiate challenge, auth gate,
  клиентские JS-логинки по сочетанию точного auth-пути и маркеров login-компонента,
  SSO/OAuth URL и сетевые поверхности remote access, file sharing, directory,
  mail, database, AAA, messaging, management, VPN и infrastructure;
- объединять дубликаты и формировать объяснимый JSON-отчёт;
- анализировать уже готовые XML/JSONL без установленных Nmap и Katana.

Основной синтаксис CLI:

```text
pointfinder -u https://example.test/ --slow
pointfinder -u urls.txt --slow
```

По умолчанию запускаются Katana и проверка стандартных путей. Nmap и Subfinder
не запускаются; их старые настройки сохранены для явного выбора через `-t`.
Файл в `-u` должен содержать полные HTTP(S) URL, по одному на строку; поддерживаются
UTF-8/BOM, пустые строки и комментарии `#`. `--no-standard-paths` оставляет только
Katana, `--no-katana` — только пути. `--page-only` отключает
обход и стандартные пути. Явный `-t` выбирает только указанные инструменты.

В `-t/--tools` через запятую перечисляются внешние инструменты, которые нужно
использовать: `katana`, `nmap`, `subfinder` или их комбинацию. Для Katana вместо хоста передаётся полный
URL. Цель можно также указать явно через `-u`, например
`pointfinder -u https://example.test/ --tools katana`. Старые домен/IP/CIDR в `-u`
поддерживаются с явным выбором инструментов через `-t`. Несколько целей можно
перечислить позиционно, повторить `-u` либо загрузить из UTF-8-файлов
`--targets-file`/`--urls-file`, по одной записи на строку. Результат
записывается в JSON и в одноимённый TXT со списком найденных endpoint по одному
на строку. Путь TXT можно изменить через `--links-output`. Каждая новая находка
сразу выводится в консоль с префиксом `[FOUND]`. Формальный контракт версии 2.0 находится в
[`src/authpoints/report.schema.json`](src/authpoints/report.schema.json) и
включается в установленный wheel. Установленный CLI выводит ту же схему командой
`pointfinder --schema`.

## Шаблоны форм входа

```bash
pointfinder --list-templates
pointfinder -u urls.txt -t wordpress --slow
pointfinder -u urls.txt -t bitrix,roundcube,zimbra,owa --slow
```

Шаблоны редактируются отдельно: по одному YAML-файлу для продукта в
[`src/authpoints/data/login_templates/`](src/authpoints/data/login_templates/).
Например, [`wordpress.yaml`](src/authpoints/data/login_templates/wordpress.yaml)
и [`bitrix.yaml`](src/authpoints/data/login_templates/bitrix.yaml).
Все `.yaml`/`.yml` в каталоге подключаются автоматически; имена `id` должны быть
уникальными. `--list-templates` проверяет определения без сетевых запросов.
При синтаксической ошибке выводятся файл и строка; повторяющиеся ключи и `id`
не допускаются. При editable-установке переустановка после изменений не нужна.
[Инструкция по созданию шаблона и пример](src/authpoints/data/login_templates/README.md).

HTTP Basic не привязан к шаблону продукта или списку путей. Для точечной
проверки уже известного адреса используйте
`pointfinder -u https://example.test/private --page-only`: один GET,
без обхода ссылок. При обычном запуске Katana может найти такую страницу по
ссылке; ответ `401` с `WWW-Authenticate: Basic` станет находкой `http_basic`.
Если адрес нигде не указан на доступных страницах, передайте его явно.
PointFinder не отправляет учётные данные; найденный URL можно передать в
`goad check -u` для отдельной проверки входа.

Основной полный шаблон `bitrix` распознаёт административную страницу по блоку
`detection`, после чего использует описанный HTTP-запрос. Наличие одной `<form>`,
видимость/тип и уникальность полей не требуются. В отчёте явно указывается,
что параметры запроса взяты из шаблона. `paths` для него — `/bitrix/admin/`
и `/bitrix/admin/index.php`. Прежние формы сайта сохранены как `bitrix-site`.

Все YAML теперь имеют единый порядок: `id`, название, категория, `paths`,
`detection`, при известных правилах входа — `verification`. Для `bitrix` и
`gitlab` `detection` распознаёт всю страницу; для остальных продуктов он
описывает поля одной доступной HTML-формы и дополнительные `signals_any`.
Признаки продукта не доказывают его версию. Регистрация и смена пароля
по-прежнему отбрасываются общим классификатором.

| Шаблон | Поля логина / пароля | Пример дополнительного признака |
| --- | --- | --- |
| wordpress | `log` / `pwd` | строки `name="log"` и `name="pwd"` в HTML |
| bitrix | параметры HTTP `USER_LOGIN` / `USER_PASSWORD` | правила страницы админки в `detection`; форма не обязательна |
| gitlab | параметры HTTP `user[login]` / `user[password]` | JS-страница `/users/sign_in`; форма может быть скрыта |
| bitrix-site | `USER_LOGIN` / `USER_PASSWORD` | прежняя схема HTML-формы: путь `/bitrix/` или поля `AUTH_FORM` + `TYPE` |
| roundcube | `_user` / `_pass` | название Roundcube или поля `_task` + `_token` |
| zimbra | `username` / `password` | название Zimbra или поля `loginOp` + `login_csrf` |
| owa | `username` / `password` | путь `/owa/auth/` или название Outlook Web App |

Без фильтра работает и обычное распознавание неизвестных форм. `-t`/`--login-template`
принимает список через запятую и повторение флага. Фильтр ограничивает находки
в консоли/JSON/TXT и встроенный список путей, но не обход Katana: чтобы узнать тип
страницы, сначала нужно её загрузить. Пользовательский `--paths-file` не изменяется.
Нестандартные версии, облачный SSO и изменённые названия полей могут остаться
без тега; это не означает, что форма не существует.

Контракт отчёта 2.0 совместим со старыми потребителями: `auth_type=password_form`
не меняется, новые сведения находятся в `metadata.login_template`,
`metadata.tags`, `metadata.credential_fields`. В `evidence` сохраняется причина
срабатывания. Модуль 4 проверяет имена полей по отчёту и использует подсказку
в HTTP-адаптере и браузере. Шаблоны Bitrix, GitLab и WordPress дополнительно
передают `metadata.login_verification` версии `form-check/1`: запрос, обновление
сессии/CSRF и признаки результата. У `bitrix` POST идёт на указанный в YAML
путь `/bitrix/admin/?login=yes` (`action: fixed`); у `bitrix-site` и WordPress —
на action найденной формы. Cookies/токены получаются заново. CAPTCHA/MFA
останавливают проверку. OWA, Roundcube и Zimbra пока содержат только правила
распознавания, без продуктового запроса входа.
Модуль 4 читает сведения из отчёта, а не из YAML; после изменения определения
нужно повторить поиск для получения нового отчёта. Формат JSON-отчёта не изменился.

`-t bitrix` выбирает продукт. Для выбора инструментов вместо прежнего `-t katana`
теперь используется `--tools katana`. Внутренний запуск через `goad run`
обновлён на длинный флаг; Nmap/Subfinder сохранены, но по умолчанию не включены.

Полная цепочка со стандартной формой Bitrix на своём стенде:

```bash
pointfinder -u http://127.0.0.1:8080 -t bitrix --slow --output bitrix-report.json
authchecker plan --report bitrix-report.json --login student --password password123
authchecker run --live --report bitrix-report.json --login student --password password123 --audit bitrix-audit.jsonl --max-total 1 --slow --compact
```

Для внешнего разрешённого домена у `authchecker run` дополнительно нужен
`--scope-domain example.com` (и `--allow-subdomains`, если они включены в область).

Текст справки `pointfinder -h` хранится отдельно в
[`src/authpoints/data/cli_help.txt`](src/authpoints/data/cli_help.txt). `pointfinder -h`
печатает его целиком без автоматического изменения разметки. Заголовки, порядок,
отступы и описания можно редактировать свободно. Это меняет только справку, а не сами
флаги CLI. PointFinder читает файл при каждом запуске.

Во время работы PointFinder без буферизации показывает текущий этап: `[START]`,
`[SUBFINDER]`, `[NMAP]`, `[PATHS]`, `[KATANA]`, `[ANALYZE]`, `[FOUND]`, `[OUTPUT]` и `[DONE]`.
Ошибка инструмента или запроса сразу выводится с `[ERROR]` и сохраняется в
`issues` JSON-отчёта.

## Гарантии и границы

Использовать активное сканирование можно только для собственных систем или при
явном разрешении владельца.

Модуль не отправляет формы и не выполняет `POST`, не принимает логины, пароли,
cookies или заголовок `Authorization`. URL с `userinfo` отклоняются, logout-пути
не запрашиваются. URL с query-параметрами, включая токены, проверяются и
сохраняются в отчётах без маскировки. Отчёты нужно хранить как секретные данные.
Редиректы HTTP-инспектора разрешены только внутри scope. Обнаруженный на странице
внешний SSO URL может попасть в отчёт, но запрос к нему не выполняется. Явно
переданный оператором URL, напротив, сам считается разрешённой целью.

Модуль запускает отдельный процесс Katana для каждой заранее проверенной страницы
с `-d 1 -mdp 1 -dr`. Корневая страница запрашивается методом `GET`, а найденные
JSONL-записи проходят Python-проверку method/scope/credential/logout до следующего
breadth-first уровня. Дополнительная локальная canary-проверка не запускается.

Каждый процесс Katana получает новый cwd и изолированные user/config directories,
поэтому пользовательский Katana config, cookies предыдущего запуска и resume-файл
не наследуются. При `-t katana` PointFinder автоматически выполняет лёгкий обход с
JS-discovery, после чего открывает в Chromium стартовую страницу и только страницы-
кандидаты. Одинаковый site-wide login-маркер отрисовывается один раз на origin.
Если Katana вернула только исходный HTML, PointFinder дополнительно снимает DOM после
JavaScript через Playwright и передаёт его обычному анализатору форм. Для этого
установите `pointfinder[browser]` и Chromium (либо укажите Chrome через
`--katana-chrome`). Автоматическая отправка форм не выполняется.
`--katana-headless` принудительно переводит весь обход в браузерный режим, а
`--no-auto-headless` отключает автоматическую отрисовку. Automatic form fill,
auto-login и knowledge-base secret validation не включаются. Переменные `AUTH_CREDENTIALS`,
CAPTCHA solver и неявные proxy удаляются из окружения; используется только явно
переданный `--proxy`. URL с literal comma
проверяется собственным GET-инспектором, но не передаётся Katana: upstream
трактует запятую в input file как разделитель нескольких root URL.

Nmap выполняет service/version scan без NSE scripts. По умолчанию берутся
1000 наиболее распространённых портов; `-p-` явно включает все порты 1–65535. Это всё
же protocol probing, а не пассивный сбор. Файл probe payloads фиксируется через
официальный [`--versiondb`](https://nmap.org/book/man-misc-options.html);
`NMAPDIR` и пользовательские config directories изолируются. По
умолчанию используется `nmap-service-probes` рядом с доверенным binary или в
системном data directory. Для нестандартной установки путь нужно явно передать
через `--nmap-versiondb`.

По умолчанию выполняется TCP-поиск. `--nmap-udp` добавляет отдельный `-sU -sV`
проход для Kerberos, RADIUS, SNMP, IKE/OpenVPN и других UDP-поверхностей. UDP
обычно существенно медленнее TCP и на Unix может требовать raw-socket privileges,
поэтому он не включается неявно. Поведение `-sU` описано в официальной
[документации Nmap](https://nmap.org/book/man-port-scanning-techniques.html).

По умолчанию scope включает только точный hostname. Для Katana генерируется
точное правило на каждый разрешённый host, а не правило на весь registrable
domain. Поддомены исходного host разрешаются флагом `--include-subdomains` или
автоматически при выборе `-t subfinder`; соседние домены при этом не добавляются. Например,
`pointfinder -u https://example.test/ --tools katana --include-subdomains` разрешает
переходы на найденные ссылки `auth.example.test` и `a.auth.example.test`.
Если исходная цель — `www.example.test`, разрешаются только она и её поддомены
(`auth.www.example.test`), но не `auth.example.test` или `example.test`.
Сам `--include-subdomains` только расширяет область обхода. Subfinder выполняет
пассивное перечисление через открытые источники, без DNS brute-force. Результат
ограничивается `--subfinder-max-results` и сохраняется в
`config.subfinder.discovered_subdomains` отчёта. Найденные имена передаются Katana
и проверке стандартных путей, но не добавляются в отдельное сканирование Nmap.
Глубина и лимиты Katana продолжают действовать.
Сети более 4096
адресов — в том числе несколько CIDR с суммарно большим числом адресов — требуют
отдельного `--allow-large-networks`. Синтаксис Nmap octet-range намеренно не
поддерживается: диапазоны нужно записывать как проверяемые CIDR.

## Требования

- Python 3.11+;
- [Nmap](https://nmap.org/download.html) для активного поиска сервисов;
- [ProjectDiscovery Katana](https://github.com/projectdiscovery/katana#installation)
  1.6.1+ (используется лимит страниц `-mdp`) для активного web crawling.
- [ProjectDiscovery Subfinder](https://github.com/projectdiscovery/subfinder) для
  пассивного поиска поддоменов;
- Chromium в `katana/chromium` или системный Chrome для автоматического поиска
  JS-логинок (его можно отключить через `--no-auto-headless`).

XML выбран как стабильный программный формат, рекомендованный официальной
[документацией Nmap](https://nmap.org/book/output-formats-xml-output.html).
Параметры scope, JSONL и form extraction сверены с официальным
[описанием Katana](https://github.com/projectdiscovery/katana#usage).

## Установка для разработки

PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e .
pointfinder --doctor
```

Bash (Linux/macOS):

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
pointfinder --doctor
```

Проект не имеет сторонних Python-зависимостей. Если editable install пока не
нужен, команды можно запускать так:

```powershell
$env:PYTHONPATH = "src"
python -m pointfinder --doctor
```

## Использование

Проверить готовые страницы без обхода ссылок и типовых путей:

```bash
pointfinder --urls-file login-urls.txt --page-only \
  --output reports/page-report.json \
  --links-output reports/page-links.txt
```

В файле должен быть один полный `http://` или `https://` URL на строку. Режим
сначала делает HTTP GET и разрешённые редиректы внутри scope. Если точка входа
не найдена, он проверяет ту же страницу в браузере. Обход ссылок, стандартные
пути и отправка логинов с паролями не запускаются.

В `--page-only` и при обычном обходе проверяются URL с `access_token` и другими
параметрами запроса. Отдельный разрешающий флаг не нужен. GET может
использовать или погасить одноразовый токен; проверяйте только свои или
разрешённые страницы. Полные URL с токенами остаются в отчёте и консоли;
исходный файл URL не меняется. Переходы за пределы scope запрещены.

Проверить один URL через Katana, если требуется JS-анализ:

```powershell
pointfinder https://example.test/login --tools katana --katana-depth 1
```

Nmap и Katana вместе:

```powershell
pointfinder https://example.test --tools katana,nmap --output reports\pointfinder.json
```

Эта команда автоматически передаёт `example.test` в Nmap, обходит сайт Katana,
извлекает URL из JavaScript и точечно запускает
Chromium для возможных JS-форм входа.

Только Katana — обязательно с полным URL:

```powershell
pointfinder https://example.test --tools katana
```

Только Nmap:

```powershell
pointfinder 192.0.2.10 --tools nmap
```

В Bash синтаксис тот же:

```bash
pointfinder example.test --tools katana,nmap \
  --urls-file urls.txt \
  --output reports/pointfinder.json
```

### Как распознаются цели

- значение с `http://` или `https://` считается начальным URL для Katana,
  например `https://example.test:8443/admin`;
- hostname, IP или CIDR без схемы считается целью Nmap и границей scope, например
  `example.test`, `192.0.2.10` или `192.0.2.0/28`;
- если выбран Nmap, hostname/IP из переданного URL также автоматически добавляется
  в его цели. Порт из URL не ограничивает портовый scan.

Цели можно задавать позиционно, через повторяемый `-u` или файлами:

```text
pointfinder -u example.test --tools nmap
pointfinder -u https://example.test/ --tools katana,nmap
pointfinder -u https://one.example.test/ -u https://two.example.test/ --tools katana
```

Для запуска одной Katana без Nmap нужен URL со схемой `http://` или `https://`.
Старые флаги `--target` и `--url` также поддерживаются.

Пример файла целей:

```text
# targets.txt
192.0.2.10
example.test
192.0.2.0/28
```

URL-файл содержит по одному абсолютному `http://` или `https://` URL на строку:

```text
# urls.txt
https://example.test/
https://example.test/account/login
```

Пример объединения входов:

```powershell
pointfinder example.test 192.0.2.10 https://example.test/admin `
  --tools katana,nmap `
  --targets-file targets.txt `
  --urls-file urls.txt
```

### Поиск внешних утилит

В Windows PointFinder сначала ищет Nmap и Katana внутри проекта по путям
`.\nmap\nmap.exe` и `.\katana\katana.exe`, затем — по системному `PATH`. Проверить
окружение можно командой:

```powershell
pointfinder --doctor
```

Нестандартные пути задаются явно:

```powershell
pointfinder --doctor `
  --nmap-executable "C:\Tools\Nmap\nmap.exe" `
  --nmap-versiondb "C:\Tools\Nmap\nmap-service-probes" `
  --katana-executable "C:\Tools\Katana\katana.exe"
```

### Стандартные пути

Проверка стандартных путей **выключена по умолчанию**. Она включается
только явным `--paths-file`:

```powershell
pointfinder https://example.test/ --tools katana --paths-file standard_paths.txt
```

Список вынесен в отдельный редактируемый файл
[`standard_paths.txt`](standard_paths.txt). В нём один путь на строку; пустые строки и
комментарии с `#` игнорируются.

HTTP-код остался только внутренним механизмом проверки этих путей: он не
указывается в `-t`, не обходит сайт и не повторяет стартовый URL. Для каждого
пути он делает `GET` и передаёт полученный HTML в общий анализатор точек входа.
Стартовые страницы и найденные ссылки проверяет Katana.

Один User-Agent применяется к Katana и к внутренней проверке путей. По умолчанию
PointFinder представляется собственным именем; переопределить заголовок можно так:

```powershell
pointfinder https://example.test/ --tools katana `
  --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
```

### Перехват запросов через Burp

Общий HTTP-прокси задаётся один раз и применяется к Katana и к
внутренней проверке стандартных путей:

```powershell
pointfinder https://example.test/ --tools katana `
  --proxy http://127.0.0.1:8080
```

Также принимается короткая запись `--proxy 127.0.0.1:8080`. Nmap выполняет
TCP/UDP-сканирование напрямую и через HTTP-прокси не проходит. В Burp следует
выключить `Intercept`, если запросы не нужно подтверждать вручную. Для расшифровки
HTTPS сертификат Burp CA должен быть доверен операционной системой.

Пустые значения, переводы строк и управляющие символы отклоняются.

### Параметры Katana

- `-t katana` — использовать Katana; для запуска нужен полный URL;
- `--katana-depth 1..10` — число уровней; `1` означает только стартовые URL;
- `--katana-rate-limit N` — максимум запросов в секунду;
- `--katana-parallelism N` — число одновременных страниц и автоматических headless-кандидатов;
- `--katana-concurrency N` — параллельность внутри одного процесса Katana;
- `--katana-max-pages N` — лимит страниц на домен;
- `--katana-timeout N`, `--katana-request-timeout N` — таймауты в секундах;
- `--katana-js` — безопасный статический разбор JavaScript;
- `--katana-headless` — принудительно выполнить весь обход в локальном Chrome;
- `--katana-headless-timeout N` — таймаут одного автоматического headless-кандидата; по умолчанию 60 секунд;
- `--no-auto-headless` — не запускать точечную автоматическую отрисовку Chromium;
- `--katana-executable PATH` — явный путь к binary.
- `--user-agent TEXT` — общий User-Agent для Katana и проверки путей.
- `--proxy HTTP_URL` — общий HTTP-прокси для Katana и проверки путей; Nmap не затрагивает.

Для каждой обработанной страницы в консоль выводится строка вида
`[KATANA] HTTP 200 https://example.test/`. Ответы сервера `5xx` также сохраняются
в `issues` JSON-отчёта с URL и кодом ответа.

### Автоматический и принудительный headless-режим Katana

Обычная команда `-t katana` сначала делает быстрый HTML/JS-discovery и сразу
классифицирует результат. URL с уже извлечённой формой не отправляются в Chromium;
`js_login` без полей остаётся кандидатом на отрисовку.
Headless получает только неподтверждённые SPA, login-пути, кнопки, модальные окна и JS-маркеры.
Каждый кандидат изолирован в своём процессе, а до `--katana-parallelism N` кандидатов
выполняются одновременно. Таймаут одной страницы не останавливает остальные. Одинаковый
сайтовый login-маркер проверяется один раз на origin, а одинаковые формы объединяются по fingerprint.

Для принудительного браузерного обхода всех страниц используется:

```powershell
pointfinder https://example.test/ --tools katana `
  --katana-headless --katana-depth 2
```

PointFinder запускает Katana с `-hh -scp ... -xhr -fx`: Chromium выполняет
JavaScript, автоматически получает challenge-cookie и обнаруживает XHR endpoints.
Если в результате нет формы, Playwright отдельно снимет отрисованный DOM. Он
может открыть видимый переключатель «Sign in»/«Use password», но не вводит
идентификатор и не отправляет форму. Во время такого переключения блокируются
все новые сетевые запросы; при начальной загрузке блокируются методы, отличные
от GET/HEAD, и явные GET-адреса отправки OTP/кода. Все начальные URL обрабатываются
одним запуском браузера; cookie хранятся в изолированном временном профиле и
удаляются после завершения. Для разных доменов браузер применяет обычную изоляцию
cookie по домену. PointFinder не нажимает submit и не включает
Katana `-aff` или `-al`. Код страницы при этом может самостоятельно выполнять
фоновые API-запросы.

`--katana-js` и `--katana-headless` остаются ручными режимами: первый только
разбирает содержимое JS-файлов, второй действительно выполняет JavaScript на всём
обходе. Без этих флагов PointFinder сочетает оба этапа автоматически. `--proxy`
передаётся как HTTP-движку Katana, так и Chromium через
`proxy-server`, поэтому весь headless-трафик виден в прокси. Без `--proxy`
Chromium получает `no-proxy-server` и не подхватывает системный/Burp-прокси
неявно. Ошибка запуска браузера сохраняется в `issues`, а не выглядит как
успешная страница без находок.
`--ca-cert` применяется и к HTTP-проверке, и к снимку DOM после JavaScript:
в браузерном fallback разрешённые GET-ответы получает Python-клиент с проверкой
этого CA и передаёт их Chromium. Системное хранилище сертификатов не меняется,
проверка HTTPS не отключается. Принудительный полный обход Katana
`--katana-headless` остаётся отдельным режимом и не использует этот механизм.

На Windows PointFinder сначала ищет `katana/chromium/chrome.exe` и передаёт его
Katana через `-scp`. Поэтому Chromium хранится рядом с Katana, не скачивается при
каждом запуске и не удаляется вместе с временным профилем. Если локальной копии
нет, Katana получает `-sc` и пытается использовать системный Chrome.

### Параметры Nmap

- `-t nmap` — использовать Nmap; цель — домен, IP или CIDR;
- `--top-ports N` — количество наиболее распространённых TCP-портов;
- `-p-` — передать Nmap режим всех портов 1–65535; несовместим с `--top-ports`;
- `--nmap-timing 0..5` — шаблон скорости Nmap;
- `--nmap-timeout N` — общий таймаут в секундах;
- `--nmap-udp` — добавить отдельный UDP-проход;
- `--nmap-executable PATH` — явный путь к binary;
- `--nmap-versiondb PATH` — явный путь к `nmap-service-probes`.

## Скорость и глубина

Один из флагов `--slow`, `--normal` или `--fast` задаёт согласованный профиль
интенсивности. Без флага используется `--normal`:

| Профиль | Nmap | Katana req/s | Katana parallelism | Katana concurrency | Потоки путей |
|---|---:|---:|---:|---:|---:|
| `slow` | `-T2` | 1 | 1 | 1 | 1 |
| `normal` | `-T3` | 10 | 2 | 5 | 5 |
| `fast` | `-T4` | 50 | 4 | 10 | 10 |

Глубина не зависит от профиля и задаётся отдельно через `--katana-depth 1..10`.
Точные параметры имеют приоритет над preset:

```powershell
pointfinder --targets-file targets.txt --tools katana,nmap `
  --slow `
  --katana-depth 4 `
  --katana-rate-limit 5 `
  --katana-parallelism 2 `
  --katana-max-pages 500 `
  --paths-file standard_paths.txt `
  --paths-concurrency 4 `
  --nmap-timing 3 `
  --nmap-udp `
  --output reports\pointfinder.json
```

Дополнительно доступны `--top-ports`, `-p-`, `--nmap-timeout`, `--katana-timeout`,
`--katana-request-timeout`, `--katana-concurrency` и `--paths-timeout`. Все
фактические значения сохраняются в `config` JSON-отчёта для воспроизводимости.

Внешние инструменты выбираются через `-t nmap`, `-t katana` или
`-t katana,nmap`. Проверка путей включается отдельно через `--paths-file`, а JS parsing
Katana — через `--katana-js`.
IPv4/hostname и IPv6-цели Nmap обрабатываются отдельными запусками; для IPv6
автоматически добавляется `-6`. Большой список целей передаётся через временный
`-iL`-файл, поэтому не разворачивается в командную строку Windows.

Обычный режим находит статически наблюдаемые точки, а `--katana-js` дополнительно
разбирает JS-файлы. Для SPA, которые создают login UI только после выполнения
JavaScript, предназначен отдельный `--katana-headless`.

Коды завершения CLI: `0` — полный результат, `1` — `--doctor` обнаружил
неготовое окружение, `2` — ошибка входных данных/файлов, `3` — отчёт записан,
но содержит ошибки или предупреждения (`partial: true`).

Если отдельный адрес Katana недоступен или завершился ошибкой, успешные
результаты других адресов и предыдущих уровней сохраняются. Проблемные адреса
записываются в `issues`, а отчёт помечается `partial: true`. Такой отчёт можно
использовать для дальнейшей проверки найденных точек; наличие ошибки одного
поддомена не отменяет находки остальных.

## Отчёт

Окно входа может открываться на главной странице после нажатия «Войти».
Автоматический DOM-анализ раскрывает такие окна, в том числе кнопки
«I already have an account», допускает необходимые GET-загрузки внутри
области сайта и ожидает поле пароля. Формы, OTP и
отправка письма на этом этапе не выполняются. При ограниченном бюджете
редиректы и ссылки входа имеют приоритет над manifest/opensearch и ресурсами.

Если форма не появилась и большинство заблокированных скриптов относятся
к одному внешнему хосту, браузер один раз повторяет загрузку, разрешив
только JS/CSS с этого хоста. Внешние изображения, API-запросы и переходы
при этом остаются запрещены. Для других необходимых ресурсов повторяемый
`--browser-resource-domain cdn.example.ru` разрешает пассивные JS/CSS,
изображения и шрифты только с этого точного хоста. Он не расширяет область
переходов страниц, API-запросов или авторизации. Запрещённые запросы и ошибки
загрузки фиксируются в диагностике; отсутствие формы при таких ограничениях
отмечается как частичный результат.

В CLI DOM-снимки и JSON-диагностика сохраняются рядом с отчётом в
`discovery-debug`. Снимки очищены от значений полей, содержимого скриптов и
cookies, но полные URL с query-параметрами сохраняются. В `config.browser_diagnostics` доступны пути,
число раскрытий формы, наличие поля пароля, автоматически разрешённый
хост JS/CSS и причины блокировки запросов.
Снимки остаются вспомогательными артефактами: классификация выполняется по
исходному DOM в памяти. В программном API запись включается полем
`KatanaConfig.browser_diagnostics_dir`.

При `--output reports/report.json` создаются два файла:

- `reports/report.json` — полный структурированный отчёт для четвёртого модуля;
- `reports/report.txt` — найденные endpoint и страницы, на которых обнаружена
  та же форма, по одному уникальному URL на строку.

Другое имя текстового файла задаётся через `--links-output endpoints.txt`.
TXT не содержит все переданные URL и не показывает результат авторизации.
Пропущенные URL с причиной находятся в `issues` JSON-отчёта.
Пример сообщения в консоли:

```text
[FOUND] password_form https://example.test/login
```

Каждая находка содержит:

- `kind`: `web_login_page`, `http_auth_challenge`, `sso_entry` или
  `network_auth_surface`;
- `auth_type`: конкретный способ входа, например `password_form`,
  `passwordless_form`, `js_login`, `http_basic`, `oauth2`, `saml` или `ssh`;
- нормализованный `endpoint`, host, port и protocol;
- список правил `evidence`, объясняющий результат;
- источники (`nmap`, `katana`, `url_list`, `http_probe`);
- безопасные метаданные без HTML-тела и значений полей.

Находка создаётся только при подтверждении: настоящая password/passwordless
форма, сочетание точного login-пути и маркера клиентского login-компонента,
HTTP authentication challenge, параметры OAuth/OIDC, SAMLRequest, серверный
SSO redirect или открытый известный сетевой auth-сервис. Для сетевого
сервиса `evidence` различает подтверждение Nmap `-sV` и определение по
стандартному порту; `protocol_verified` показывает, был ли протокол подтверждён.
Название пути `/login` и текст страницы сами по себе находкой не считаются.
Logout, static assets, registration и password reset
подавляются. Страницы с ответами `404`, `410` и `5xx` отбрасываются;
`401`, `403` и `407` учитываются только вместе с authentication-заголовком.

## Тесты

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
```

Тесты отдельно проверяют XML/JSONL, scope, secret redaction, детектор форм,
HTTP challenge, SSO, изоляцию Nmap/Katana и GET-only orchestration. Локальный
HTTP-сервер фиксирует только `GET /` и `GET /login`: указанный формой `/session`
никогда не запрашивается.

## Структура

```text
src/authpoints/
  cli.py                 основной CLI и служебные флаги
  pipeline.py            orchestration and partial-result handling
  scope.py               explicit allowlist
  normalize.py           canonical URL and secret redaction
  runners/               fixed-argument Nmap/Katana wrappers
  parsers/               Nmap XML, Katana JSONL and HTML
  classifier.py          детерминированные правила подтверждения
  http_probe.py          scoped GET-only inspection
  models.py              report contract
tests/
```

Следующие решения зависят от интеграции с другими модулями: входной контракт
предыдущего модуля, JSON или SQLite как основной storage, нужен ли CSV, диапазон
портов, допустимость внешних IdP и необходимость headless crawling для SPA.
