# Первая публикация GOAD на GitHub

Эти команды выполняются на вашем Linux-компьютере из корня проекта. Они не
создают репозиторий на GitHub автоматически: сначала создайте там **пустой**
репозиторий `goad` без README, `.gitignore` и лицензии. Для первого просмотра
лучше выбрать видимость Private; позднее её можно изменить.

Перейдите в корень своей копии GOAD и создайте локальный репозиторий:

```bash
git init -b main
git status --short
```

Если `git init` сообщает об ошибке доступа к `.git`, не удаляйте эту папку
вслепую: проверьте её владельца и права командой `ls -ld .git`. Если папка
принадлежит вам, но у владельца нет права записи, выполните `chmod u+w .git`
и повторите `git init -b main`. В текущей копии проекта до инициализации
`git status` может сообщать `not a git repository`.

Перед добавлением файлов посмотрите, что попадёт в первый коммит:

```bash
git add --dry-run .
```

В списке не должно быть `.env`, ключей, журналов, отчётов, скачанных
документов, результатов проверки, браузерных профилей и `bitrix/env-docker/`.
Особенно проверьте новые файлы, которые не покрывает `.gitignore`.

Если список верный:

```bash
git add .
git diff --cached --name-only
git commit -m 'Initial GOAD release'
git remote add origin https://github.com/USERNAME/goad.git
git push -u origin main
```

Замените `USERNAME` на свой логин GitHub. При входе через HTTPS GitHub
запросит действующий способ аутентификации; пароль от сайта в Git не вводят.
Если `origin` уже существует, сначала посмотрите `git remote -v`, а не
добавляйте второй.

После отправки откройте репозиторий в браузере и убедитесь, что видны исходный
код, три инструкции стендов и справки, но не результаты запусков и секреты.
Официальное руководство: [Adding locally hosted code to
GitHub](https://docs.github.com/en/migrations/importing-source-code/using-the-command-line-to-import-source-code/adding-locally-hosted-code-to-github?platform=linux).
