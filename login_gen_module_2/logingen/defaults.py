from __future__ import annotations

from functools import lru_cache
from importlib import resources

from .models import Person


POPULAR_FIRSTNAMES_FILE = "popular_firstnames_ru.txt"
POPULAR_LASTNAMES_FILE = "popular_lastnames_ru.txt"
POPULAR_PATRONYMICS_FILE = "popular_patronymics_ru.txt"
FALLBACK_PEOPLE_LIMIT = 250


DEFAULT_TRANSLITERATION: dict[str, str | list[str]] = {
    "а": "a",
    "б": "b",
    "в": "v",
    "г": "g",
    "д": "d",
    "е": "e",
    "ё": ["e", "yo"],
    "ж": ["zh", "j"],
    "з": "z",
    "и": "i",
    "й": ["y", "i"],
    "к": "k",
    "л": "l",
    "м": "m",
    "н": "n",
    "о": "o",
    "п": "p",
    "р": "r",
    "с": "s",
    "т": "t",
    "у": "u",
    "ф": "f",
    "х": ["kh", "h"],
    "ц": ["ts", "c"],
    "ч": ["ch", "tch"],
    "ш": "sh",
    "щ": ["sch", "shch"],
    "ъ": "",
    "ы": ["y", "i"],
    "ь": "",
    "э": "e",
    "ю": ["yu", "iu"],
    "я": ["ya", "ia"],
}


DEFAULT_PERSON_PATTERNS: tuple[str, ...] = (
    "{f}.{lastname}",
    "{firstname}.{lastname}",
    "{lastname}.{firstname}",
    "{lastname}.{f}",
    "{f}{lastname}",
    "{lastname}{f}",
    "{firstname}_{lastname}",
    "{lastname}_{firstname}",
    "{firstname}-{lastname}",
    "{lastname}-{firstname}",
    "{lastname}.{f2}",
    "{f2}.{lastname}",
    "{f3}.{lastname}",
)


DEFAULT_TECHNICAL_PATTERNS: tuple[str, ...] = (
    "{word}",
    "{word}.{company}",
    "{company}.{word}",
)


DEFAULT_PEOPLE: tuple[Person, ...] = (
    Person("Александр", "Иванов", "Сергеевич"),
    Person("Сергей", "Смирнов", "Александрович"),
    Person("Дмитрий", "Кузнецов", "Сергеевич"),
    Person("Андрей", "Попов", "Андреевич"),
    Person("Алексей", "Васильев", "Дмитриевич"),
    Person("Максим", "Петров", "Алексеевич"),
    Person("Иван", "Соколов", "Иванович"),
    Person("Михаил", "Михайлов", "Павлович"),
    Person("Николай", "Новиков", "Николаевич"),
    Person("Владимир", "Федоров", "Владимирович"),
    Person("Артем", "Морозов", "Олегович"),
    Person("Евгений", "Волков", "Евгеньевич"),
    Person("Илья", "Алексеев", "Ильич"),
    Person("Павел", "Лебедев", "Павлович"),
    Person("Роман", "Семенов", "Романович"),
    Person("Анна", "Кузнецова", "Сергеевна"),
    Person("Мария", "Иванова", "Александровна"),
    Person("Елена", "Смирнова", "Дмитриевна"),
    Person("Ольга", "Петрова", "Андреевна"),
    Person("Наталья", "Соколова", "Алексеевна"),
    Person("Ирина", "Попова", "Владимировна"),
    Person("Татьяна", "Васильева", "Николаевна"),
    Person("Екатерина", "Михайлова", "Евгеньевна"),
    Person("Светлана", "Федорова", "Павловна"),
    Person("Юлия", "Морозова", "Ильинична"),
)


DEFAULT_TECHNICAL_WORDS: tuple[str, ...] = (
    "admin",
    "administrator",
    "adm",
    "root",
    "support",
    "helpdesk",
    "service",
    "svc",
    "test",
    "user",
    "info",
    "office",
    "manager",
    "hr",
    "it",
    "security",
    "soc",
    "noc",
    "devops",
    "backup",
    "mail",
    "postmaster",
    "webmaster",
)


DEFAULT_SEARCH_DORKS: tuple[str, ...] = (
    '"ivanov@{domain}"',
    '"petrov@{domain}"',
    '"ivan@{domain}"',
    '"petr@{domain}"',
    '"andrei@{domain}"',
    '"eva@{domain}"',
    '"elena@{domain}"',
    '"a@{domain}"',
    '"b@{domain}"',
    '"c@{domain}"',
)


DEFAULT_CONTACT_ROLE_TERMS: tuple[str, ...] = (
    "info",
    "contact",
    "contacts",
    "mail",
    "email",
    "office",
    "reception",
    "support",
    "help",
    "helpdesk",
    "service",
    "client",
    "clients",
    "customer",
    "customers",
    "sales",
    "sale",
    "commercial",
    "marketing",
    "pr",
    "press",
    "media",
    "hr",
    "job",
    "jobs",
    "career",
    "careers",
    "vacancy",
    "vacancies",
    "partner",
    "partners",
    "security",
    "abuse",
    "webmaster",
    "postmaster",
)


@lru_cache(maxsize=None)
def popular_firstnames() -> tuple[str, ...]:
    return _read_data_lines(POPULAR_FIRSTNAMES_FILE)


@lru_cache(maxsize=None)
def popular_lastnames() -> tuple[str, ...]:
    return _read_data_lines(POPULAR_LASTNAMES_FILE)


@lru_cache(maxsize=None)
def popular_patronymics() -> tuple[str, ...]:
    return _read_data_lines(POPULAR_PATRONYMICS_FILE)


def fallback_people(limit: int = FALLBACK_PEOPLE_LIMIT) -> tuple[Person, ...]:
    firstnames = popular_firstnames()
    lastnames = popular_lastnames()
    patronymics = popular_patronymics()
    if not firstnames or not lastnames:
        return DEFAULT_PEOPLE[:limit]

    people: list[Person] = []
    for lastname in lastnames:
        for firstname in firstnames:
            patronymic = patronymics[len(people) % len(patronymics)] if patronymics else ""
            people.append(Person(firstname=firstname, lastname=lastname, patronymic=patronymic))
            if len(people) >= limit:
                return tuple(people)
    return tuple(people)


def _read_data_lines(filename: str) -> tuple[str, ...]:
    try:
        text = resources.files("logingen").joinpath("data").joinpath(filename).read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError):
        return ()
    values: list[str] = []
    for line in text.splitlines():
        value = line.strip()
        if value and not value.startswith("#") and value not in values:
            values.append(value)
    return tuple(values)
