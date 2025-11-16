import os
from dotenv import load_dotenv
from datetime import datetime
from ldap3 import Server, Connection, ALL, SUBTREE, ALL_ATTRIBUTES, Tls, MODIFY_REPLACE, set_config_parameter, utils
from ldap3.core.exceptions import LDAPBindError
import logging
import logging.handlers as handlers
import sys
import requests
from dataclasses import dataclass
from http import HTTPStatus
import time
import csv

LOG_FILE = "sync_deps.log"
EMAIL_DOMAIN = "domain.ru"
DEFAULT_360_API_URL = "https://api360.yandex.net"
ITEMS_PER_PAGE = 100
MAX_RETRIES = 3
RETRIES_DELAY_SEC = 2
SLEEP_TIME_BETWEEN_API_CALLS = 0.5
ALL_USERS_REFRESH_IN_MINUTES = 15
USERS_PER_PAGE_FROM_API = 1000
DEPARTMENTS_PER_PAGE_FROM_API = 100
GROUPS_PER_PAGE_FROM_API = 1000
SENSITIVE_FIELDS = ['password', 'oauth_token', 'access_token', 'token']
EXIT_CODE = 1

logger = logging.getLogger("sync_deps")
logger.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter('%(asctime)s.%(msecs)03d %(levelname)s:\t%(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
#file_handler = handlers.TimedRotatingFileHandler(LOG_FILE, when='D', interval=1, backupCount=30, encoding='utf-8')
file_handler = handlers.RotatingFileHandler(LOG_FILE, maxBytes=10 * 1024 * 1024,  backupCount=20, encoding='utf-8')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(logging.Formatter('%(asctime)s.%(msecs)03d %(levelname)s:\t%(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
logger.addHandler(console_handler)
logger.addHandler(file_handler)


def get_ldap_users(settings: "SettingParams"):
    """
    Запрашивает всех пользователей из LDAP каталога.
    Фильтрует только объекты с objectClass = person.
    
    Args:
        settings: Объект настроек с параметрами подключения к LDAP
        
    Returns:
        list: Список словарей с атрибутами пользователей
    """
    set_config_parameter('DEFAULT_SERVER_ENCODING', 'utf-8')
    set_config_parameter('ADDITIONAL_SERVER_ENCODINGS', 'koi8-r')

    if settings.ldaps_enabled:
        server = Server(settings.ldap_host, port=settings.ldap_port, get_info=ALL, use_ssl=True) 
    else:
        server = Server(settings.ldap_host, port=settings.ldap_port, get_info=ALL) 

    try:
        logger.debug(f'Trying to connect to LDAP server {settings.ldap_host}:{settings.ldap_port}')
        conn = Connection(server, user=settings.ldap_user, password=settings.ldap_password, auto_bind=True)
    except LDAPBindError as e:
        logger.error('Can not connect to LDAP - "automatic bind not successful - invalidCredentials". Exit.')
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        return []
    
    logger.info(f'Connected to LDAP server {settings.ldap_host}:{settings.ldap_port}')
    
    users = []
    logger.info(f'Trying to search users. LDAP filter: {settings.ldap_user_search_filter}')
    logger.info(f'Search base DN: {settings.ldap_user_base_dn}')
    logger.info(f'Attributes: {settings.attrib_user_list}')
    
    conn.search(
        settings.ldap_user_base_dn, 
        settings.ldap_user_search_filter, 
        search_scope=SUBTREE, 
        attributes=settings.attrib_user_list
    )
    
    if conn.last_error is not None:
        logger.error('Can not search users in LDAP. Exit.')
        return []
    
    logger.info(f'Found {len(conn.entries)} user records.')
    
    try:            
        for item in conn.entries:
            # Проверяем наличие атрибута objectClass
            if 'objectClass' in item.entry_attributes_as_dict:
                object_classes = item['objectClass'].values if hasattr(item['objectClass'], 'values') else [item['objectClass'].value]
                
                # Фильтруем только объекты типа person
                if 'person' in object_classes:
                    entry = {}
                    # Извлекаем все запрошенные атрибуты
                    for attr in settings.attrib_user_list:
                        if attr in item.entry_attributes_as_dict:
                            attr_value = item[attr].value
                            if attr_value is not None:
                                if isinstance(attr_value, str):
                                    entry[attr] = attr_value.strip()
                                else:
                                    entry[attr] = attr_value
                            else:
                                entry[attr] = None
                        else:
                            entry[attr] = None
                    
                    if entry:
                        users.append(entry)
                
    except Exception as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        return []
    
    logger.info(f'All users are processed. Total {len(users)} users.')
    conn.unbind()
    
    return users


def get_ldap_dynamic_groups(settings: "SettingParams"):
    """
    Запрашивает динамические группы рассылки из LDAP каталога.
    Фильтрует только объекты с objectClass = msExchDynamicDistributionList.
    
    Args:
        settings: Объект настроек с параметрами подключения к LDAP
        
    Returns:
        list: Список словарей с атрибутами динамических групп рассылки
    """
    set_config_parameter('DEFAULT_SERVER_ENCODING', 'utf-8')
    set_config_parameter('ADDITIONAL_SERVER_ENCODINGS', 'koi8-r')

    if settings.ldaps_enabled:
        server = Server(settings.ldap_host, port=settings.ldap_port, get_info=ALL, use_ssl=True) 
    else:
        server = Server(settings.ldap_host, port=settings.ldap_port, get_info=ALL) 

    try:
        logger.debug(f'Trying to connect to LDAP server {settings.ldap_host}:{settings.ldap_port}')
        conn = Connection(server, user=settings.ldap_user, password=settings.ldap_password, auto_bind=True)
    except LDAPBindError as e:
        logger.error('Can not connect to LDAP - "automatic bind not successful - invalidCredentials". Exit.')
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        return []
    
    logger.info(f'Connected to LDAP server {settings.ldap_host}:{settings.ldap_port}')
    
    groups = []
    logger.info(f'Trying to search dynamic distribution groups. LDAP filter: {settings.ldap_group_search_filter}')
    logger.info(f'Search base DN: {settings.ldap_group_base_dn}')
    logger.info(f'Attributes: {settings.attrib_group_list}')
    
    conn.search(
        settings.ldap_group_base_dn, 
        settings.ldap_group_search_filter, 
        search_scope=SUBTREE, 
        attributes=settings.attrib_group_list
    )
    
    if conn.last_error is not None:
        logger.error('Can not search groups in LDAP. Exit.')
        return []
    
    logger.info(f'Found {len(conn.entries)} group records.')
    
    try:            
        for item in conn.entries:
            # Проверяем наличие атрибута objectClass
            if 'objectClass' in item.entry_attributes_as_dict:
                object_classes = item['objectClass'].values if hasattr(item['objectClass'], 'values') else [item['objectClass'].value]
                
                # Фильтруем только динамические группы рассылки
                if 'msExchDynamicDistributionList' in object_classes:
                    entry = {}
                    # Извлекаем все запрошенные атрибуты
                    for attr in settings.attrib_group_list:
                        if attr in item.entry_attributes_as_dict:
                            attr_value = item[attr].value
                            if attr_value is not None:
                                if isinstance(attr_value, str):
                                    entry[attr] = attr_value.strip()
                                else:
                                    entry[attr] = attr_value
                            else:
                                entry[attr] = None
                        else:
                            entry[attr] = None
                    
                    # Если displayName пустой, используем значение cn
                    if not entry.get('displayName') and entry.get('cn'):
                        entry['displayName'] = entry['cn']
                        logger.debug(f"Группа с пустым displayName: используется значение cn '{entry['cn']}'")
                    
                    if entry:
                        groups.append(entry)
                        
    except Exception as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        return []
    
    logger.info(f'All dynamic distribution groups are processed. Total {len(groups)} groups.')
    conn.unbind()
    
    return groups


def get_group_members_from_file(ad_group: dict, members_files_dir: str = "."):
    """
    Читает список email адресов членов группы из CSV файла.
    
    Функция формирует имя файла на основе атрибута displayName из данных группы AD,
    заменяя пробелы на подчеркивания, и читает CSV файл с разделителем ";".
    
    Args:
        ad_group (dict): Словарь с данными группы из Active Directory, 
                        должен содержать атрибут 'displayName'
        members_files_dir (str): Путь к каталогу с файлами членов групп (по умолчанию текущий каталог)
    
    Returns:
        list: Список email адресов членов группы. 
              Возвращает пустой список в случае ошибки или отсутствия файла.
    
    Example:
        ad_group = {
            "displayName": "Динамическая группа рассылки",
            "mail": "group@domain.ru",
            "objectGUID": "12345"
        }
        
        # Будет искать файл "Группа_рассылки_Динамическая_группа_рассылки.csv"
        emails = get_group_members_from_file(ad_group, members_files_dir="/path/to/files")
        
        # Результат: ['email1@domain.ru', 'email2@domain.ru', ...]
    
    Note:
        - Формат имени файла: "Группа_рассылки_{displayName}.csv" 
          где {displayName} - значение атрибута displayName с заменой пробелов на подчеркивания
        - CSV файл должен иметь разделитель ";" (точка с запятой)
        - Первая строка файла считается заголовком и пропускается
        - Email адреса извлекаются из второго столбца (индекс 1)
        - Пустые строки и строки без email адресов пропускаются
        - Все email адреса очищаются от пробелов и кавычек
    """
    # Получаем displayName из словаря
    display_name = ad_group.get('displayName')
    
    if not display_name:
        logger.error("Группа не имеет атрибута 'displayName'. Невозможно определить имя файла.")
        return []
    
    # Заменяем пробелы на подчеркивания
    display_name_formatted = display_name.replace(' ', '_')
    
    # Формируем имя файла
    filename = f"Группа_рассылки_{display_name_formatted}.csv"
    
    # Формируем полный путь к файлу
    file_path = os.path.join(members_files_dir, filename)
    
    logger.info(f"Чтение членов группы '{display_name}' из файла: {file_path}")
    
    # Проверяем существование файла
    if not os.path.exists(file_path):
        logger.warning(f"Файл '{file_path}' не найден. Возвращается пустой список членов.")
        return []
    
    # Читаем CSV файл
    emails = []
    try:
        with open(file_path, 'r', encoding='utf-8') as csvfile:
            # Используем csv.reader с разделителем ";"
            csv_reader = csv.reader(csvfile, delimiter=';')
            
            # Пропускаем заголовок (первую строку)
            next(csv_reader, None)
            
            # Читаем остальные строки
            for row_number, row in enumerate(csv_reader, start=2):  # start=2 т.к. первая строка - заголовок
                # Проверяем, что строка не пустая и содержит достаточно столбцов
                if not row or len(row) < 2:
                    continue
                
                # Извлекаем email из второго столбца (индекс 1)
                email = row[1].strip().strip('"').strip("'")
                
                # Проверяем, что email не пустой
                if email:
                    emails.append(email)
                    logger.debug(f"  Строка {row_number}: найден email '{email}'")
                else:
                    logger.debug(f"  Строка {row_number}: пустое значение email, пропускается")
        
        logger.info(f"Успешно прочитано {len(emails)} email адресов из файла '{filename}'")
        
    except FileNotFoundError:
        logger.error(f"Файл '{file_path}' не найден.")
        return []
    except PermissionError:
        logger.error(f"Нет прав доступа для чтения файла '{file_path}'.")
        return []
    except csv.Error as e:
        logger.error(f"Ошибка при чтении CSV файла '{file_path}': {e}")
        return []
    except Exception as e:
        logger.error(f"Неожиданная ошибка при чтении файла '{file_path}': {type(e).__name__} - {e}")
        return []
    
    return emails


def get_all_groups_from_api360(settings: "SettingParams"):

    logger.info("Getting all groups of the organisation...")
    url = f"{DEFAULT_360_API_URL}/directory/v1/org/{settings.org_id}/groups"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    has_errors = False
    groups = []
    current_page = 1
    last_page = 1
    while current_page <= last_page:
        params = {'page': current_page, 'perPage': GROUPS_PER_PAGE_FROM_API}
        try:
            retries = 1
            while True:
                logger.debug(f"GET URL - {url}")
                response = requests.get(url, headers=headers, params=params)
                logger.debug(f"x-request-id: {response.headers.get('x-request-id','')}")
                if response.status_code != HTTPStatus.OK.value:
                    logger.error(f"!!! ERROR !!! during GET request url - {url}: {response.status_code}. Error message: {response.text}")
                    if retries < MAX_RETRIES:
                        logger.error(f"Retrying ({retries+1}/{MAX_RETRIES})")
                        time.sleep(RETRIES_DELAY_SEC * retries)
                        retries += 1
                    else:
                        has_errors = True
                        break
                else:
                    groups.extend(response.json()['groups'])
                    logger.debug(f"Get {len(response.json()['groups'])} groups from page {current_page} (total {last_page} page(s)).")
                    current_page += 1
                    last_page = response.json()['pages']
                    break

        except requests.exceptions.RequestException as e:
            logger.error(f"!!! ERROR !!! {type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
            has_errors = True
            break

        if has_errors:
            break

    if has_errors:
        logger.error("There are some error during GET requests. Return empty groups list.")
        return []
    
    return groups


def get_all_api360_users(settings: "SettingParams", force = False):
    if not force:
        logger.info("Получение всех пользователей организации из кэша...")

    if not settings.all_users or force or (datetime.now() - settings.all_users_get_timestamp).total_seconds() > ALL_USERS_REFRESH_IN_MINUTES * 60:
        #logger.info("Получение всех пользователей организации из API...")
        settings.all_users = get_all_api360_users_from_api(settings)
        settings.all_users_get_timestamp = datetime.now()
    return settings.all_users

def get_all_api360_users_from_api(settings: "SettingParams"):
    logger.info("Получение всех пользователей организации из API...")
    url = f"{DEFAULT_360_API_URL}/directory/v1/org/{settings.org_id}/users"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    has_errors = False
    users = []
    current_page = 1
    last_page = 1
    while current_page <= last_page:
        params = {'page': current_page, 'perPage': USERS_PER_PAGE_FROM_API}
        try:
            retries = 1
            while True:
                logger.debug(f"GET URL - {url}")
                response = requests.get(url, headers=headers, params=params)
                logger.debug(f"x-request-id: {response.headers.get('x-request-id','')}")
                if response.status_code != HTTPStatus.OK.value:
                    logger.error(f"!!! ОШИБКА !!! при GET запросе url - {url}: {response.status_code}. Сообщение об ошибке: {response.text}")
                    if retries < MAX_RETRIES:
                        logger.error(f"Повторная попытка ({retries+1}/{MAX_RETRIES})")
                        time.sleep(RETRIES_DELAY_SEC * retries)
                        retries += 1
                    else:
                        has_errors = True
                        break
                else:
                    for user in response.json()['users']:
                        if not user.get('isRobot') and int(user["id"]) >= 1130000000000000:
                            users.append(user)
                    logger.debug(f"Загружено {len(response.json()['users'])} пользователей. Текущая страница - {current_page} (всего {last_page} страниц).")
                    current_page += 1
                    last_page = response.json()['pages']
                    break

        except requests.exceptions.RequestException as e:
            logger.error(f"!!! ERROR !!! {type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
            has_errors = True
            break

        if has_errors:
            break

    if has_errors:
        print("Есть ошибки при GET запросах. Возвращается пустой список пользователей.")
        return []
    
    return users

@dataclass
class SettingParams:
    oauth_token: str
    org_id: int
    all_users : list
    all_users_get_timestamp : datetime
    dry_run : bool
    ldap_host : str
    ldap_port : int
    ldap_user : str
    ldap_password : str
    ldaps_enabled : bool
    ldap_user_base_dn : str
    ldap_user_search_filter : str
    attrib_user_list : list
    ldap_group_base_dn : str
    ldap_group_search_filter : str
    attrib_group_list : list
    members_files_dir : str
    enable_diagnostics : bool
    y360_group_members_dir : str

def get_settings():
    exit_flag = False
    oauth_token_bad = False
    settings = SettingParams (
        oauth_token = os.environ.get("OAUTH_TOKEN"),
        org_id = os.environ.get("ORG_ID"),
        all_users = [],
        all_users_get_timestamp = datetime.now(),
        dry_run = os.environ.get("DRY_RUN","false").lower() == "true",
        ldap_host = os.environ.get('LDAP_HOST'),
        ldap_port = int(os.environ.get('LDAP_PORT')),
        ldap_user = os.environ.get('LDAP_USER'),
        ldap_password = os.environ.get('LDAP_PASSWORD'),
        ldaps_enabled = os.environ.get("LDAPS_ENABLED","false").lower() == "true",
        ldap_user_base_dn = os.environ.get('LDAP_USER_BASE_DN'),
        ldap_user_search_filter = os.environ.get('LDAP_USER_SEARCH_FILTER'),
        attrib_user_list = os.environ.get('ATTRIB_USER_LIST').split(',') if os.environ.get('ATTRIB_USER_LIST') else [],
        ldap_group_base_dn = os.environ.get('LDAP_GROUP_BASE_DN'),
        ldap_group_search_filter = os.environ.get('LDAP_GROUP_SEARCH_FILTER'),
        attrib_group_list = os.environ.get('ATTRIB_GROUP_LIST').split(',') if os.environ.get('ATTRIB_GROUP_LIST') else [],
        members_files_dir = os.environ.get('GROUPS_MEMBERS_FILE_DIR', '.'),
        enable_diagnostics = os.environ.get('ENABLE_DIAGNOSTICS', 'false').lower() == 'true',
        y360_group_members_dir = os.environ.get('Y360_GROUP_MEMBERS_DIR', './y360_diagnostics'),
    )
    
    if not settings.oauth_token:
        logger.error("OAUTH_TOKEN_ARG не установлен.")
        oauth_token_bad = True

    if not settings.org_id:
        logger.error("ORG_ID_ARG не установлен.")
        exit_flag = True

    if not (oauth_token_bad or exit_flag):
        if not check_oauth_token(settings.oauth_token, settings.org_id):
            logger.error("OAUTH_TOKEN_ARG не является действительным")
            oauth_token_bad = True

        if not settings.ldap_host:
            logger.error("LDAP_HOST не установлен.")
            exit_flag = True

        if not settings.ldap_port:
            logger.error("LDAP_PORT не установлен.")
            exit_flag = True

        if not settings.ldap_user:
            logger.error("LDAP_USER не установлен.")
            exit_flag = True

        if not settings.ldap_password:
            logger.error("LDAP_PASSWORD не установлен.")
            exit_flag = True


    if oauth_token_bad:
        exit_flag = True
    
    if exit_flag:
        return None
    
    return settings


def check_oauth_token(oauth_token, org_id):
    """Проверяет, что токен OAuth действителен."""
    url = f"{DEFAULT_360_API_URL}/directory/v1/org/{org_id}/users?perPage=100"
    headers = {
        "Authorization": f"OAuth {oauth_token}"
    }
    response = requests.get(url, headers=headers)
    if response.status_code == HTTPStatus.OK:
        return True
    return False

def mask_sensitive_data(data: dict) -> dict:
    """
    Создает копию словаря с замаскированными чувствительными данными для безопасного логирования.
    
    Args:
        data (dict): Исходный словарь с данными
        
    Returns:
        dict: Копия словаря с замаскированными паролями и токенами
    """
    import copy
    
    # Создаем глубокую копию для безопасного изменения
    masked_data = copy.deepcopy(data)
    
    # Список полей, которые нужно замаскировать
    sensitive_fields = SENSITIVE_FIELDS
    
    def mask_recursive(obj):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key.lower() in sensitive_fields:
                    obj[key] = "***MASKED***"
                elif isinstance(value, (dict, list)):
                    mask_recursive(value)
        elif isinstance(obj, list):
            for item in obj:
                mask_recursive(item)
    
    mask_recursive(masked_data)
    return masked_data

def create_user_by_api(settings: "SettingParams", user: dict):

    url = f"{DEFAULT_360_API_URL}/directory/v1/org/{settings.org_id}/users"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    logger.debug(f"POST URL: {url}")
    logger.debug(f"POST DATA: {mask_sensitive_data(user)}")
    retries = 1
    added_user = {}
    success = False
    while True:
        try:
            response = requests.post(f"{url}", headers=headers, json=user)
            logger.debug(f"x-request-id: {response.headers.get('x-request-id','')}")
            if response.status_code != HTTPStatus.OK.value:
                logger.error(f"Error during POST request: {response.status_code}. Error message: {response.text}")
                if retries < MAX_RETRIES:
                    logger.error(f"Retrying ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    logger.error(f"Ошибка. Создание пользователя {user['nickname']} ({user['name']['last']} {user['name']['first']}) не удалось.")
                    break
            else:
                logger.info(f"Успех - пользователь {user['nickname']} ({user['name']['last']} {user['name']['first']}) создан успешно.")
                added_user = response.json()
                success = True
                break
        except Exception as e:
            logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")

    return success, added_user

def patch_user_by_api(settings: "SettingParams", user_id: int, patch_data: dict):
    logger.info(f"Изменение пользователя {user_id} в API...")
    url = f"{DEFAULT_360_API_URL}/directory/v1/org/{settings.org_id}/users/{user_id}"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    logger.debug(f"PATCH URL: {url}")
    logger.debug(f"PATCH DATA: {mask_sensitive_data(patch_data)}")
    retries = 1
    success = False
    while True:
        try:
            response = requests.patch(f"{url}", headers=headers, json=patch_data)
            logger.debug(f"x-request-id: {response.headers.get('x-request-id','')}")
            if response.status_code != HTTPStatus.OK.value:
                logger.error(f"Error during PATCH request: {response.status_code}. Error message: {response.text}")
                if retries < MAX_RETRIES:
                    logger.error(f"Retrying ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    logger.error(f"Ошибка. Изменение пользователя {user_id} не удалось.")
                    break
            else:
                logger.info(f"Успех - данные пользователя {user_id} изменены успешно.")
                success = True
                break
        except Exception as e:
            logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")

    return success

def patch_department_by_api(settings: "SettingParams", department_id: int, patch_data: dict):
    logger.info(f"Изменение подразделения {department_id} в API...")
    url = f"{DEFAULT_360_API_URL}/directory/v1/org/{settings.org_id}/departments/{department_id}"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    logger.debug(f"PATCH URL: {url}")
    logger.debug(f"PATCH DATA: {mask_sensitive_data(patch_data)}")
    retries = 1
    success = False
    while True:
        try:
            response = requests.patch(f"{url}", headers=headers, json=patch_data)
            logger.debug(f"x-request-id: {response.headers.get('x-request-id','')}")
            if response.status_code != HTTPStatus.OK.value:
                logger.error(f"Error during PATCH request: {response.status_code}. Error message: {response.text}")
                if retries < MAX_RETRIES:
                    logger.error(f"Retrying ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    logger.error(f"Ошибка. Изменение подразделения {department_id} не удалось.")
                    break
            else:
                logger.info(f"Успех - данные подразделения {department_id} изменены успешно.")
                success = True
                break
        except Exception as e:
            logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")

    return success

def get_all_api360_departments(settings: "SettingParams"):
    logger.info("Получение всех подразделений организации из API...")
    url = f"{DEFAULT_360_API_URL}/directory/v1/org/{settings.org_id}/departments"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}

    has_errors = False
    departments = []
    current_page = 1
    last_page = 1
    while current_page <= last_page:
        params = {'page': current_page, 'perPage': DEPARTMENTS_PER_PAGE_FROM_API}
        try:
            retries = 1
            while True:
                logger.debug(f"GET URL - {url}")
                response = requests.get(url, headers=headers, params=params)
                logger.debug(f"x-request-id: {response.headers.get('x-request-id','')}")
                if response.status_code != HTTPStatus.OK.value:
                    logger.error(f"!!! ОШИБКА !!! при GET запросе url - {url}: {response.status_code}. Сообщение об ошибке: {response.text}")
                    if retries < MAX_RETRIES:
                        logger.error(f"Повторная попытка ({retries+1}/{MAX_RETRIES})")
                        time.sleep(RETRIES_DELAY_SEC * retries)
                        retries += 1
                    else:
                        has_errors = True
                        break
                else:
                    for deps in response.json()['departments']:
                        departments.append(deps)
                    logger.debug(f"Загружено {len(response.json()['departments'])} подразделений. Текущая страница - {current_page} (всего {last_page} страниц).")
                    current_page += 1
                    last_page = response.json()['pages']
                    break

        except requests.exceptions.RequestException as e:
            logger.error(f"!!! ERROR !!! {type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
            has_errors = True
            break

        if has_errors:
            break

    if has_errors:
        print("Есть ошибки при GET запросах. Возвращается пустой список подразделений.")
        return []
    
    return departments

def delete_department_by_api(settings: "SettingParams", department: dict):
    logger.info(f"Удаление подразделения {department['id']} ({department['name']}) из API...")
    url = f"{DEFAULT_360_API_URL}/directory/v1/org/{settings.org_id}/departments/{department['id']}"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    logger.debug(f"DELETE URL: {url}")
    try:
        retries = 1
        while True:
            response = requests.delete(f"{url}", headers=headers)
            logger.debug(f"x-request-id: {response.headers.get('x-request-id','')}")
            if response.status_code != HTTPStatus.OK.value:
                logger.error(f"!!! ОШИБКА !!! при DELETE запросе url - {url}: {response.status_code}. Сообщение об ошибке: {response.text}")
                if retries < MAX_RETRIES:
                    logger.error(f"Повторная попытка ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    has_errors = True
                    break
            else:
                logger.info(f"Успех - подразделение {department['id']} ({department['name']}) удалено успешно.")
                return True
    except requests.exceptions.RequestException as e:
        logger.error(f"!!! ERROR !!! {type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        has_errors = True

    if has_errors:
        print("Есть ошибки при DELETE запросах. Возвращается False.")
        return False

    return True


def delete_all_departments(settings: "SettingParams"):
    logger.info("Удаление всех подразделений организации...")
    departments = get_all_api360_departments(settings)
    if len(departments) == 0:
        logger.info("Нет подразделений для удаления.")
        return
    logger.info(f"Удаление {len(departments)} подразделений...")
    for department in departments:
        delete_department_by_api(settings, department)
    logger.info("Удаление всех подразделений завершено.")
    return

def create_department_by_api(settings: "SettingParams", department: dict):
    logger.info(f"Создание подразделения {department['name']} в API...")
    url = f"{DEFAULT_360_API_URL}/directory/v1/org/{settings.org_id}/departments"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    logger.debug(f"POST URL: {url}")
    logger.debug(f"POST DATA: {department}")
    try:
        retries = 1
        while True:
            response = requests.post(f"{url}", headers=headers, json=department)
            logger.debug(f"x-request-id: {response.headers.get('x-request-id','')}")
            if response.status_code != HTTPStatus.OK.value:
                logger.error(f"!!! ОШИБКА !!! при POST запросе url - {url}: {response.status_code}. Сообщение об ошибке: {response.text}")
                if retries < MAX_RETRIES:
                    logger.error(f"Повторная попытка ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    has_errors = True
                    break
            else:
                logger.info(f"Успех - подразделение {department['name']} создано успешно.")
                return True

    except requests.exceptions.RequestException as e:
        logger.error(f"!!! ERROR !!! {type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        has_errors = True

    if has_errors:
        print("Есть ошибки при POST запросах. Возвращается False.")
        return False

    return True


def create_group_by_api(settings: "SettingParams", group: dict):
    """
    Создает новую группу в Yandex 360.
    
    Args:
        settings: Объект настроек с параметрами подключения к API
        group: Словарь с данными группы, содержащий:
            - name (str, обязательно): Название группы
            - description (str, необязательно): Описание группы
            - label (str, необязательно): Имя почтовой рассылки группы (например, для адреса 
              new-group@ваш-домен.ru имя почтовой рассылки — это new-group)
            - externalId (str, необязательно): Произвольный внешний идентификатор группы
            - members (list, необязательно): Список участников группы, где каждый участник представлен словарем:
                - type (str): Тип участника ('user', 'group', 'department')
                - id (str): Идентификатор участника
    
    Returns:
        tuple: (success: bool, created_group: dict) - 
            success: True если группа создана успешно, False в противном случае
            created_group: Словарь с данными созданной группы или пустой словарь при ошибке
            
    Example:
        group_data = {
            "name": "Моя группа",
            "description": "Описание группы",
            "label": "my-group",
            "externalId": "external-123",
            "members": [
                {"type": "user", "id": "1234567890"},
                {"type": "department", "id": "5"}
            ]
        }
        success, created_group = create_group_by_api(settings, group_data)
    """
    logger.info(f"Создание группы {group.get('name', 'без имени')} в API...")
    url = f"{DEFAULT_360_API_URL}/directory/v1/org/{settings.org_id}/groups"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    logger.debug(f"POST URL: {url}")
    logger.debug(f"POST DATA: {mask_sensitive_data(group)}")
    
    retries = 1
    created_group = {}
    success = False
    has_errors = False
    
    try:
        while True:
            response = requests.post(url, headers=headers, json=group)
            logger.debug(f"x-request-id: {response.headers.get('x-request-id','')}")
            
            if response.status_code != HTTPStatus.OK.value:
                logger.error(f"!!! ОШИБКА !!! при POST запросе url - {url}: {response.status_code}. Сообщение об ошибке: {response.text}")
                if retries < MAX_RETRIES:
                    logger.error(f"Повторная попытка ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    has_errors = True
                    break
            else:
                created_group = response.json()
                logger.info(f"Успех - группа {group.get('name', 'без имени')} создана успешно. ID группы: {created_group.get('id', 'N/A')}")
                success = True
                break
                
    except requests.exceptions.RequestException as e:
        logger.error(f"!!! ERROR !!! {type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        has_errors = True
    except Exception as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        has_errors = True

    if has_errors:
        logger.error(f"Ошибка. Создание группы {group.get('name', 'без имени')} не удалось.")
        return False, {}

    return success, created_group


def get_group_members_by_api(settings: "SettingParams", group_id: int):
    """
    Получает список участников группы из Yandex 360.
    
    Возвращает список участников группы, таких как сотрудники, подразделения или другие группы.
    
    Args:
        settings: Объект настроек с параметрами подключения к API
        group_id (int): Идентификатор группы
    
    Returns:
        tuple: (success: bool, members: dict) - 
            success: True если запрос выполнен успешно, False в противном случае
            members: Словарь с данными участников группы в формате:
                {
                    "departments": [
                        {
                            "id": int,
                            "name": str,
                            "membersCount": int
                        }
                    ],
                    "groups": [
                        {
                            "id": int,
                            "name": str,
                            "membersCount": int
                        }
                    ],
                    "users": [
                        {
                            "id": str,
                            "nickname": str,
                            "departmentId": int,
                            "email": str,
                            "name": {
                                "first": str,
                                "last": str,
                                "middle": str
                            },
                            "gender": str,
                            "position": str,
                            "avatarId": str
                        }
                    ]
                }
            или пустой словарь при ошибке
            
    Example:
        success, members = get_group_members_by_api(settings, 123)
        if success:
            print(f"Users in group: {len(members.get('users', []))}")
            print(f"Departments in group: {len(members.get('departments', []))}")
            print(f"Groups in group: {len(members.get('groups', []))}")
    
    Reference:
        https://yandex.ru/dev/api360/doc/ru/ref/GroupService/GroupService_ListMembers
    """
    logger.info(f"Получение участников группы {group_id} из API...")
    url = f"{DEFAULT_360_API_URL}/directory/v1/org/{settings.org_id}/groups/{group_id}/members"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    logger.debug(f"GET URL: {url}")
    
    retries = 1
    members = {}
    success = False
    has_errors = False
    
    try:
        while True:
            response = requests.get(url, headers=headers)
            logger.debug(f"x-request-id: {response.headers.get('x-request-id','')}")
            
            if response.status_code != HTTPStatus.OK.value:
                logger.error(f"!!! ОШИБКА !!! при GET запросе url - {url}: {response.status_code}. Сообщение об ошибке: {response.text}")
                if retries < MAX_RETRIES:
                    logger.error(f"Повторная попытка ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    has_errors = True
                    break
            else:
                members = response.json()
                users_count = len(members.get('users', []))
                departments_count = len(members.get('departments', []))
                groups_count = len(members.get('groups', []))
                logger.info(f"Успех - получены участники группы {group_id}. "
                          f"Сотрудники: {users_count}, Подразделения: {departments_count}, Группы: {groups_count}")
                success = True
                break
                
    except requests.exceptions.RequestException as e:
        logger.error(f"!!! ERROR !!! {type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        has_errors = True
    except Exception as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        has_errors = True

    if has_errors:
        logger.error(f"Ошибка. Получение участников группы {group_id} не удалось.")
        return False, {}

    return success, members


def add_member_to_group_by_api(settings: "SettingParams", group_id: int, member_type: str, member_id: str):
    """
    Добавляет участника в группу в Yandex 360.
    
    Участником группы может быть сотрудник организации, отдельное подразделение или другая группа.
    
    Args:
        settings: Объект настроек с параметрами подключения к API
        group_id (int): Идентификатор группы
        member_type (str): Тип участника группы. Допустимые значения:
            - 'user': Сотрудник
            - 'group': Группа
            - 'department': Подразделение
        member_id (str): Идентификатор участника группы
    
    Returns:
        tuple: (success: bool, result: dict) - 
            success: True если участник успешно добавлен, False в противном случае
            result: Словарь с результатом операции в формате:
                {
                    "id": str,         # Идентификатор участника группы
                    "type": str,       # Тип участника группы
                    "added": bool      # Признак добавления участника (true — добавлен; false — не добавлен)
                }
            или пустой словарь при ошибке
            
    Example:
        # Добавить сотрудника в группу
        success, result = add_member_to_group_by_api(settings, group_id=123, member_type='user', member_id='1234567890')
        if success and result.get('added'):
            print(f"User {result['id']} successfully added to group")
        
        # Добавить подразделение в группу
        success, result = add_member_to_group_by_api(settings, group_id=123, member_type='department', member_id='5')
        
        # Добавить другую группу в группу
        success, result = add_member_to_group_by_api(settings, group_id=123, member_type='group', member_id='456')
    
    Reference:
        https://yandex.ru/dev/api360/doc/ru/ref/GroupService/GroupService_AddMember
    """
    # Проверка корректности типа участника
    valid_member_types = ['user', 'group', 'department']
    if member_type not in valid_member_types:
        logger.error(f"Некорректный тип участника: {member_type}. Допустимые значения: {', '.join(valid_member_types)}")
        return False, {}
    
    logger.info(f"Добавление участника (тип: {member_type}, ID: {member_id}) в группу {group_id}...")
    url = f"{DEFAULT_360_API_URL}/directory/v1/org/{settings.org_id}/groups/{group_id}/members"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    
    member_data = {
        "type": member_type,
        "id": member_id
    }
    
    logger.debug(f"POST URL: {url}")
    logger.debug(f"POST DATA: {member_data}")
    
    retries = 1
    result = {}
    success = False
    has_errors = False
    
    try:
        while True:
            response = requests.post(url, headers=headers, json=member_data)
            logger.debug(f"x-request-id: {response.headers.get('x-request-id','')}")
            
            if response.status_code != HTTPStatus.OK.value:
                logger.error(f"!!! ОШИБКА !!! при POST запросе url - {url}: {response.status_code}. Сообщение об ошибке: {response.text}")
                if retries < MAX_RETRIES:
                    logger.error(f"Повторная попытка ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    has_errors = True
                    break
            else:
                result = response.json()
                if result.get('added', False):
                    logger.info(f"Успех - участник (тип: {member_type}, ID: {member_id}) добавлен в группу {group_id}")
                else:
                    logger.warning(f"Участник (тип: {member_type}, ID: {member_id}) не был добавлен в группу {group_id} (возможно, уже является участником)")
                success = True
                break
                
    except requests.exceptions.RequestException as e:
        logger.error(f"!!! ERROR !!! {type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        has_errors = True
    except Exception as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        has_errors = True

    if has_errors:
        logger.error(f"Ошибка. Добавление участника (тип: {member_type}, ID: {member_id}) в группу {group_id} не удалось.")
        return False, {}

    return success, result


def delete_member_from_group_by_api(settings: "SettingParams", group_id: int, member_type: str, member_id: str):
    """
    Удаляет участника из группы в Yandex 360.
    
    Удаляет конкретного участника из группы: сотрудника организации, подразделение или вложенную группу.
    
    Args:
        settings: Объект настроек с параметрами подключения к API
        group_id (int): Идентификатор группы
        member_type (str): Тип участника группы. Допустимые значения:
            - 'user': Сотрудник
            - 'group': Группа
            - 'department': Подразделение
        member_id (str): Идентификатор участника группы
    
    Returns:
        tuple: (success: bool, result: dict) - 
            success: True если участник успешно удален, False в противном случае
            result: Словарь с результатом операции в формате:
                {
                    "id": str,         # Идентификатор участника группы
                    "type": str,       # Тип участника группы
                    "deleted": bool    # Признак удаления участника (true — удален; false — не удален)
                }
            или пустой словарь при ошибке
            
    Example:
        # Удалить сотрудника из группы
        success, result = delete_member_from_group_by_api(settings, group_id=123, member_type='user', member_id='1234567890')
        if success and result.get('deleted'):
            print(f"User {result['id']} successfully removed from group")
        
        # Удалить подразделение из группы
        success, result = delete_member_from_group_by_api(settings, group_id=123, member_type='department', member_id='5')
        
        # Удалить другую группу из группы
        success, result = delete_member_from_group_by_api(settings, group_id=123, member_type='group', member_id='456')
    
    Reference:
        https://yandex.ru/dev/api360/doc/ru/ref/GroupService/GroupService_DeleteMember
    """
    # Проверка корректности типа участника
    valid_member_types = ['user', 'group', 'department']
    if member_type not in valid_member_types:
        logger.error(f"Некорректный тип участника: {member_type}. Допустимые значения: {', '.join(valid_member_types)}")
        return False, {}
    
    logger.info(f"Удаление участника (тип: {member_type}, ID: {member_id}) из группы {group_id}...")
    url = f"{DEFAULT_360_API_URL}/directory/v1/org/{settings.org_id}/groups/{group_id}/members/{member_type}/{member_id}"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    
    logger.debug(f"DELETE URL: {url}")
    
    retries = 1
    result = {}
    success = False
    has_errors = False
    
    try:
        while True:
            response = requests.delete(url, headers=headers)
            logger.debug(f"x-request-id: {response.headers.get('x-request-id','')}")
            
            if response.status_code != HTTPStatus.OK.value:
                logger.error(f"!!! ОШИБКА !!! при DELETE запросе url - {url}: {response.status_code}. Сообщение об ошибке: {response.text}")
                if retries < MAX_RETRIES:
                    logger.error(f"Повторная попытка ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    has_errors = True
                    break
            else:
                result = response.json()
                if result.get('deleted', False):
                    logger.info(f"Успех - участник (тип: {member_type}, ID: {member_id}) удален из группы {group_id}")
                else:
                    logger.warning(f"Участник (тип: {member_type}, ID: {member_id}) не был удален из группы {group_id} (возможно, не является участником)")
                success = True
                break
                
    except requests.exceptions.RequestException as e:
        logger.error(f"!!! ERROR !!! {type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        has_errors = True
    except Exception as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        has_errors = True

    if has_errors:
        logger.error(f"Ошибка. Удаление участника (тип: {member_type}, ID: {member_id}) из группы {group_id} не удалось.")
        return False, {}

    return success, result


def patch_group_by_api(settings: "SettingParams", group_id: int, patch_data: dict):
    """
    Изменяет параметры группы в Yandex 360.
    
    Изменяются значения только тех параметров, которые были переданы в запросе.
    
    Args:
        settings: Объект настроек с параметрами подключения к API
        group_id (int): Идентификатор группы
        patch_data (dict): Словарь с данными для обновления группы, может содержать:
            - name (str, необязательно): Название группы
            - description (str, необязательно): Описание группы
            - label (str, необязательно): Имя почтовой рассылки группы (например, для адреса 
              new-group@ваш-домен.ru имя почтовой рассылки — это new-group)
            - externalId (str, необязательно): Произвольный внешний идентификатор группы
            - members (list, необязательно): Список участников группы, где каждый участник представлен словарем:
                - type (str): Тип участника ('user', 'group', 'department')
                - id (str): Идентификатор участника
    
    Returns:
        tuple: (success: bool, updated_group: dict) - 
            success: True если группа обновлена успешно, False в противном случае
            updated_group: Словарь с обновленными данными группы или пустой словарь при ошибке
            
    Example:
        # Изменить название и описание группы
        patch_data = {
            "name": "Новое название группы",
            "description": "Новое описание"
        }
        success, updated_group = patch_group_by_api(settings, group_id=123, patch_data=patch_data)
        
        # Изменить участников группы
        patch_data = {
            "members": [
                {"type": "user", "id": "1234567890"},
                {"type": "department", "id": "5"}
            ]
        }
        success, updated_group = patch_group_by_api(settings, group_id=123, patch_data=patch_data)
        
        # Изменить внешний идентификатор
        patch_data = {"externalId": "new-external-id"}
        success, updated_group = patch_group_by_api(settings, group_id=123, patch_data=patch_data)
    
    Reference:
        https://yandex.ru/dev/api360/doc/ru/ref/GroupService/GroupService_Update
    """
    logger.info(f"Изменение параметров группы {group_id} в API...")
    url = f"{DEFAULT_360_API_URL}/directory/v1/org/{settings.org_id}/groups/{group_id}"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    logger.debug(f"PATCH URL: {url}")
    logger.debug(f"PATCH DATA: {mask_sensitive_data(patch_data)}")
    
    retries = 1
    updated_group = {}
    success = False
    has_errors = False
    
    try:
        while True:
            response = requests.patch(url, headers=headers, json=patch_data)
            logger.debug(f"x-request-id: {response.headers.get('x-request-id','')}")
            
            if response.status_code != HTTPStatus.OK.value:
                logger.error(f"!!! ОШИБКА !!! при PATCH запросе url - {url}: {response.status_code}. Сообщение об ошибке: {response.text}")
                if retries < MAX_RETRIES:
                    logger.error(f"Повторная попытка ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    has_errors = True
                    break
            else:
                updated_group = response.json()
                logger.info(f"Успех - параметры группы {group_id} изменены успешно.")
                success = True
                break
                
    except requests.exceptions.RequestException as e:
        logger.error(f"!!! ERROR !!! {type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        has_errors = True
    except Exception as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        has_errors = True

    if has_errors:
        logger.error(f"Ошибка. Изменение параметров группы {group_id} не удалось.")
        return False, {}

    return success, updated_group


def delete_group_by_api(settings: "SettingParams", group_id: int):
    """
    Удаляет группу из Yandex 360.
    
    Удаляет группу по её идентификатору. При этом участники, которые входили в группу, не удаляются.
    
    Args:
        settings: Объект настроек с параметрами подключения к API
        group_id (int): Идентификатор группы для удаления
    
    Returns:
        tuple: (success: bool, result: dict) - 
            success: True если группа успешно удалена, False в противном случае
            result: Словарь с результатом операции в формате:
                {
                    "id": int,         # Идентификатор группы
                    "removed": bool    # Признак удаления (true — удалена; false — не удалена)
                }
            или пустой словарь при ошибке
            
    Example:
        # Удалить группу
        success, result = delete_group_by_api(settings, group_id=123)
        if success and result.get('removed'):
            print(f"Group {result['id']} successfully deleted")
        else:
            print(f"Failed to delete group or group was not removed")
    
    Reference:
        https://yandex.ru/dev/api360/doc/ru/ref/GroupService/GroupService_Delete
    """
    logger.info(f"Удаление группы {group_id} из API...")
    url = f"{DEFAULT_360_API_URL}/directory/v1/org/{settings.org_id}/groups/{group_id}"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    
    logger.debug(f"DELETE URL: {url}")
    
    retries = 1
    result = {}
    success = False
    has_errors = False
    
    try:
        while True:
            response = requests.delete(url, headers=headers)
            logger.debug(f"x-request-id: {response.headers.get('x-request-id','')}")
            
            if response.status_code != HTTPStatus.OK.value:
                logger.error(f"!!! ОШИБКА !!! при DELETE запросе url - {url}: {response.status_code}. Сообщение об ошибке: {response.text}")
                if retries < MAX_RETRIES:
                    logger.error(f"Повторная попытка ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    has_errors = True
                    break
            else:
                result = response.json()
                if result.get('removed', False):
                    logger.info(f"Успех - группа {group_id} удалена из API")
                else:
                    logger.warning(f"Группа {group_id} не была удалена (возможно, не существует)")
                success = True
                break
                
    except requests.exceptions.RequestException as e:
        logger.error(f"!!! ERROR !!! {type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        has_errors = True
    except Exception as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        has_errors = True

    if has_errors:
        logger.error(f"Ошибка. Удаление группы {group_id} не удалось.")
        return False, {}

    return success, result


def save_group_members_to_csv(settings: "SettingParams", group_name: str, y360_member_users: list):
    """
    Сохраняет список членов группы из Yandex 360 в CSV файл для диагностики.
    
    Функция создает CSV файл с информацией о членах группы, включая:
    - ID пользователя
    - Nickname (логин)
    - Email
    - Полное имя (Фамилия Имя Отчество)
    - Должность
    - ID департамента
    
    Args:
        settings: Объект настроек с параметрами подключения
        group_name (str): Имя группы для использования в имени файла
        y360_member_users (list): Список пользователей-членов группы из API Y360
    
    Returns:
        bool: True если файл успешно сохранен, False в случае ошибки
    
    Example:
        success = save_group_members_to_csv(settings, "Sales Team", members_list)
        if success:
            print("CSV файл успешно создан")
    
    Note:
        Функция активна только при ENABLE_DIAGNOSTICS = True в настройках.
        Файлы сохраняются в каталоге, указанном в Y360_GROUP_MEMBERS_DIR.
    """
    if not settings.enable_diagnostics:
        logger.debug("Диагностика отключена, пропускаем сохранение файла с членами группы")
        return True
    
    try:
        # Создаем каталог для сохранения файлов, если он не существует
        os.makedirs(settings.y360_group_members_dir, exist_ok=True)
        
        # Формируем безопасное имя файла из имени группы
        # Убираем небезопасные символы для имени файла
        safe_group_name = "".join(c for c in group_name if c.isalnum() or c in (' ', '-', '_')).strip()
        safe_group_name = safe_group_name.replace(' ', '_')
        if not safe_group_name:
            safe_group_name = "unnamed_group"
        
        file_path = os.path.join(settings.y360_group_members_dir, f"{safe_group_name}.csv")
        
        # Записываем данные в CSV файл
        with open(file_path, 'w', newline='', encoding='utf-8-sig') as csvfile:
            # Определяем поля CSV
            fieldnames = ['id', 'nickname', 'email', 'last_name', 'first_name', 'middle_name', 'position', 'departmentId']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames, delimiter=';')
            
            # Записываем заголовки
            writer.writeheader()
            
            # Записываем данные пользователей
            for user in y360_member_users:
                name = user.get('name', {})
                row = {
                    'id': user.get('id', ''),
                    'nickname': user.get('nickname', ''),
                    'email': user.get('email', ''),
                    'last_name': name.get('last', ''),
                    'first_name': name.get('first', ''),
                    'middle_name': name.get('middle', ''),
                    'position': user.get('position', ''),
                    'departmentId': user.get('departmentId', '')
                }
                writer.writerow(row)
        
        logger.info(f"  [ДИАГНОСТИКА] Список членов группы '{group_name}' сохранен в файл: {file_path}")
        logger.info(f"  [ДИАГНОСТИКА] Сохранено пользователей: {len(y360_member_users)}")
        return True
        
    except Exception as e:
        logger.error(f"  [ДИАГНОСТИКА] Ошибка при сохранении файла с членами группы '{group_name}': {type(e).__name__}: {e}")
        return False


def sync_group_members(settings: "SettingParams", ad_groups: list, y360_groups: list, y360_users: list):
    """
    Синхронизирует списки членов групп между Active Directory и Yandex 360.
    
    Функция выполняет следующие действия:
    1. Для каждой группы в Yandex 360 с externalId, начинающимся с "DDG":
       - Запрашивает список членов группы в Yandex 360
       - Находит соответствующую группу в AD по objectGUID (извлекается из externalId)
       - Запрашивает список членов из AD через файл (get_group_members_from_file)
       - Сравнивает списки по nickname (Y360) и части до "@" в email (AD)
       - При сравнении учитываются алиасы пользователей из поля aliases
       - Добавляет недостающих пользователей в группу Yandex 360
       - Удаляет из группы Yandex 360 пользователей, которых нет в списке AD
    
    Args:
        settings: Объект настроек с параметрами подключения к API Yandex 360 
                  (включает атрибут members_files_dir - путь к каталогу с файлами списков членов групп)
        ad_groups: Список групп из Active Directory (результат get_ldap_dynamic_groups)
        y360_groups: Список групп из Yandex 360 (результат get_all_groups_from_api360)
        y360_users: Список пользователей из Yandex 360 (результат get_all_api360_users)
        
    Returns:
        tuple: (success: bool, stats: dict) - 
            success: True если синхронизация прошла успешно (может быть с предупреждениями)
            stats: Статистика синхронизации в формате:
                {
                    "y360_groups_processed": int,     # Количество обработанных групп в Y360
                    "ad_groups_found": int,           # Количество найденных соответствующих групп в AD
                    "users_added_count": int,         # Количество добавленных пользователей
                    "users_removed_count": int,       # Количество удаленных пользователей
                    "users_not_found_count": int,     # Количество пользователей не найденных в Y360
                    "errors_count": int,              # Количество ошибок
                    "skipped_groups_count": int       # Количество пропущенных групп
                }
    
    Example:
        # Получаем необходимые данные
        ad_groups = get_ldap_dynamic_groups(settings)
        y360_groups = get_all_groups_from_api360(settings)
        y360_users = get_all_api360_users(settings)
        
        # Путь к каталогу с файлами указывается в настройках settings.members_files_dir
        # (читается из переменной окружения GROUPS_MEMBERS_FILE_DIR)
        
        # Запускаем синхронизацию членов групп
        success, stats = sync_group_members(
            settings, 
            ad_groups, 
            y360_groups, 
            y360_users
        )
        
        if success:
            print(f"Синхронизация завершена успешно.")
            print(f"Добавлено пользователей: {stats['users_added_count']}")
            print(f"Удалено пользователей: {stats['users_removed_count']}")
        else:
            print(f"Синхронизация завершена с ошибками: {stats['errors_count']}")
    
    Note:
        - Функция обрабатывает только группы Y360 с externalId, начинающимся с "DDG;"
        - Для каждой группы в AD должен существовать CSV файл с членами группы
        - Имя файла формируется как "Группа_рассылки_{displayName}.csv"
        - Каталог с CSV файлами задается в настройках через settings.members_files_dir
          (читается из переменной окружения GROUPS_MEMBERS_FILE_DIR, по умолчанию ".")
        - В CSV файле email адреса должны быть во втором столбце
        - При сравнении учитываются алиасы пользователей (поле aliases):
          * Если у пользователя есть алиас, совпадающий с email из AD, пользователь не будет добавлен повторно
          * Пользователь не будет удален, если хотя бы один из его алиасов есть в списке AD
          * Алиасы имеют формат nickname (без символа "@")
        - Функция выполняет двустороннюю синхронизацию:
          * Добавляет пользователей из AD, которых нет в Y360
          * Удаляет из Y360 пользователей, которых нет в AD
    """
    logger.info("=" * 80)
    logger.info("Начало синхронизации членов групп из Active Directory в Yandex 360...")
    logger.info("=" * 80)
    
    # Инициализация статистики
    stats = {
        "y360_groups_processed": 0,
        "ad_groups_found": 0,
        "users_added_count": 0,
        "users_removed_count": 0,
        "users_not_found_count": 0,
        "errors_count": 0,
        "skipped_groups_count": 0
    }
    
    # Проверяем входные параметры
    if not ad_groups:
        logger.warning("Список групп из Active Directory пуст.")
        return True, stats
    
    if not y360_groups:
        logger.warning("Список групп из Yandex 360 пуст.")
        return True, stats
    
    if not y360_users:
        logger.warning("Список пользователей из Yandex 360 пуст.")
        return True, stats
    
    logger.info(f"Получено {len(ad_groups)} групп из Active Directory.")
    logger.info(f"Получено {len(y360_groups)} групп из Yandex 360.")
    logger.info(f"Получено {len(y360_users)} пользователей из Yandex 360.")
    logger.info("-" * 80)
    
    # Создаем словарь AD групп по objectGUID для быстрого поиска
    ad_groups_by_guid = {}
    for ad_group in ad_groups:
        object_guid = ad_group.get('objectGUID')
        if object_guid:
            ad_groups_by_guid[object_guid] = ad_group
    
    logger.info(f"Создан индекс для {len(ad_groups_by_guid)} групп из AD по objectGUID.")
    
    # Создаем словарь пользователей Y360 по nickname для быстрого поиска
    # Индексируем как по основному nickname, так и по алиасам
    y360_users_by_nickname = {}
    alias_count = 0
    
    for user in y360_users:
        nickname = user.get('nickname')
        if nickname:
            # Добавляем по основному nickname
            y360_users_by_nickname[nickname.lower()] = user
            
            # Добавляем по алиасам
            aliases = user.get('aliases', [])
            if aliases:
                for alias in aliases:
                    # Алиасы уже в формате nickname (без "@")
                    alias_lower = alias.lower()
                    y360_users_by_nickname[alias_lower] = user
                    alias_count += 1
                    logger.debug(f"  Индексирован алиас '{alias}' для пользователя '{nickname}'")
    
    logger.info(f"Создан индекс для {len(y360_users)} пользователей Y360.")
    logger.info(f"Всего уникальных nicknames (включая {alias_count} алиасов): {len(y360_users_by_nickname)}")
    logger.info("-" * 80)
    
    # Проходим по каждой группе в Yandex 360
    for y360_group in y360_groups:
        external_id = y360_group.get('externalId', '')
        
        # Проверяем, начинается ли externalId с "DDG;"
        if not external_id.startswith('DDG;'):
            continue
        
        group_name = y360_group.get('name', 'без имени')
        group_id = y360_group.get('id')
        
        stats["y360_groups_processed"] += 1
        
        logger.info(f"Обработка группы '{group_name}' (ID: {group_id}, externalId: {external_id})...")
        
        # Извлекаем objectGUID из externalId
        try:
            object_guid = external_id.split(';', 1)[1]
        except IndexError:
            logger.warning(f"  Некорректный формат externalId: '{external_id}'. Пропускаем группу.")
            stats["skipped_groups_count"] += 1
            continue
        
        # Находим соответствующую группу в AD
        ad_group = ad_groups_by_guid.get(object_guid)
        if not ad_group:
            logger.warning(f"  Группа с objectGUID '{object_guid}' не найдена в Active Directory. Пропускаем.")
            stats["skipped_groups_count"] += 1
            continue
        
        stats["ad_groups_found"] += 1
        logger.info(f"  Найдена соответствующая группа в AD: '{ad_group.get('displayName')}'")
        
        # Получаем список членов группы из Y360
        success_y360, y360_members_data = get_group_members_by_api(settings, group_id)
        if not success_y360:
            logger.error("  Ошибка при получении списка членов группы из Y360. Пропускаем группу.")
            stats["errors_count"] += 1
            continue
        
        # Извлекаем список пользователей-членов группы Y360
        y360_member_users = y360_members_data.get('users', [])
        
        # Сохраняем список членов группы в файл для диагностики (если включено)
        save_group_members_to_csv(settings, group_name, y360_member_users)
        
        y360_member_nicknames = set()
        
        for user in y360_member_users:
            # Добавляем основной nickname
            nickname = user.get('nickname')
            if nickname:
                y360_member_nicknames.add(nickname.lower())
            
            # Добавляем алиасы пользователя
            aliases = y360_users_by_nickname.get(nickname.lower()).get('aliases', [])
            if aliases:
                for alias in aliases:
                    # Алиасы уже в формате nickname (без "@")
                    alias_lower = alias.lower()
                    y360_member_nicknames.add(alias_lower)
                    logger.debug(f"    Добавлен алиас '{alias}' для пользователя '{nickname}'")
        
        logger.info(f"  Текущее количество пользователей в группе Y360: {len(y360_member_users)}")
        logger.info(f"  Уникальных nicknames (включая алиасы): {len(y360_member_nicknames)}")
        
        # Получаем список членов группы из файла AD
        ad_member_emails = get_group_members_from_file(ad_group, settings.members_files_dir)
        if not ad_member_emails:
            logger.warning(f"  Файл с членами группы {ad_group['displayName']} из AD не найден или пуст. Пропускаем группу.")
            stats["skipped_groups_count"] += 1
            continue
        
        logger.info(f"  Количество членов группы {ad_group['displayName']} в файле AD: {len(ad_member_emails)}")
        
        # Создаем множество nickname из AD для быстрого поиска и сравнения
        ad_nicknames_set = set()
        for ad_email in ad_member_emails:
            # Извлекаем часть до "@"
            if '@' in ad_email:
                ad_nickname = ad_email.split('@')[0].lower()
                ad_nicknames_set.add(ad_nickname)
            else:
                logger.warning(f"  Некорректный формат email в AD: '{ad_email}'. Пропускаем.")
        
        logger.debug(f"  Уникальных nickname из AD: {len(ad_nicknames_set)}")
        
        # Сравниваем списки и находим пользователей для добавления
        users_to_add = []
        for ad_nickname in ad_nicknames_set:
            # Проверяем, есть ли пользователь в группе Y360
            if ad_nickname not in y360_member_nicknames:
                # Пользователь не в группе, нужно добавить
                # Находим пользователя в списке всех пользователей Y360
                y360_user = y360_users_by_nickname.get(ad_nickname)
                if y360_user:
                    users_to_add.append({
                        'nickname': ad_nickname,
                        'user_id': y360_user.get('id')
                    })
                else:
                    logger.warning(f"  Пользователь '{ad_nickname}' не найден в списке пользователей Y360.")
                    stats["users_not_found_count"] += 1
        
        # Находим пользователей для удаления (есть в Y360, но нет в AD)
        users_to_remove = []
        for y360_user in y360_member_users:
            nickname = y360_user.get('nickname')
            if nickname:
                nickname_lower = nickname.lower()
                if nickname_lower not in ad_nicknames_set:
                    users_to_remove.append({
                        'nickname': nickname,
                        'user_id': y360_user.get('id')
                    })
        
        if users_to_add:
            logger.info(f"  Найдено {len(users_to_add)} пользователей для добавления в группу {group_name}.")
            
            for user_info in users_to_add:
                logger.info(f"    Добавление пользователя '{user_info['nickname']}' (ID: {user_info['user_id']}) в группу {group_name}...")
                
                if not settings.dry_run:
                    success_add, result = add_member_to_group_by_api(
                        settings, 
                        group_id, 
                        'user', 
                        user_info['user_id']
                    )
                    
                    if success_add and result.get('added'):
                        stats["users_added_count"] += 1
                        logger.info(f"      ✓ Пользователь '{user_info['nickname']}' успешно добавлен в группу {group_name}")
                    elif success_add and not result.get('added'):
                        logger.info(f"      ⚠ Пользователь '{user_info['nickname']}' уже является членом группы {group_name}")
                    else:
                        stats["errors_count"] += 1
                        logger.error(f"      ✗ Ошибка при добавлении пользователя '{user_info['nickname']}' в группу {group_name}")
                    
                    # Небольшая задержка между вызовами API
                    time.sleep(SLEEP_TIME_BETWEEN_API_CALLS)
                else:
                    logger.info(f"      DRY RUN: Пользователь '{user_info['nickname']}' будет добавлен в группу {group_name}")
                    stats["users_added_count"] += 1
        else:
            logger.info(f"  Нет пользователей для добавления в группу {group_name}.")
        
        # Удаляем пользователей, которые есть в Y360, но нет в AD
        if users_to_remove:
            logger.info(f"  Найдено {len(users_to_remove)} пользователей для удаления из группы {group_name}.")
            
            for user_info in users_to_remove:
                logger.info(f"    Удаление пользователя '{user_info['nickname']}' (ID: {user_info['user_id']}) из группы {group_name}...")
                
                if not settings.dry_run:
                    success_remove, result = delete_member_from_group_by_api(
                        settings, 
                        group_id, 
                        'user', 
                        user_info['user_id']
                    )
                    
                    if success_remove and result.get('deleted'):
                        stats["users_removed_count"] += 1
                        logger.info(f"      ✓ Пользователь '{user_info['nickname']}' успешно удален из группы {group_name}")
                    elif success_remove and not result.get('deleted'):
                        logger.info(f"      ⚠ Пользователь '{user_info['nickname']}' не является членом группы {group_name}")
                    else:
                        stats["errors_count"] += 1
                        logger.error(f"      ✗ Ошибка при удалении пользователя '{user_info['nickname']}' из группы {group_name}")
                    
                    # Небольшая задержка между вызовами API
                    time.sleep(SLEEP_TIME_BETWEEN_API_CALLS)
                else:
                    logger.info(f"      DRY RUN: Пользователь '{user_info['nickname']}' будет удален из группы {group_name}")
                    stats["users_removed_count"] += 1
        else:
            logger.info(f"  Нет пользователей для удаления из группы {group_name}.")
        
        # Итоговая информация по группе
        if not users_to_add and not users_to_remove:
            logger.info(f"  ✓ Группа {group_name} полностью синхронизирована. Изменения не требуются.")
        
        logger.info("-" * 80)
    
    # Выводим итоговую статистику
    logger.info("=" * 80)
    logger.info("Синхронизация членов групп завершена.")
    logger.info("-" * 80)
    logger.info(f"Обработано групп Y360 с префиксом 'DDG': {stats['y360_groups_processed']}")
    logger.info(f"Найдено соответствующих групп в AD: {stats['ad_groups_found']}")
    logger.info(f"Добавлено пользователей в группы: {stats['users_added_count']}")
    logger.info(f"Удалено пользователей из групп: {stats['users_removed_count']}")
    if stats['users_not_found_count'] > 0:
        logger.warning(f"Пользователей не найдено в Y360: {stats['users_not_found_count']}")
    if stats['skipped_groups_count'] > 0:
        logger.warning(f"Пропущено групп: {stats['skipped_groups_count']}")
    if stats['errors_count'] > 0:
        logger.error(f"Ошибок при синхронизации пользователей: {stats['errors_count']}")
    logger.info("=" * 80)
    
    success = stats['errors_count'] == 0
    return success, stats


def sync_ad_groups_to_y360(settings: "SettingParams", ad_groups: list, y360_groups: list):
    """
    Синхронизирует динамические группы рассылки из Active Directory в Yandex 360.
    
    Функция выполняет следующие действия:
    1. Принимает списки групп из AD и Y360
    2. Сравнивает списки по objectGUID (из AD) и externalId (из Y360) в формате "DDG;<objectGUID>"
    3. Для групп, отсутствующих в Y360 - создает их
    4. Для существующих групп - проверяет соответствие полей (name, label, description) и обновляет при необходимости
    5. Удаляет из Y360 группы с externalId "DDG;*", которых больше нет в AD
    
    Args:
        settings: Объект настроек с параметрами подключения к API Yandex 360
        ad_groups: Список словарей с группами из Active Directory (результат get_ldap_dynamic_groups)
        y360_groups: Список словарей с группами из Yandex 360 (результат get_all_groups_from_api360)
        
    Returns:
        tuple: (success: bool, stats: dict) - 
            success: True если синхронизация прошла успешно (может быть с предупреждениями)
            stats: Статистика синхронизации в формате:
                {
                    "ad_groups_count": int,      # Количество групп в AD
                    "y360_groups_count": int,    # Количество групп в Y360
                    "created_count": int,        # Количество созданных групп
                    "updated_count": int,        # Количество обновленных групп
                    "deleted_count": int,        # Количество удаленных групп из Y360
                    "errors_count": int,         # Количество ошибок при создании/обновлении/удалении
                    "skipped_count": int         # Количество пропущенных групп (без обязательных атрибутов)
                }
    
    Example:
        # Получаем списки групп
        ad_groups = get_ldap_dynamic_groups(settings)
        y360_groups = get_all_groups_from_api360(settings)
        
        # Запускаем синхронизацию
        success, stats = sync_ad_groups_to_y360(settings, ad_groups, y360_groups)
        
        if success:
            print(f"Синхронизация завершена успешно.")
            print(f"Создано групп: {stats['created_count']}")
            print(f"Обновлено групп: {stats['updated_count']}")
            print(f"Удалено групп: {stats['deleted_count']}")
        else:
            print(f"Синхронизация завершена с ошибками: {stats['errors_count']}")
    
    Note:
        Для корректной работы функции необходимо добавить атрибут 'objectGUID' в ATTRIB_GROUP_LIST 
        в файле .env_ldap:
        ATTRIB_GROUP_LIST = distinguishedName,mail,displayName,description,objectCategory,sAMAccountName,msExchQueryFilter,cn,objectClass,objectGUID
        
        Функция сравнивает следующие поля:
        - name (Y360) с displayName (AD)
        - label (Y360) с частью до "@" из mail (AD)
        - description (Y360) с description (AD)
        
        ВАЖНО: Функция удаляет из Yandex 360 группы с externalId, начинающимся с "DDG;", 
        если соответствующий objectGUID не найден в Active Directory. Группы без externalId 
        или с другим префиксом не удаляются.
    """
    logger.info("=" * 80)
    logger.info("Начало синхронизации групп из Active Directory в Yandex 360...")
    logger.info("=" * 80)
    
    # Инициализация статистики
    stats = {
        "ad_groups_count": 0,
        "y360_groups_count": 0,
        "created_count": 0,
        "updated_count": 0,
        "deleted_count": 0,
        "errors_count": 0,
        "skipped_count": 0
    }
    
    # Проверяем входные параметры
    if ad_groups is None:
        ad_groups = []
    if y360_groups is None:
        y360_groups = []
    
    if not ad_groups:
        logger.warning("Список групп из Active Directory пуст.")
        return True, stats
    
    stats["ad_groups_count"] = len(ad_groups)
    logger.info(f"Получено {len(ad_groups)} динамических групп рассылки из Active Directory.")
    
    stats["y360_groups_count"] = len(y360_groups)
    logger.info(f"Получено {len(y360_groups)} групп из Yandex 360.")
    
    # Создаем словарь групп Y360 по externalId для быстрого поиска
    y360_groups_by_external_id = {}
    for group in y360_groups:
        external_id = group.get('externalId', '')
        if external_id:
            y360_groups_by_external_id[external_id] = group
    
    logger.info(f"Из них {len(y360_groups_by_external_id)} групп имеют externalId.")
    logger.info("-" * 80)
    
    # Проходим по каждой группе из AD
    for ad_group in ad_groups:
        object_guid = ad_group.get('objectGUID')
        display_name = ad_group.get('displayName')
        mail = ad_group.get('mail')
        description = ad_group.get('description')
        
        # Проверяем обязательные поля
        if not object_guid:
            logger.warning(f"Группа '{display_name or 'без имени'}' не имеет objectGUID. Пропускаем.")
            logger.warning("Убедитесь, что атрибут 'objectGUID' добавлен в ATTRIB_GROUP_LIST в файле .env_ldap")
            stats["skipped_count"] += 1
            continue
        
        if not display_name:
            logger.warning(f"Группа с objectGUID '{object_guid}' не имеет displayName. Пропускаем.")
            stats["skipped_count"] += 1
            continue

        if not mail:
            logger.warning(f"Группа с objectGUID '{object_guid}' не имеет атрибута mail. Пропускаем.")
            stats["skipped_count"] += 1
            continue
        
        # Формируем externalId в формате "DDG;<objectGUID>"
        external_id = f"DDG;{object_guid}"
        
        # Формируем ожидаемые значения полей
        expected_label = mail.split('@')[0] if mail and '@' in mail else None
        expected_description = description if description else ""
        
        # Проверяем, существует ли группа в Y360
        if external_id in y360_groups_by_external_id:
            # Группа существует, проверяем поля
            y360_group = y360_groups_by_external_id[external_id]
            group_id = y360_group.get('id')
            
            # Словарь для изменений
            changes_needed = {}
            
            # Проверяем name
            y360_name = y360_group.get('name', '')
            if y360_name != display_name:
                logger.info(f"Группа '{display_name}' (ID: {group_id}): поле 'name' отличается.")
                logger.info(f"  В Y360: '{y360_name}' → В AD: '{display_name}'")
                changes_needed['name'] = display_name
            
            # Проверяем label
            y360_label = y360_group.get('label', '')
            if expected_label:
                if y360_label != expected_label:
                    logger.info(f"Группа '{display_name}' (ID: {group_id}): поле 'label' отличается.")
                    logger.info(f"  В Y360: '{y360_label}' → В AD: '{expected_label}'")
                    changes_needed['label'] = expected_label
            
            # Проверяем description
            y360_description = y360_group.get('description', '')
            if y360_description != expected_description:
                logger.info(f"Группа '{display_name}' (ID: {group_id}): поле 'description' отличается.")
                logger.info(f"  В Y360: '{y360_description}' → В AD: '{expected_description}'")
                changes_needed['description'] = expected_description
            
            # Если есть изменения, обновляем группу
            if changes_needed:
                logger.info(f"Обновление группы '{display_name}' (ID: {group_id})...")
                if not settings.dry_run:
                    success, updated_group = patch_group_by_api(settings, group_id, changes_needed)
                    if success:
                        stats["updated_count"] += 1
                        logger.info(f"  ✓ Группа '{display_name}' успешно обновлена")
                    else:
                        stats["errors_count"] += 1
                        logger.error(f"  ✗ Ошибка при обновлении группы '{display_name}'")
                else:
                    logger.info(f"  DRY RUN: Группа '{display_name}' будет обновлена с параметрами: {changes_needed}")
                    stats["updated_count"] += 1
                
                # Небольшая задержка между вызовами API
                if not settings.dry_run:
                    time.sleep(SLEEP_TIME_BETWEEN_API_CALLS)
            else:
                logger.debug(f"Группа '{display_name}' (externalId: {external_id}) в актуальном состоянии.")
            
            continue
        
        # Группы нет в Y360, создаем её
        logger.info(f"Группа '{display_name}' не найдена в Yandex 360. Создаем...")
        
        # Формируем данные для создания группы
        group_data = {
            "name": display_name,
            "externalId": external_id
        }
        
        # Добавляем label (часть до @ из mail)
        if mail:
            if '@' in mail:
                label = mail.split('@')[0]
                group_data['label'] = label
                logger.debug(f"  - Label: {label}")
            else:
                logger.warning(f"  - Некорректный формат mail '{mail}'. Label не установлен.")
        else:
            logger.debug(f"  - Mail не указан для группы '{display_name}'. Label не установлен.")
        
        # Добавляем description, если есть
        if description:
            group_data['description'] = description
            logger.debug(f"  - Description: {description}")
        
        # Создаем группу
        if not settings.dry_run:
            success, created_group = create_group_by_api(settings, group_data)
            if success:
                stats["created_count"] += 1
                logger.info(f"  ✓ Группа '{display_name}' успешно создана (ID: {created_group.get('id', 'N/A')})")
            else:
                stats["errors_count"] += 1
                logger.error(f"  ✗ Ошибка при создании группы '{display_name}'")
        else:
            logger.info(f"  DRY RUN: Группа '{display_name}' будет создана с параметрами: {group_data}")
            stats["created_count"] += 1
        
        # Небольшая задержка между вызовами API
        if not settings.dry_run:
            time.sleep(SLEEP_TIME_BETWEEN_API_CALLS)
    
    # Проверяем группы из Y360, которых нет в AD (для удаления)
    logger.info("-" * 80)
    logger.info("Проверка групп в Yandex 360, которых нет в Active Directory...")
    
    # Создаем множество objectGUID из AD для быстрой проверки
    ad_object_guids = set()
    for ad_group in ad_groups:
        object_guid = ad_group.get('objectGUID')
        if object_guid:
            ad_object_guids.add(object_guid)
    
    logger.info(f"Уникальных objectGUID в AD: {len(ad_object_guids)}")
    
    # Проходим по группам Y360 с externalId, начинающимся с "DDG"
    groups_to_delete = []
    for y360_group in y360_groups:
        external_id = y360_group.get('externalId', '')
        
        # Проверяем, начинается ли externalId с "DDG"
        if external_id.startswith('DDG;'):
            # Извлекаем objectGUID из externalId (формат: "DDG;<objectGUID>")
            try:
                object_guid = external_id.split(';', 1)[1]
            except IndexError:
                logger.warning(f"Некорректный формат externalId для группы '{y360_group.get('name')}': '{external_id}'")
                continue
            
            # Проверяем, есть ли такой objectGUID в AD
            if object_guid not in ad_object_guids:
                groups_to_delete.append({
                    'id': y360_group.get('id'),
                    'name': y360_group.get('name'),
                    'externalId': external_id,
                    'objectGUID': object_guid
                })
    
    if groups_to_delete:
        logger.info(f"Найдено {len(groups_to_delete)} групп для удаления из Yandex 360.")
        logger.info("-" * 80)
        
        for group in groups_to_delete:
            logger.info(f"Удаление группы '{group['name']}' (ID: {group['id']}, objectGUID: {group['objectGUID']})...")
            logger.info("  Причина: группа не найдена в Active Directory")
            
            if not settings.dry_run:
                success, result = delete_group_by_api(settings, group['id'])
                if success and result.get('removed'):
                    stats["deleted_count"] += 1
                    logger.info(f"  ✓ Группа '{group['name']}' успешно удалена")
                else:
                    stats["errors_count"] += 1
                    logger.error(f"  ✗ Ошибка при удалении группы '{group['name']}'")
            else:
                logger.info(f"  DRY RUN: Группа '{group['name']}' будет удалена")
                stats["deleted_count"] += 1
            
            # Небольшая задержка между вызовами API
            if not settings.dry_run:
                time.sleep(SLEEP_TIME_BETWEEN_API_CALLS)
    else:
        logger.info("Групп для удаления не найдено. Все группы в Y360 присутствуют в AD.")
    
    # Выводим итоговую статистику
    logger.info("=" * 80)
    logger.info("Синхронизация групп завершена.")
    logger.info("-" * 80)
    logger.info(f"Групп в Active Directory: {stats['ad_groups_count']}")
    logger.info(f"Групп в Yandex 360: {stats['y360_groups_count']}")
    logger.info(f"Создано новых групп: {stats['created_count']}")
    if stats['updated_count'] > 0:
        logger.info(f"Обновлено существующих групп: {stats['updated_count']}")
    if stats['deleted_count'] > 0:
        logger.info(f"Удалено групп из Yandex 360: {stats['deleted_count']}")
    if stats['skipped_count'] > 0:
        logger.warning(f"Пропущено групп (отсутствуют обязательные атрибуты): {stats['skipped_count']}")
    if stats['errors_count'] > 0:
        logger.error(f"Ошибок при создании/обновлении/удалении групп: {stats['errors_count']}")
    logger.info("=" * 80)
    
    success = stats['errors_count'] == 0
    return success, stats



if __name__ == "__main__":
    denv_path = os.path.join(os.path.dirname(__file__), '.env_ldap')

    if os.path.exists(denv_path):
        load_dotenv(dotenv_path=denv_path,verbose=True, override=True)
    else:
        logger.error("Не найден файл .env_ldap. Выход.")
        sys.exit(EXIT_CODE)
    
    logger.info("\n")
    logger.info("---------------------------------------------------------------------------.")
    logger.info("Запуск скрипта.")
    
    settings = get_settings()
    
    if settings is None:
        logger.error("Проверьте настройки в файле .env_ldap и попробуйте снова.")
        sys.exit(EXIT_CODE)

    if settings.dry_run:
        logger.info('- Режим тестового прогона включен (DRY_RUN = True)! Изменения не сохраняются! -')

    # Шаг 1: Получаем список пользователей из Яндекс 360
    logger.info("=" * 80)
    logger.info("Шаг 1: Получение списка пользователей из Yandex 360")
    logger.info("=" * 80)
    y360_users = get_all_api360_users(settings)
    if not y360_users:
        logger.error('\n')
        logger.error('List of users from Yandex 360 is empty. Exit.\n')
        sys.exit(EXIT_CODE)
    logger.info(f"Успешно получено пользователей из Yandex 360: {len(y360_users)}")
    
    # Шаг 2: Получаем список групп из Active Directory
    logger.info("\n")
    logger.info("=" * 80)
    logger.info("Шаг 2: Получение списка групп из Active Directory")
    logger.info("=" * 80)
    ad_groups = get_ldap_dynamic_groups(settings)
    if not ad_groups:
        logger.error('\n')
        logger.error('List of groups from Active Directory is empty. Exit.\n')
        sys.exit(EXIT_CODE)
    logger.info(f"Успешно получено групп из Active Directory: {len(ad_groups)}")
    
    # Шаг 3: Получаем список групп из Yandex 360 (первый раз - для синхронизации групп)
    logger.info("\n")
    logger.info("=" * 80)
    logger.info("Шаг 3: Получение списка групп из Yandex 360 (для синхронизации групп)")
    logger.info("=" * 80)
    y360_groups = get_all_groups_from_api360(settings)
    if y360_groups is None:
        logger.error('\n')
        logger.error('Failed to get groups from Yandex 360. Exit.\n')
        sys.exit(EXIT_CODE)
    logger.info(f"Успешно получено групп из Yandex 360: {len(y360_groups)}")
    
    # Шаг 4: Синхронизируем группы с Yandex 360
    logger.info("\n")
    logger.info("=" * 80)
    logger.info("Шаг 4: Синхронизация групп с Yandex 360")
    logger.info("=" * 80)
    success, stats = sync_ad_groups_to_y360(settings, ad_groups, y360_groups)
    if not success:
        logger.warning("Синхронизация групп завершена с ошибками, но продолжаем выполнение.")
    
    # Шаг 5: Повторно получаем список групп из Yandex 360 (после синхронизации)
    logger.info("\n")
    logger.info("=" * 80)
    logger.info("Шаг 5: Повторное получение списка групп из Yandex 360 (после синхронизации)")
    logger.info("=" * 80)
    y360_groups_updated = get_all_groups_from_api360(settings)
    if y360_groups_updated is None:
        logger.error('\n')
        logger.error('Failed to get updated groups from Yandex 360. Exit.\n')
        sys.exit(EXIT_CODE)
    logger.info(f"Успешно получено групп из Yandex 360: {len(y360_groups_updated)}")
    
    # Шаг 6: Синхронизируем членство в группах
    logger.info("\n")
    logger.info("=" * 80)
    logger.info("Шаг 6: Синхронизация членства в группах")
    logger.info("=" * 80)
    members_success, members_stats = sync_group_members(settings, ad_groups, y360_groups_updated, y360_users)
    if not members_success:
        logger.warning("Синхронизация членства завершена с ошибками.")

    # Итоговая информация
    logger.info("\n")
    logger.info("=" * 80)
    logger.info("ИТОГОВАЯ ИНФОРМАЦИЯ")
    logger.info("=" * 80)
    logger.info(f"Пользователей в Yandex 360: {len(y360_users)}")
    logger.info(f"Групп в Active Directory: {len(ad_groups)}")
    logger.info(f"Групп в Yandex 360 (после синхронизации): {len(y360_groups_updated)}")
    logger.info("-" * 80)
    logger.info("Статистика синхронизации групп:")
    logger.info(f"  - Создано новых групп: {stats.get('created_count', 0)}")
    logger.info(f"  - Обновлено групп: {stats.get('updated_count', 0)}")
    logger.info(f"  - Удалено групп: {stats.get('deleted_count', 0)}")
    logger.info(f"  - Пропущено групп: {stats.get('skipped_count', 0)}")
    logger.info(f"  - Ошибок: {stats.get('errors_count', 0)}")
    logger.info("-" * 80)
    logger.info("Статистика синхронизации членства:")
    logger.info(f"  - Обработано групп: {members_stats.get('processed_groups', 0)}")
    logger.info(f"  - Пропущено групп: {members_stats.get('skipped_groups', 0)}")
    logger.info(f"  - Добавлено участников: {members_stats.get('added_members', 0)}")
    logger.info(f"  - Удалено участников: {members_stats.get('removed_members', 0)}")
    logger.info(f"  - Ошибок при добавлении: {members_stats.get('add_errors', 0)}")
    logger.info(f"  - Ошибок при удалении: {members_stats.get('remove_errors', 0)}")
    logger.info("=" * 80)

    logger.info('---------------End-----------------')

  