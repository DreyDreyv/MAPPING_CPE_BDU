import pandas as pd
import re, requests
import xml.etree.ElementTree as ET

# Чтение файла Similarity.xlsx
mapping_df = pd.read_excel('Similarity.xlsx', header=None)

def parse_cpe(cpe_str):
    """Парсит строку CPE и возвращает словарь с полями."""
    if cpe_str.startswith("wfn:"):
        fields = re.findall(r'(\w+)=("([^"]+)"|ANY)', cpe_str)
        cpe_dict = {k: v.strip('"').replace('ANY', '').replace('NA', '') for k, v, _ in fields}
    elif cpe_str.startswith("cpe:2.3:"):
        parts = cpe_str.split(':')
        cpe_dict = {
            'part': parts[2].replace('/', ''),
            'vendor': parts[3],
            'product': parts[4],
            'version': parts[5],
            'update': parts[6],
            'edition': parts[7] ,
            'target_hw': parts[11] if parts[11] != '*' else 'Не указана'
        }
    elif cpe_str.startswith("cpe:/"):
        parts = cpe_str.split(':')
        target_hw = parts[-1].replace('~', '') if parts[-1].replace('~', '') != '' else 'Не указана'
        edition = parts[6].strip() if parts[6].strip()[0] != '~' else ''
        cpe_dict = {
            'part': parts[1].replace('/', ''),
            'vendor': parts[2],
            'product': parts[3],
            'version': parts[4],
            'update': parts[5],
            'edition': edition,
            'target_hw': target_hw
        }
    return cpe_dict

def get_software_type(part):
    """Возвращает тип ПО по CPE."""
    return {
        'o': 'Операционная система',
        'a': 'Прикладное ПО информационных систем',
        'h': 'Микропрограммный код'
    }.get(part, 'Неизвестный тип')

def convert_to_bdu(cpe_dict):
    """Конвертирует CPE в формат БДУ на основе сопоставлений."""
    for _, row in mapping_df.iterrows():
        if row[4] == cpe_dict['vendor'] and row[5] == cpe_dict['product']:
            version = f"{cpe_dict['version']} {cpe_dict['update']} {cpe_dict['edition']}".strip().replace('*', '').replace('  ', '')
            if not version:
                version = "-"
            bdu_str = f"{row[0]},{row[1]},{row[2]},{version},{cpe_dict['target_hw']}"
            return bdu_str
        elif row[4] == cpe_dict['vendor']:
            software_type = get_software_type(cpe_dict['part'])
            product_name = cpe_dict['product'].replace('_', ' ')
            version = f"{cpe_dict['version']} {cpe_dict['update']} {cpe_dict['edition']}".strip().replace('*', '').replace('  ', '')
            if not version:
                version = "-"
            bdu_str = f"{software_type},{row[1]},{product_name},{version},{cpe_dict['target_hw']}"
            return bdu_str

    # Если совпадений нет
    software_type = get_software_type(cpe_dict['part'])
    product_name = cpe_dict['product'].replace('_', ' ')
    version = f"{cpe_dict['version']} {cpe_dict['update']} {cpe_dict['edition']}".strip().replace('*', '').replace('  ', '')
    if not version:
        version = "-"
    bdu_str = f"{software_type},{cpe_dict['vendor']},{product_name},{version},{cpe_dict['target_hw']}"
    return bdu_str


def ver_prod(item):
    """Собирает версии, вендоров, типы и названия продуктов с JSON-файла."""
    ver = []
    prod = []
    vendors = []
    parts = []
    
    configurations = item['vulnerabilities'][0]['cve']['configurations']
    for configuration in configurations:
        for node in configuration['nodes']:
            for cpe_match in node['cpeMatch']:
                criteria = cpe_match['criteria'].split(":")
                part = criteria[2]
                vendor = criteria[3]
                product = criteria[4]
                version = criteria[5]

                if 'versionStartIncluding' in cpe_match and 'versionEndExcluding' in cpe_match:
                    ver.append(f"от {cpe_match['versionStartIncluding']} до {cpe_match['versionEndExcluding']}")
                elif 'versionStartIncluding' in cpe_match and 'versionEndIncluding' in cpe_match:
                    ver.append(f"от {cpe_match['versionStartIncluding']} до {cpe_match['versionEndIncluding']} включительно")
                elif 'versionStartExcluding' in cpe_match and 'versionEndIncluding' in cpe_match:
                    ver.append(f"от {cpe_match['versionStartExcluding']} до {cpe_match['versionEndIncluding']} включительно")
                elif 'versionStartExcluding' in cpe_match and 'versionEndExcluding' in cpe_match:
                    ver.append(f"от {cpe_match['versionStartExcluding']} до {cpe_match['versionEndExcluding']}")
                elif 'versionEndIncluding' in cpe_match:
                    ver.append(f"до {cpe_match['versionEndIncluding']} включительно")
                elif 'versionEndExcluding' in cpe_match:
                    ver.append(f"до {cpe_match['versionEndExcluding']}")
                else:
                    ver.append(version)

                parts.append(part)
                prod.append(product)
                vendors.append(vendor)

    return vendors, prod, ver, parts



def convert_to_bdu_from_nvd(cve):
    """Конвертирует данные из NVD в формат БДУ на основе сопоставлений."""
    # Получение данных по CVE из NVD API
    response = requests.get(f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}')
    if response.status_code != 200:
        return "Ошибка получения данных из NVD"

    item = response.json()
    vendors, products, versions, parts = ver_prod(item)

    bdu_entries = []
    for vendor, product, version, part in zip(vendors, products, versions, parts):
        found = False
        for _, row in mapping_df.iterrows():
            if row[4] == vendor:
                if row[5] == product:
                    # Полное соответствие найдено
                    bdu_entries.append(f"{row[0]},{row[1]},{row[2]},{version},Не указана")
                    found = True
                    break
                else:
                    # Только вендор найден
                    software_type = get_software_type(part)
                    bdu_entries.append(f"{software_type},{vendor},{product.replace('_', ' ')},{version},Не указана")
                    found = True
                    break

        if not found:
            # Соответствие не найдено
            software_type = get_software_type(part)
            bdu_entries.append(f"{software_type},{vendor},{product.replace('_', ' ')},{version},Не указана")

    return bdu_entries



# Парсинг XML словаря CPE
def parse_cpe_dictionary(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    cpe_items = []
    for cpe_item in root.findall('.//{http://cpe.mitre.org/dictionary/2.0}cpe-item'):
        cpe23_item = cpe_item.find('{http://scap.nist.gov/schema/cpe-extension/2.3}cpe23-item')
        if cpe23_item is not None:
            cpe_name = cpe23_item.get('name')
            cpe_items.append(cpe_name)
    return cpe_items

# Загрузка XML словаря
cpe_items = parse_cpe_dictionary('official-cpe-dictionary_v2.3.xml')

def check_version_format(version_str):
    patterns = [
        r'\d+(\.\d+)*[a-zA-Z]*',  # версия с возможными буквами
        r'от \d+(\.\d+)*[a-zA-Z]*',  # от версия с возможными буквами
        r'от \d+(\.\d+)*[a-zA-Z]* включительно',  # от версия включительно
        r'до \d+(\.\d+)*[a-zA-Z]*',  # до версия с возможными буквами
        r'до \d+(\.\d+)*[a-zA-Z]* включительно',  # до версия включительно
        r'от \d+(\.\d+)*[a-zA-Z]* до \d+(\.\d+)*[a-zA-Z]*',  # от версия до версия
        r'от \d+(\.\d+)*[a-zA-Z]* до \d+(\.\d+)*[a-zA-Z]* включительно',  # от версия до версия включительно
        r'от \d+(\.\d+)*[a-zA-Z]* включительно до \d+(\.\d+)*[a-zA-Z]* включительно',  # от версия включительно до версия включительно
        r'от \d+(\.\d+)*[a-zA-Z]* включительно до \d+(\.\d+)*[a-zA-Z]*',  # от версия включительно до версия
    ]
    for pattern in patterns:
        if re.match(pattern, version_str):
            return True
    print(f"Неверный формат версии: {version_str}")
    return False

def find_cpe_versions(cpe_type, vendor, product, bdu_version, bdu_platform):
    """Находит соответствующие версии CPE для заданного диапазона версий."""
    filtered_cpe_versions = []

    if bdu_platform == 'Не указана':
        bdu_platform = '*'

    # Определение начала и конца версии на основе строки BDU
    version_parts = re.findall(r'(\S+)', bdu_version)

    start_version = None
    end_version = None
    inclusive_start = False
    inclusive_end = False

    if "от" in bdu_version and "до" in bdu_version and bdu_version.count("включительно") == 2:
        if len(version_parts) != 6:
            print(f"Ошибка парсинга версий в строке: {bdu_version}")
            return []
        start_version = version_parts[1]
        end_version = version_parts[4]
        inclusive_start = True
        inclusive_end = True

    elif "от" in bdu_version and "включительно" in bdu_version and "до" in bdu_version:
        if len(version_parts) != 5:
            print(f"Ошибка парсинга версий в строке: {bdu_version}")
            return []
        if version_parts[2] == "включительно":
            start_version = version_parts[1]
            end_version = version_parts[4]
            inclusive_start = True

        else:
            start_version = version_parts[1]
            end_version = version_parts[3]
            inclusive_end = True

    elif "от" in bdu_version and "до" in bdu_version:
        if len(version_parts) != 4:
            print(f"Ошибка парсинга версий в строке: {bdu_version}")
            return []
        start_version = version_parts[1]
        end_version = version_parts[3]

    elif "от" in bdu_version and "включительно" in bdu_version:
        if len(version_parts) != 3:
            print(f"Ошибка парсинга версии в строке: {bdu_version}")
            return []
        start_version = version_parts[1]
        inclusive_start = True

    elif "от" in bdu_version:
        if len(version_parts) != 2:
            print(f"Ошибка парсинга версии в строке: {bdu_version}")
            return []
        start_version = version_parts[1]

    elif "до" in bdu_version and "включительно" in bdu_version:
        if len(version_parts) != 3:
            print(f"Ошибка парсинга версии в строке: {bdu_version}")
            return []
        end_version = version_parts[2]
        inclusive_end = True

    elif "до" in bdu_version:
        if len(version_parts) != 2:
            print(f"Ошибка парсинга версии в строке: {bdu_version}")
            return []
        end_version = version_parts[1]

    else:
        start_version = bdu_version
        end_version = bdu_version

    found_start_version = False
    found_end_version = False  # Флаг, что версия конца диапазона найдена

    # Проход по всем элементам словаря CPE
    for cpe_item in cpe_items:
        cpe_parts = cpe_item.split(':')
        cpe_version = cpe_parts[5]

        # Сравнение типа ПО, вендора и продукта
        if cpe_parts[2] == cpe_type and cpe_parts[3] == vendor and cpe_parts[4].startswith(product):
            if start_version and end_version:
                if (start_version < cpe_version or (inclusive_start and start_version == cpe_version)) and \
                   (cpe_version < end_version or (inclusive_end and cpe_version == end_version)):
                    cpe_result = f"cpe:2.3:{cpe_type}:{vendor}:{product}:{cpe_version}:*:*:*:*:*:{bdu_platform}:*"
                    filtered_cpe_versions.append(cpe_result)
                if cpe_version == end_version:
                    found_end_version = True
                if cpe_version == start_version:
                    found_start_version = True
            elif start_version:
                if start_version < cpe_version or (inclusive_start and start_version == cpe_version):
                    cpe_result = f"cpe:2.3:{cpe_type}:{vendor}:{product}:{cpe_version}:*:*:*:*:*:{bdu_platform}:*"
                    filtered_cpe_versions.append(cpe_result)
            elif end_version:
                if cpe_version < end_version or (inclusive_end and cpe_version == end_version):
                    cpe_result = f"cpe:2.3:{cpe_type}:{vendor}:{product}:{cpe_version}:*:*:*:*:*:{bdu_platform}:*"
                    filtered_cpe_versions.append(cpe_result)
                if cpe_version == end_version:
                    found_end_version = True
                if cpe_version == start_version:
                    found_start_version = True

    # Если версия конца диапазона не была найдена, но она должна быть включена
    if inclusive_start and found_start_version:
        cpe_result = f"cpe:2.3:{cpe_type}:{vendor}:{product}:{start_version}:*:*:*:*:*:{bdu_platform}:*"
        filtered_cpe_versions.insert(0,cpe_result)


    # Если версия конца диапазона не была найдена, но она должна быть включена
    if inclusive_end and not found_end_version:
        cpe_result = f"cpe:2.3:{cpe_type}:{vendor}:{product}:{end_version}:*:*:*:*:*:{bdu_platform}:*"
        filtered_cpe_versions.append(cpe_result)

    return filtered_cpe_versions


def translate_bdu_to_cpe(bdu_str):
    """Переводит описание уязвимого ПО из формата БДУ в CPE."""
    bdu_parts = [part.strip() for part in bdu_str.split(',')]
    bdu_type, bdu_vendor, bdu_product, bdu_version, bdu_platform = bdu_parts

    # Проверка формата версии
    if not check_version_format(bdu_version):
        return "Ошибка: Неверный формат версии"

    # Поиск соответствия в файле Similarity.xlsx
    for _, row in mapping_df.iterrows():
        if row[0] == bdu_type and row[1] == bdu_vendor and row[2] == bdu_product:
            cpe_type = row[3]
            cpe_vendor = row[4]
            cpe_product = row[5]

            # Если версия соответствует формату "просто версия"
            if re.match(r'\d+(\.\d+)*[a-zA-Z]*', bdu_version):
                cpe_str = f"cpe:2.3:{cpe_type}:{cpe_vendor}:{cpe_product}:{bdu_version}:*:*:*:*:{bdu_platform}:*:*"
                return cpe_str

            # Если версия соответствует другим форматам
            else:
                filtered_versions = find_cpe_versions(cpe_type, cpe_vendor, cpe_product, bdu_version, bdu_platform)
                if filtered_versions:
                    filtered_versions = list(set(filtered_versions))
                    print('Количество найденных версий: ',len(filtered_versions))
                    return "\n".join(filtered_versions)
                else:
                    return "Соответствующие версии не найдены"

    return "Совпадения не найдено"

# Пример использования
#bdu_example = "Операционная система,Сообщество свободного программного обеспечения,Linux,от 6.2 до 6.5.8 включительно,Не указана"
#print('Входные данные: ',bdu_example)
#cpe_result = translate_bdu_to_cpe(bdu_example)
#print(cpe_result)


# Пример использования
# cve_example = 'CVE-2023-2163'
# bdu_entries = convert_to_bdu_from_nvd(cve_example)
# for entry in bdu_entries:
    # print(entry)


# Пример использования
#cpe_example = 'wfn:[part="o", vendor="linux", product="linux_kernel", version="r2", update="sp1", edition=ANY, language=ANY, sw_edition=ANY, target_sw=ANY, target_hw="itanium", other=ANY]'
#cpe_example = "cpe:/o:linux:linux_kernel:r2:sp1:~~~~~~"
#cpe_example = 'cpe:2.3:o:linux:linux_kernel:r2:sp1:*:*:*:*:*:*'
#cpe_dict = parse_cpe(cpe_example)
#bdu_str = convert_to_bdu(cpe_dict)
#print(bdu_str)