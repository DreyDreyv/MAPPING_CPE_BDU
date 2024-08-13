# Конвертер форматов CPE и БДУ

Этот скрипт позволяет конвертировать форматы описания версий ПО между форматами Базы данных уязвимостей (БДУ) и Common Platform Enumeration (CPE), а также извлекать информацию из Национальной базы данных уязвимостей (NVD) и переводить её в формат БДУ.

## Функциональность

- Конвертация строки формата CPE в формат БДУ.
- Конвертация строки формата БДУ в CPE.
- Извлечение данных из NVD по CVE и их конвертация в формат БДУ.

## Установка и использование

1. Клонируйте репозиторий на локальную машину:

    ```bash
    git clone https://github.com/<ваш-репозиторий>.git
    cd <ваш-репозиторий>
    ```

2. Установите необходимые зависимости:

    ```bash
    pip install pandas requests openpyxl
    ```

3. Подготовьте файл `Similarity.xlsx` с сопоставлением данных.

4. **Важно:** Для работы скрипта необходим словарь CPE версии 2.3. Его нужно скачать самостоятельно, так как размер файла превышает лимит загрузки на GitHub.

   - Скачать словарь CPE можно по [ссылке](https://nvd.nist.gov/products/cpe).

   - Поместите файл `official-cpe-dictionary_v2.3.xml` в корневую директорию проекта.

5. Запустите скрипт для выполнения необходимых операций:

    ```bash
    python script_name.py
    ```

## Пример использования

Вы можете использовать скрипт для различных задач. Например:

### Конвертация из БДУ в CPE

```python
bdu_example = "Операционная система,Сообщество свободного программного обеспечения,Linux,от 6.2 до 6.5.8 включительно,Не указана"
cpe_result = translate_bdu_to_cpe(bdu_example)
print(cpe_result)
