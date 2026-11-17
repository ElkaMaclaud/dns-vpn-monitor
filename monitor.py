#!/usr/bin/env python3
"""Локальное наблюдение DNS: не изменяет маршруты или правила файрвола."""
import argparse
import csv
import fcntl
import ipaddress
import os
from datetime import datetime
from pathlib import Path
import re
import subprocess
import sys

PROJECT_DIR = Path(__file__).resolve().parent
HOSTNAME = re.compile(r'(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')


def stamp():
    return datetime.now().astimezone().isoformat(timespec='seconds')


def log(message):
    line = f'{stamp()} {message}'
    with LOG.open('a', encoding='utf-8') as file:
        file.write(line + '\n')
    print(line, flush=True)


def command(args, timeout):
    return subprocess.run(args, text=True, capture_output=True, timeout=timeout, check=False)


def dns(domain):
    result = command(['getent', 'ahostsv4', domain], 10)
    if result.returncode != 0:
        raise RuntimeError(f'getent: код {result.returncode}; {result.stderr.strip() or "адреса не получены"}')
    addresses = set()
    for line in result.stdout.splitlines():
        fields = line.split()
        if fields:
            try:
                address = ipaddress.ip_address(fields[0])
            except ValueError:
                continue
            if isinstance(address, ipaddress.IPv4Address):
                addresses.add(str(address))
    if not addresses:
        raise RuntimeError('DNS не вернул IPv4-адреса')
    return sorted(addresses, key=ipaddress.IPv4Address)


def route(address):
    try:
        result = command(['ip', '-4', 'route', 'get', address], 5)
    except (OSError, subprocess.TimeoutExpired) as error:
        return 'не определён', str(error)
    if result.returncode != 0:
        return 'не определён', result.stderr.strip() or f'ip route: код {result.returncode}'
    parts = result.stdout.split()
    if 'dev' not in parts or parts.index('dev') + 1 >= len(parts):
        return 'не определён', result.stdout.strip()
    return parts[parts.index('dev') + 1], result.stdout.strip()


def known_pairs():
    if not FOUND.exists():
        return set()
    with FOUND.open(encoding='utf-8', newline='') as file:
        reader = csv.DictReader(file, delimiter='\t')
        required = {'домен', 'IPv4'}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError(f'Неожиданный формат {FOUND}; не буду изменять файл')
        return {(row['домен'], row['IPv4']) for row in reader}


def save_new(rows):
    if not rows:
        return
    write_header = not FOUND.exists()
    with FOUND.open('a', encoding='utf-8', newline='') as file:
        writer = csv.writer(file, delimiter='\t', lineterminator='\n')
        if write_header:
            writer.writerow(['время', 'домен', 'IPv4', 'интерфейс_при_обнаружении'])
        writer.writerows(rows)
        file.flush()
        os.fsync(file.fileno())


def notify(title, message):
    try:
        result = command(['notify-send', '--app-name=Мониторинг DNS', title, message], 5)
        if result.returncode:
            log(f'Уведомление не показано: код {result.returncode}; {result.stderr.strip()}')
    except (OSError, subprocess.TimeoutExpired) as error:
        log(f'Уведомление не показано: {error}')


def main():
    with LOCK.open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print('Предыдущая проверка ещё выполняется; повторный запуск пропущен.', file=sys.stderr)
            return 1
        log('Проверка началась')
        try:
            lines = DOMAINS.read_text(encoding='utf-8').splitlines()
            domains = []
            for line in lines:
                domain = line.split('#', 1)[0].strip().lower().rstrip('.')
                if not domain:
                    continue
                if not HOSTNAME.fullmatch(domain):
                    raise ValueError(f'Некорректный домен в списке: {domain!r}')
                if domain not in domains:
                    domains.append(domain)
            if not domains:
                raise ValueError('Список доменов пуст')
            seen = known_pairs()
        except (OSError, ValueError, csv.Error) as error:
            log(f'Ошибка подготовки: {error}')
            notify('Ошибка мониторинга DNS', 'Не удалось прочитать домены или историю. Подробности в журнале.')
            return 1

        new_rows = []
        failures = []
        for domain in domains:
            try:
                addresses = dns(domain)
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
                failures.append(domain)
                log(f'{domain}: ошибка DNS: {error}')
                continue
            log(f'{domain}: DNS IPv4: {", ".join(addresses)}')
            for address in addresses:
                interface, detail = route(address)
                log(f'{domain} {address}: маршрут {detail}')
                pair = (domain, address)
                if pair not in seen:
                    new_rows.append((stamp(), domain, address, interface))
                    seen.add(pair)
                    log(f'Впервые обнаружено: {domain} {address}, интерфейс {interface}')
        try:
            save_new(new_rows)
        except OSError as error:
            log(f'Ошибка записи новых IP: {error}')
            notify('Ошибка мониторинга DNS', 'Новые адреса не сохранены. Подробности в журнале.')
            return 1
        if new_rows:
            preview = '\n'.join(f'{domain}: {address} ({interface})' for _, domain, address, interface in new_rows[:5])
            if len(new_rows) > 5:
                preview += f'\nЕщё записей: {len(new_rows) - 5}'
            notify(f'Новые IP: {len(new_rows)}', preview + '\nПроверьте файл new-ips.tsv.')
        if failures:
            notify('Ошибка DNS', f'Нет ответа для {len(failures)} доменов. Предыдущие записи сохранены; подробности в журнале.')
        log(f'Проверка завершена: доменов {len(domains)}, новых пар {len(new_rows)}, ошибок DNS {len(failures)}')
        return 1 if failures else 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Наблюдение за DNS и маршрутами без изменения сети')
    parser.add_argument('--data-dir', type=Path, required=True,
                        help='локальная папка для журнала, истории IP и блокировки')
    parser.add_argument('--domains-file', type=Path, default=PROJECT_DIR / 'domains.txt',
                        help='файл со списком доменов (по умолчанию domains.txt рядом со скриптом)')
    args = parser.parse_args()
    args.data_dir.mkdir(parents=True, exist_ok=True)
    DOMAINS = args.domains_file
    FOUND = args.data_dir / 'new-ips.tsv'
    LOG = args.data_dir / 'monitor.log'
    LOCK = args.data_dir / '.monitor.lock'
    raise SystemExit(main())
