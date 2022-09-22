#!/usr/bin/env python
import requests
from scapy.all import sniff
import os
import time
from multiprocessing import Process
from dotenv import load_dotenv
from pyroute2 import IPRoute
import exeptions
import logging
from logging.handlers import RotatingFileHandler

load_dotenv()

logging.basicConfig(
    level=logging.DEBUG,
    filename='main.log',
    format='%(asctime)s, %(levelname)s, %(funcName)s,'
    '%(lineno)s, %(message)s, %(name)s'
)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
handler = RotatingFileHandler("main.log", maxBytes=1000000, backupCount=2)
logger.addHandler(handler)

TELEGRAM_TOKEN = os.getenv('TELEGRAM_TOKEN')
TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')
URL = (f'https://api.telegram.org/bot{TELEGRAM_TOKEN}'
       f'/sendMessage?chat_id={TELEGRAM_CHAT_ID}&text=')

RETRY_TIME = 60
HOST = '225.40.12.43'
UDP_PORT = '1234'
HOSTNAME = os.uname().nodename


def get_iface_name():
    """Вернуть имя сетевого интерфейса."""
    iface, parent_iface = '', ''
    ipr = IPRoute()
    try:
        logger.info('Запрос индекса интерфейса')
        route_info = ipr.route('get', dst=HOST)
        route_info_dict = dict(route_info[0]).get('attrs')
        iface_index = route_info_dict[2].get_value()
        logger.info(f'Индекс интерфейса получен: {iface_index}')
    except Exception as e:
        logger.error('Проблема при получении индекса интерфейса')
        raise exeptions.GetIfnameExeption(e)
    try:
        logger.info('Запрос имени интерфейса')
        links = ipr.get_links()
        for link in links:
            if link.get('index') == iface_index:
                for attr in link['attrs']:
                    if attr[0] == 'IFLA_IFNAME':
                        iface = attr[1]

        if '.' in iface:
            parent_iface = iface.split('.')[0]

        if parent_iface:
            logger.info(f'Имя интерфейса получено: {parent_iface}')
            return parent_iface
    except Exception as e:
        logger.error('Проблема при получении имени интерфейса')
        raise exeptions.GetIfnameExeption(e)


def get_l2cos(packet):
    """Вернуть COS метку."""
    logger.info('Запрос COS метки')
    try:
        l2cos = packet[0].prio
        logger.info(f'COS метка получена: {l2cos}')
    except Exception as e:
        logger.error('Проблема при получении COS метки')
        raise exeptions.GetCosError(e)
    return l2cos


def get_dscp(packet):
    """Вернуть DSCP метку."""
    logger.info('Запрос DSCP метки')
    try:
        dscp = packet[0].tos
        logger.info(f'DSCP метка получена: {dscp}')
    except Exception as e:
        logger.error('Проблема при получении DSCP метки')
        raise exeptions.GetDscpError(e)
    return dscp


def analyze():
    """Запросить поток."""
    logger.info('Запуск анализатора')
    try:
        os.system(f'astra --analyze -n 1 udp://{HOST}')
        logger.info(f'Анализ группы {HOST} запущен')
    except Exception as e:
        logger.error('Проблема при запуске анализатора')
        raise exeptions.AnalyzeExeption(e)


def send_message(message):
    """Отправить сообщение."""
    logger.info('Отправка сообщения в телеграм')
    try:
        requests.get(f'{URL}{message}')
        logger.info('Сообщение отправлено')
    except Exception as e:
        logger.error('Проблема при оптравке сообщения')
        raise exeptions.SendMessageError(e)


def main():
    """Основная логика скрипта."""
    prev_dscp = ''
    prev_l2cos = ''
    iface = get_iface_name()
    while True:
        try:
            process = Process(target=analyze)
            process.start()
            logger.info('Запуск снифера')
            packet = sniff(
                iface=iface,
                filter=f'udp and host {HOST} and port {UDP_PORT}',
                count=1
            )
            l2cos = get_l2cos(packet)
            dscp = get_dscp(packet)
            process.join()
            if prev_dscp == dscp and prev_l2cos == l2cos:
                continue
            if dscp != 128 and l2cos != 4:
                message = (f'{HOSTNAME}: Некорректная метка приоритета\n'
                           f'DSCP {dscp}, COS: {l2cos}\nинтерфейс {iface}, группа {HOST}')
                send_message(message)
                prev_dscp = dscp
                prev_l2cos = l2cos
            else:
                prev_dscp = dscp
                prev_l2cos = l2cos
        except Exception as error:
            message = f'Сбой в работе программы: {error}'
            send_message(message)
        finally:
            time.sleep(RETRY_TIME)


if __name__ == '__main__':
    main()
