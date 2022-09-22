class GetDscpError(Exception):
    """Обработка исключений получения метки dscp."""

    pass

class GetCosError(Exception):
    """Обработка исключений получения метки 802.1p cos."""

    pass

class ApiRequestException(Exception):
    """Обработка исключений ответа API."""

    pass

class SendMessageError(Exception):
    """Обработка исключений отправки сообщений"""

    pass

class AnalyzeExeption(Exception):
    """Обработка исключений запуска анализатора"""

    pass

class GetIfnameExeption(Exception):
    """Обработка исключений получения интерфейса"""

    pass
