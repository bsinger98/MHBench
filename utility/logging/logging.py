import logging
from logging.handlers import RotatingFileHandler
import os

import structlog


class PerryLogger:
    plugin_logger = logging.getLogger("perry")
    caldera_log_file = None

    @staticmethod
    def get_logger():
        return PerryLogger.plugin_logger

    @staticmethod
    def setup_logger(experiment_output_dir: str):
        # Setup perry logging
        log_filename = f"perry_log.log"
        log_path = os.path.join(experiment_output_dir, log_filename)

        PerryLogger.plugin_logger.setLevel(logging.DEBUG)
        plugin_logger_handler = RotatingFileHandler(log_path, maxBytes=5 * 1024 * 1024)
        plugin_logger_formatter = logging.Formatter(
            "%(asctime)s {%(filename)s:%(lineno)d} %(levelname)s:%(message)s"
        )
        plugin_logger_handler.setFormatter(plugin_logger_formatter)
        plugin_logger_handler.setLevel(logging.DEBUG)

        PerryLogger.plugin_logger.handlers.clear()
        PerryLogger.plugin_logger.addHandler(plugin_logger_handler)

        # Setup caldera logging
        log_filename = f"caldera_log.log"
        log_path = os.path.join(experiment_output_dir, log_filename)
        PerryLogger.caldera_log_file = open(log_path, "w")


def setup_action_logger(experiment_output_dir: str):
    # Setup action logging
    log_filename = f"defender_action.log"
    log_path = os.path.join(experiment_output_dir, log_filename)
    structlog.configure(
        processors=[
            structlog.processors.JSONRenderer(),
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
    )
    action_logger = logging.getLogger("action_logger")
    action_logger.setLevel(logging.DEBUG)
    action_logger_handler = RotatingFileHandler(log_path, maxBytes=5 * 1024 * 1024)
    action_logger_formatter = logging.Formatter("%(message)s")
    action_logger_handler.setFormatter(action_logger_formatter)
    action_logger_handler.setLevel(logging.DEBUG)

    action_logger.handlers.clear()
    action_logger.addHandler(action_logger_handler)

    return structlog.get_logger("action_logger")


def serialize(action):
    IGNORE_OBJECTS = [logging.Logger]

    dict_format = dict()
    if hasattr(action, "__dict__"):
        for key, value in action.__dict__.items():
            if type(value) in IGNORE_OBJECTS:
                continue
            elif isinstance(value, list):
                if value and type(value[0]) in IGNORE_OBJECTS:
                    continue
                else:
                    dict_format[key] = [serialize(item) for item in value]
            elif isinstance(value, dict):
                dict_format[key] = {str(k): serialize(v) for k, v in value.items()}
            else:
                dict_format[key] = serialize(value)
        return dict_format
    else:
        return action


### Legacy code ###
def get_logger():
    return PerryLogger.plugin_logger


def log(message: str):
    PerryLogger.plugin_logger.debug(message)


def log_event(event: str, message: str):
    PerryLogger.plugin_logger.debug(f"{event:<24}\t{message}")


def log_trusted_agents(trusted_agents):
    for agent in trusted_agents:
        log_event(
            "TRUSTED AGENT",
            f"{agent.paw} ({agent.host} - {agent.host_ip_addrs})",
        )
