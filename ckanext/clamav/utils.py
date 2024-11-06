from __future__ import annotations
import logging
from typing import Optional, Any, Union

from clamd import (
    ClamdUnixSocket,
    ClamdNetworkSocket,
    ConnectionError as ClamConnectionError,
    BufferTooLongError,
)
from werkzeug.datastructures import FileStorage

import ckan.model as model
import ckan.logic as logic
import ckan.plugins.toolkit as tk
from ckan.exceptions import CkanConfigurationException

import ckanext.clamav.config as c
from ckanext.clamav.adapters import CustomClamdNetworkSocket


log = logging.getLogger(__name__)


def scan_file_for_viruses(data_dict: dict[str, Any]):
    """
    Scans upload file for malwares with `clamav` open-source anti-virus toolkit

    Args:
        data_dict (dict[str, Any]): upload resource data_dict

    Raises:
        logic.ValidationError: returns a validation error to the user
        upload form
    """
    
    upload_unscanned: bool = tk.asbool(
        tk.config.get(c.CLAMAV_CONF_UPLOAD_UNSCANNED, c.CLAMAV_CONF_UPLOAD_UNSCANNED_DF)
    )

    file: FileStorage = data_dict["upload"]
    log.info(f"Scanning file {file.filename} for viruses and malware")
    status: str
    signature: Optional[str]
    status, signature = _scan_filestream(file)
    package_id = _get_package_id(data_dict)

    if status == c.CLAMAV_STATUS_ERR_DISABLED:
        log.info("Clamd: unable to connect to clamav. Can't scan the file")
        if upload_unscanned:
            log.info(_get_unscanned_file_message(file, package_id))
        else:
            raise logic.ValidationError(
                {
                    "Virus checker": [
                        "The clamav is disabled. Can't uploade the file. Contact administrator"
                    ]
                }
            )
    elif status in (c.CLAMAV_STATUS_ERR_FILELIMIT,):
        log.warning(signature)
        if upload_unscanned:
            log.info(_get_unscanned_file_message(file, package_id))
        else:
            raise logic.ValidationError({"Virus checker": [signature]})
    elif status == c.CLAMAV_STATUS_FOUND:
        error_msg: str = (
            "malware has been found. "
            f"Filename: {file.filename}, signature: {signature}."
        )
        log.warning(error_msg)
        raise logic.ValidationError({"Virus checker": [error_msg]})

    else:
        success_msg: str = (
            "Scan successful, no malware has been found. "
            f"Filename: {file.filename}, signature: {signature}."
        )
        log.info(success_msg)


def _get_package_id(data_dict: dict[str, Any]) -> str:
    """In some cases, like when we are syndicating datasets with resource files,
    we are missing `package_id` from the data_dict. We are going to fetch it
    from the resource.

    If resource is is not here for some reason, just return a placeholder, because
    we are using it only for logging"""

    resource_id: str | None = data_dict.get("id")

    if not resource_id:
        return "<PACKAGE IS NOT CREATED>"

    return model.Resource.get(resource_id).package.id


def _scan_filestream(file: FileStorage) -> tuple[str, Optional[str]]:
    """

    Args:
        file (FileStorage): werkzeug FileStorage object

    Returns:
        tuple[str, Optional[str]]: contains a status_code and a malware signature if found
        if status is returned error code, then instead of the signature there will
        be an error message.
    """

    cd: Union[ClamdUnixSocket, ClamdNetworkSocket] = _get_conn()

    try:
        scan_result: dict[str, tuple[str, str | None]] | None  = cd.instream(file.stream)
        log.info("MB_clamav_05")
        log.info(scan_result)
    except BufferTooLongError:
        error_msg: str = (
            "the uploaded file exceeds the filesize limit "
            "The file will not be scanned"
        )
        log.error(error_msg)
        return (c.CLAMAV_STATUS_ERR_FILELIMIT, error_msg)
    except ClamConnectionError:
        error_msg: str = "clamav is not accessible, check its status."
        log.critical(error_msg)
        return (c.CLAMAV_STATUS_ERR_DISABLED, error_msg)

    if not scan_result:
        return (c.CLAMAV_STATUS_ERR_DISABLED, None)

    return scan_result["stream"]


def _get_conn() -> Union[ClamdUnixSocket, CustomClamdNetworkSocket]:
    """
    Simply connects to the ClamAV via TCP/IP or Unix socket and returns
    the connection object

    Returns:
        Union[ClamdUnixSocket, CustomClamdNetworkSocket]: a connection to ClamAV
        Support two type of connection mechanism - TCP/IP or Unix socket

    Raises:
        CkanConfigurationException: if the TCP/IP connection mechanism has been choosen,
        the host:port must be provided, otherwise, raises an exception

        CkanConfigurationException: raises an exception, if the unsupported connection
        mechanism has been choosen
    """
    socket_type: str = tk.config.get(
        c.CLAMAV_CONF_SOCKET_TYPE, c.CLAMAV_CONF_SOCKET_TYPE_DF
    )
    conn_timeout: int = tk.asint(
        tk.config.get(c.CLAMAV_CONF_CONN_TIMEOUT, c.CLAMAV_CONF_CONN_TIMEOUT_DF)CLAMAV_CONF_CONN_TIMEOUT
    )

    if socket_type not in (c.CLAMAV_SOCK_UNIX, c.CLAMAV_SOCK_TCP):
        raise CkanConfigurationException("Clamd: unsupported connection type")

    if socket_type == c.CLAMAV_SOCK_UNIX:
        socket_path: str = tk.config.get(
            c.CLAMAV_CONF_SOCKET_PATH, c.CLAMAV_CONF_SOCKET_PATH_DF
        )
        log.info(f"Clamd connection timeout: {str(conn_timeout)}")
        return ClamdUnixSocket(socket_path, conn_timeout)

    tcp_host: str = tk.config.get(c.CLAMAV_CONF_SOCK_TCP_HOST)
    tcp_port: int = tk.asint(tk.config.get(c.CLAMAV_CONF_SOCK_TCP_PORT))

    if not all((tcp_port, tcp_host)):
        raise CkanConfigurationException(
            "Clamd: please, provide TCP/IP host:port for ClamAV"
        )

    log.info("MB_clamav_03-2")
    log.info(tcp_host)
    log.info(tcp_port)
    log.info(conn_timeout)
    log.info(CustomClamdNetworkSocket(tcp_host, tcp_port, conn_timeout))
    return CustomClamdNetworkSocket(tcp_host, tcp_port, conn_timeout)


def _get_unscanned_file_message(file: FileStorage, pkg_id: str) -> str:
    return (
        "The unscanned file will be uploaded because unscanned fileupload is enabled. "
        f"Filename: {file.filename}, package_id: {pkg_id}, name: {file.filename or None}"
    )
