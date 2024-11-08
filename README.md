[![Tests](https://github.com/DataShades/ckanext-clamav/workflows/Tests/badge.svg?branch=main)](https://github.com/DataShades/ckanext-clamav/actions)

# ckanext-clamav

This is a basic example that helps to scan uploaded resources for malwares with clamd library.

## Installation

Clamd library uses clamav tool, and you must install it into your environment, to make this extension work.

For example, to install ClamAV on Ubuntu:

1. Install ClamAV with APT
	```
    apt-get update
    apt-get install clamav clamav-daemon -y
	```

2. Update the ClamAV signature database
	```
    systemctl stop clamav-freshclam
    freshclam
    systemctl start clamav-freshclam
	```

To install ckanext-clamav:

1. Activate your CKAN virtual environment, for example:

     `. /usr/lib/ckan/default/bin/activate`

2. Clone the source and install it on the virtualenv
	```
    git clone https://github.com/DataShades/ckanext-clamav.git
    cd ckanext-clamav
    pip install -e .
	pip install -r requirements.txt
	```

3. Add `clamav` to the `ckan.plugins` setting in your CKAN
   config file (by default the config file is located at
   `/etc/ckan/default/ckan.ini`).

4. Restart CKAN. For example if you've deployed CKAN with Apache on Ubuntu:

    `sudo service apache2 reload`


## Config settings

	# If your socket file is in different folder, you can specify it
	# (optional, default: /var/run/clamav/clamd.ctl).
	ckanext.clamav.socket_path = /your/path/to/socket.file

	# You can decide to upload unscanned files or not.
    # For example, if clamav is disabled, you won't be able to scan a file
	# (optional, default: True).
	ckanext.clamav.upload_unscanned = False

    # ClamAV connection mechanism. There are two options: `tcp` or `unix`.
    # If `tcp` selected, you must provide host:port (check next options).
    # ( optional, default: unix)
    ckanext.clamav.socket_type = unix

    # TCP/IP hostname
    ckanext.clamav.tcp.host = your.hostname.address

    # TCP/IP port
    ckanext.clamav.tcp.port = 3310

    # ClamAV connection timeout. Either `tcp` or `unix`
    # By default, there is no timeout.
    # ( optional, default: 60)
    ckanext.clamav.timeout = 120

    # Writable directory for tmp files used to prevent timeout error while scanning file stream.
    ckanext.clamav.timeout = /your/writable/directory


## Developer installation

To install ckanext-clamav for development, activate your CKAN virtualenv and
do:

    git clone https://github.com/DataShades/ckanext-clamav.git
    cd ckanext-clamav
    python setup.py develop
    pip install -r dev-requirements.txt


## Tests

To run the tests, do:

    pytest --ckan-ini=test.ini


## License

[AGPL](https://www.gnu.org/licenses/agpl-3.0.en.html)
